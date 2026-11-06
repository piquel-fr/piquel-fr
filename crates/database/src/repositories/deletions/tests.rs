//! Scheduling, restore tokens and the purge.
use super::*;
use crate::{Database, DatabaseTransaction, EventRepository, InsertUser, RestoreToken};
use chrono::Duration;
use piquel_common::{
    AccountStatus, Handle, PasskeyId, Personal, Provider, SessionId, TokenId,
    events::{Actor, Browser, DomainEvent, EventContext, Platform, RequestOrigin, UserAgentFamily},
};
use piquel_common::{AuthenticationMethod, events::SignInFailure};
use sqlx::{Acquire, PgPool};
use std::{net::IpAddr, time::Duration as StdDuration};

/// Inserts an active account whose handle is `prefix` and part of its ID.
async fn insert_user(pool: &PgPool, prefix: &str) -> (UserId, Handle) {
    let user = InsertUser::named(prefix);
    crate::UserRepository::from_pool(pool)
        .insert(&user)
        .await
        .expect("user");
    (user.id, user.handle)
}

/// Purges `user` in its own committed transaction.
async fn purge(pool: &PgPool, user: UserId) -> bool {
    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    let purged = tx.deletions().purge(user).await.expect("purge");
    tx.commit().await.expect("commit");
    purged
}

/// A purged account's handles stay without an owner, so no account claims them
/// again until an operator releases them.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_purged_accounts_handle_stays_taken() {
    let pool = Database::test_pool().await;
    let (user, handle) = insert_user(&pool, "retired").await;
    assert!(purge(&pool, user).await);
    assert!(!purge(&pool, user).await, "the account is gone");

    let holder = crate::HandleRepository::from_pool(&pool)
        .holder(&handle)
        .await
        .expect("lookup")
        .expect("the handle stays");
    assert_eq!(holder.user_id, None);
    let reuse = crate::UserRepository::from_pool(&pool)
        .insert(&InsertUser {
            handle,
            ..InsertUser::named("again")
        })
        .await;
    assert!(
        matches!(reuse, Err(DatabaseError::Conflict(_))),
        "{reuse:?}"
    );
}

/// A restore token is found while unexpired and its passkey active, and a newer
/// one replaces it. Cancelling the deletion ends both the schedule and the token.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn restore_tokens_expire_and_end_with_the_deletion() {
    let pool = Database::test_pool().await;
    let (user, _) = insert_user(&pool, "restore").await;
    let mut deletions = AccountDeletionRepository::from_pool(&pool);
    let purge_after = Utc::now() + Duration::days(30);
    let scheduled = deletions
        .schedule(user, purge_after)
        .await
        .expect("schedule");
    assert!(matches!(
        deletions.schedule(user, purge_after).await,
        Err(DatabaseError::Conflict(_))
    ));
    assert_eq!(
        deletions.find(user).await.expect("find"),
        Some(scheduled.clone())
    );

    let (old, new, expired) = ([1; 32], [2; 32], [3; 32]);
    let passkey = PasskeyId::new();
    sqlx::query(
        "INSERT INTO passkey_credentials (id, credential_id, user_id, credential, friendly_name)
        VALUES ($1, uuid_send($1), $2, '{}', 'Restore test')",
    )
    .bind(passkey.as_uuid())
    .bind(user.as_uuid())
    .execute(&pool)
    .await
    .expect("passkey");
    let later = Utc::now() + Duration::minutes(5);
    for digest in [old, new] {
        let issued = deletions
            .issue_restore_token(user, &digest, passkey, later)
            .await
            .expect("issue");
        assert_eq!(issued, Some(scheduled.clone()));
    }
    assert_eq!(
        deletions.find_by_restore_token(&old).await.expect("old"),
        None
    );
    assert_eq!(
        deletions.find_by_restore_token(&new).await.expect("new"),
        Some(RestoreToken {
            user_id: user,
            passkey_id: passkey
        })
    );
    sqlx::query("UPDATE passkey_credentials SET revoked_at = now() WHERE id = $1")
        .bind(passkey.as_uuid())
        .execute(&pool)
        .await
        .expect("revoke");
    assert_eq!(
        deletions
            .find_by_restore_token(&new)
            .await
            .expect("revoked"),
        None,
        "a revoked passkey's token restores nothing"
    );
    deletions
        .issue_restore_token(user, &expired, passkey, Utc::now() - Duration::seconds(1))
        .await
        .expect("issue expired");
    assert_eq!(
        deletions
            .find_by_restore_token(&expired)
            .await
            .expect("expired"),
        None
    );

    assert!(deletions.cancel(user).await.expect("cancel"));
    assert!(!deletions.cancel(user).await.expect("cancel again"));
    assert_eq!(deletions.find(user).await.expect("find"), None);
    assert_eq!(
        deletions
            .issue_restore_token(user, &old, passkey, later)
            .await
            .expect("issue"),
        None,
        "an account that is not scheduled gets no token"
    );

    // Leaving 'deleting' any other way, as the previous release's enable and
    // disable do, ends the schedule too.
    let mut users = crate::UserRepository::from_pool(&pool);
    users
        .set_status(user, AccountStatus::Deleting)
        .await
        .expect("deleting");
    deletions
        .schedule(user, purge_after)
        .await
        .expect("schedule again");
    users
        .set_status(user, AccountStatus::Disabled)
        .await
        .expect("disable");
    assert_eq!(deletions.find(user).await.expect("find"), None);
}

/// After a purge no row of any table references the account through a foreign
/// key, and its events, and those it caused about others, keep no personal data.
/// The foreign keys are read from the catalog, so tables added later are covered.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "One row in every table that references users."
)]
async fn purge_leaves_nothing_that_references_or_identifies_the_account() {
    let pool = Database::test_pool().await;
    let (user, handle) = insert_user(&pool, "purged").await;
    let (bystander, _) = insert_user(&pool, "bystander").await;
    let client = format!("purge-{user}");
    let (session, code, family) = (SessionId::new(), TokenId::new(), TokenId::new());
    // Test-generated IDs only, so formatting them into the SQL is safe.
    sqlx::raw_sql(&format!(
        "INSERT INTO oidc_clients (id, display_name, allowed_scopes, allowed_audiences)
        VALUES ('{client}', 'Purge test', '[]', '[]');
        INSERT INTO user_emails (id, user_id, normalized_email, verified_at, is_primary)
        VALUES (uuidv7(), '{user}', '{client}@example.com', now(), TRUE);
        INSERT INTO passkey_credentials (id, credential_id, user_id, credential, friendly_name)
        VALUES (uuidv7(), uuid_send('{user}'), '{user}', '{{}}', 'Purge test');
        INSERT INTO external_login_identities (id, user_id, provider_name, issuer, subject)
        VALUES (uuidv7(), '{user}', 'github', 'https://github.com', '{client}');
        INSERT INTO oidc_consents (user_id, client_id, audience, scopes)
        VALUES ('{user}', '{client}', 'test', '[]');
        INSERT INTO administrators (user_id) VALUES ('{user}');
        INSERT INTO notifications (id, user_id, payload)
        VALUES (uuidv7(), '{user}', '{{\"kind\": \"account_enabled\"}}');
        INSERT INTO authorization_requests (
            id, secret_digest, client_id, redirect_uri, client_state, pkce_challenge, scopes,
            audience, interaction, expires_at, hinted_user_id
        ) VALUES (
            uuidv7(), uuid_send('{user}'), '{client}', 'https://client.example/callback', 'state',
            'challenge', '[]', 'test', 'as_needed', now() + interval '5 minutes', '{user}'
        );
        INSERT INTO sessions (id, user_id, authentication_methods, authenticated_at, expires_at, last_seen_at)
        VALUES ('{session}', '{user}', '[\"passkey\"]', now(), now() + interval '1 day', now());
        INSERT INTO browser_session_secrets (session_id, secret_digest)
        VALUES ('{session}', uuid_send('{session}'));
        INSERT INTO webauthn_ceremonies (id, user_id, session_id, ceremony_kind, challenge_digest, state, expires_at)
        VALUES (uuidv7(), '{user}', '{session}', 'enrollment', '\\x00', '{{}}', now() + interval '5 minutes');
        INSERT INTO authorization_codes (
            id, secret_digest, client_id, user_id, session_id, redirect_uri, pkce_challenge,
            scopes, audience, expires_at, authentication
        ) VALUES (
            '{code}', uuid_send('{code}'), '{client}', '{user}', '{session}',
            'https://client.example/callback', 'challenge', '[]', 'test',
            now() + interval '1 minute', '{{}}'
        );
        INSERT INTO refresh_token_families (
            id, user_id, client_id, session_id, audience, scopes, authentication, authorization_code_id
        ) VALUES ('{family}', '{user}', '{client}', '{session}', 'test', '[]', '{{}}', '{code}');
        INSERT INTO refresh_tokens (id, family_id, secret_digest, expires_at)
        VALUES (uuidv7(), '{family}', uuid_send('{family}'), now() + interval '1 day');
        INSERT INTO deliveries (id, channel, destination, recipient, payload, status) VALUES
            (uuidv7(), 'email', 'account', to_jsonb('{user}'::text),
                '{{\"type\": \"notification\", \"address\": \"{client}@example.com\"}}', 'succeeded'),
            (uuidv7(), 'backchannel_logout', 'https://client.example/logout', to_jsonb('{user}'::text),
                '{{}}', 'pending');"
    ))
    .execute(&pool)
    .await
    .expect("rows referencing the account");
    let origin = RequestOrigin {
        client_ip: Some(IpAddr::from([192, 0, 2, 9])),
        user_agent_family: Some(UserAgentFamily {
            browser: Browser::Safari,
            platform: Platform::MacOs,
        }),
    };
    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    let mine = EventContext {
        actor: Actor::User {
            user_id: user,
            session_id: None,
        },
        origin,
        reason: None,
    };
    tx.record(
        &mine,
        Some(user),
        DomainEvent::IdentityLinked {
            provider: Provider::GitHub,
            subject: Personal::Value(client.clone()),
        },
    )
    .await
    .expect("own event");
    let as_admin = EventContext {
        actor: Actor::Admin {
            user_id: user,
            session_id: SessionId::new(),
        },
        origin,
        reason: None,
    };
    tx.record(&as_admin, Some(bystander), DomainEvent::AccountViewed {})
        .await
        .expect("event caused about another account");
    let theirs = EventContext {
        actor: Actor::User {
            user_id: bystander,
            session_id: None,
        },
        origin,
        reason: None,
    };
    tx.record(&theirs, Some(bystander), DomainEvent::AccountEnabled {})
        .await
        .expect("bystander's own event");
    tx.deletions()
        .schedule(user, Utc::now())
        .await
        .expect("schedule");
    tx.commit().await.expect("commit");

    assert!(purge(&pool, user).await);

    // Every column with a foreign key to users(id), and how many rows hold the account.
    // Only this schema's: audit tests migrate schemas of their own beside it.
    let references: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT
            source.table_name::text, source.column_name::text,
            (xpath('/row/c/text()', query_to_xml(format(
                'SELECT count(*) AS c FROM %I.%I WHERE %I = %L',
                source.table_schema, source.table_name, source.column_name, $1
            ), FALSE, TRUE, '')))[1]::text::bigint
        FROM information_schema.referential_constraints r
        JOIN information_schema.key_column_usage source
            ON source.constraint_name = r.constraint_name
            AND source.constraint_schema = r.constraint_schema
        JOIN information_schema.key_column_usage target
            ON target.constraint_name = r.unique_constraint_name
            AND target.constraint_schema = r.unique_constraint_schema
            AND target.ordinal_position = source.position_in_unique_constraint
        WHERE target.table_schema = current_schema()
            AND target.table_name = 'users' AND target.column_name = 'id'",
    )
    .bind(user.to_string())
    .fetch_all(&pool)
    .await
    .expect("references");
    let referencing: Vec<String> = references
        .iter()
        .map(|(table, column, _)| format!("{table}.{column}"))
        .collect();
    for expected in [
        "sessions.user_id",
        "user_emails.user_id",
        "passkey_credentials.user_id",
        "oidc_consents.user_id",
        "refresh_token_families.user_id",
        "administrators.user_id",
        "account_deletions.user_id",
        "notifications.user_id",
    ] {
        assert!(
            referencing.iter().any(|column| column == expected),
            "{expected}"
        );
    }
    let remaining: Vec<_> = references.iter().filter(|(_, _, rows)| *rows > 0).collect();
    assert!(remaining.is_empty(), "{remaining:?}");

    // Events stay, with their personal data erased, except the bystander's own.
    let events = EventRepository::from_pool(&pool)
        .history_for_user(user, 10)
        .await
        .expect("history");
    let [own] = <[_; 1]>::try_from(events).expect("one own event");
    assert_eq!(own.origin, Personal::Erased);
    assert_eq!(
        own.event.known(),
        Some(&DomainEvent::IdentityLinked {
            provider: Provider::GitHub,
            subject: Personal::Erased,
        })
    );
    let bystanders = EventRepository::from_pool(&pool)
        .history_for_user(bystander, 10)
        .await
        .expect("bystander history");
    let erased: Vec<_> = bystanders
        .iter()
        .map(|event| {
            (
                event.event.known().cloned(),
                event.origin == Personal::Erased,
            )
        })
        .collect();
    assert_eq!(
        erased,
        [
            (Some(DomainEvent::AccountEnabled {}), false),
            (Some(DomainEvent::AccountViewed {}), true),
        ]
    );
    // A request that was in flight during the purge records its event, but no
    // personal data comes back with it.
    let mut late = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    late.record(&mine, Some(user), DomainEvent::AccountEnabled {})
        .await
        .expect("late event");
    late.commit().await.expect("commit");
    let latest = EventRepository::from_pool(&pool)
        .history_for_user(user, 1)
        .await
        .expect("history");
    assert_eq!(latest[0].origin, Personal::Erased);

    // Its email deliveries copied its addresses; a logout token still goes out.
    let channels: Vec<String> = sqlx::query_scalar(
        "SELECT channel FROM deliveries WHERE recipient = to_jsonb($1::text) ORDER BY channel",
    )
    .bind(user.to_string())
    .fetch_all(&pool)
    .await
    .expect("deliveries");
    assert_eq!(channels, ["backchannel_logout"]);

    let holder = crate::HandleRepository::from_pool(&pool)
        .holder(&handle)
        .await
        .expect("lookup")
        .expect("the handle stays");
    assert_eq!(holder.user_id, None, "without an owner");
}

/// A request that stores personal data about the account while it is being
/// purged, such as a failed sign-in's IP address, leaves none behind. Here the
/// request holds migration 0022's key-share lock on the account until the purge
/// waits for it, then commits: the purge must erase what it stored.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn personal_data_stored_during_a_purge_is_erased() {
    let pool = Database::test_pool().await;
    let (user, _) = insert_user(&pool, "racing").await;
    let failed = EventContext {
        actor: Actor::Anonymous,
        origin: RequestOrigin {
            client_ip: Some(IpAddr::from([192, 0, 2, 66])),
            user_agent_family: None,
        },
        reason: None,
    };
    let mut request = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    request
        .record(
            &failed,
            Some(user),
            DomainEvent::SignInFailed {
                method: AuthenticationMethod::Passkey,
                reason: SignInFailure::InvalidCredential,
            },
        )
        .await
        .expect("failed sign-in");

    let mut connection = pool.acquire().await.expect("connection");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await
        .expect("pid");
    let purging = tokio::spawn(async move {
        let mut tx = DatabaseTransaction::new(connection.begin().await.expect("transaction"));
        let purged = tx.deletions().purge(user).await.expect("purge");
        tx.commit().await.expect("commit");
        purged
    });
    // Only deleting the account waits for the request's lock.
    let blocked = async {
        while !sqlx::query_scalar::<_, bool>(
            "SELECT coalesce(bool_or(wait_event_type = 'Lock'), FALSE)
            FROM pg_stat_activity WHERE pid = $1",
        )
        .bind(pid)
        .fetch_one(&pool)
        .await
        .expect("activity")
        {
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(StdDuration::from_secs(10), blocked)
        .await
        .expect("the purge waits for the request");
    request.commit().await.expect("commit");
    assert!(purging.await.expect("purge task"));

    let events = EventRepository::from_pool(&pool)
        .history_for_user(user, 10)
        .await
        .expect("history");
    let [event] = <[_; 1]>::try_from(events).expect("the failed sign-in stays");
    assert_eq!(event.origin, Personal::Erased);
}

/// A failed purge waits its backoff behind the other due accounts, doubling with
/// each failure up to the cap, and is counted once it keeps failing. A failure
/// recorded after the account was scheduled again is dropped.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn failed_purges_back_off_behind_other_accounts() {
    let pool = Database::test_pool().await;
    let (failing, _) = insert_user(&pool, "failing").await;
    let (other, _) = insert_user(&pool, "other").await;
    let mut deletions = AccountDeletionRepository::from_pool(&pool);
    // Other tests' accounts may be due too, so only these two are compared.
    let order = async |deletions: &mut AccountDeletionRepository<'_>| {
        deletions
            .due(u32::MAX)
            .await
            .expect("due")
            .into_iter()
            .filter(|user| [failing, other].contains(user))
            .collect::<Vec<_>>()
    };
    deletions
        .schedule(failing, Utc::now() - Duration::days(2))
        .await
        .expect("schedule");
    deletions
        .schedule(other, Utc::now() - Duration::days(1))
        .await
        .expect("schedule");
    assert_eq!(order(&mut deletions).await, [failing, other]);
    assert_eq!(deletions.failure(failing).await.expect("failure"), None);

    let (backoff, cap) = (Duration::minutes(5), Duration::minutes(12));
    let mut delays = Vec::new();
    for _ in 0..3 {
        deletions
            .record_failure(failing, "boom", backoff, cap)
            .await
            .expect("record");
        let failure = deletions
            .failure(failing)
            .await
            .expect("failure")
            .expect("failed");
        assert_eq!(failure.last_error, "boom");
        delays.push((failure.next_attempt_at - Utc::now()).num_minutes());
    }
    assert_eq!(delays, [4, 9, 11], "5, 10, then capped at 12 minutes");
    assert_eq!(order(&mut deletions).await, [other], "waits its backoff");
    assert!(deletions.count_failing(3).await.expect("count") >= 1);

    // Restored and scheduled again while an attempt failed: the new schedule
    // starts without the old failure.
    assert!(deletions.cancel(failing).await.expect("cancel"));
    deletions
        .schedule(failing, Utc::now() + Duration::days(30))
        .await
        .expect("schedule again");
    deletions
        .record_failure(failing, "late", backoff, cap)
        .await
        .expect("record");
    assert_eq!(deletions.failure(failing).await.expect("failure"), None);
}
