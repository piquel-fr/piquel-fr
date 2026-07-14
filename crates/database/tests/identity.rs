#![allow(missing_docs)]

use chrono::{Duration as ChronoDuration, Utc};
use piquel_auth_protocol::{AccountStatus, AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_repository::{
    AppendInternalEvent, Database, DatabaseConfig, DatabaseError, InsertCeremony, InsertPasskey,
    InsertSession, InsertUser, InsertVerifiedEmail, UpdateUserProfile,
};
use std::{env, time::Duration};

async fn database() -> Database {
    let url = env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
    let config = DatabaseConfig::new_development(url, 10, Duration::from_secs(5))
        .expect("test database configuration");
    let database = Database::connect(config)
        .await
        .expect("connect test database");
    database.run_migrations().await.expect("run migrations");
    database
}

async fn insert_user(database: &Database, prefix: &str) -> UserId {
    let id = UserId::new();
    let identifier = id.to_string();
    let username = format!("{prefix}_{}", &identifier[identifier.len() - 12..]);
    database
        .users()
        .insert(&InsertUser {
            id,
            username: username.clone(),
            display_name: username,
        })
        .await
        .expect("insert user");
    id
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn identity_transactions_and_concurrency_hold() {
    let database = database().await;

    let rolled_back = UserId::new();
    let mut transaction = database.begin().await.expect("begin");
    transaction
        .users()
        .insert(&InsertUser {
            id: rolled_back,
            username: format!("rollback_{}", &rolled_back.to_string()[..8]),
            display_name: "Rolled Back".into(),
        })
        .await
        .expect("insert");
    transaction
        .internal_events()
        .append(&AppendInternalEvent {
            id: TokenId::new(),
            aggregate_type: "user".into(),
            aggregate_id: rolled_back,
            event_type: "account.created".into(),
            schema_version: 1,
            payload: serde_json::json!({}),
        })
        .await
        .expect("event");
    transaction.rollback().await.expect("rollback");
    assert!(
        database
            .users()
            .find_by_id(rolled_back)
            .await
            .expect("lookup")
            .is_none()
    );

    let invalid_primary = UserId::new();
    let mut transaction = database.begin().await.expect("begin invalid account");
    transaction
        .users()
        .insert(&InsertUser {
            id: invalid_primary,
            username: format!("invalid_{}", &invalid_primary.to_string()[..8]),
            display_name: "Invalid Primary".into(),
        })
        .await
        .expect("insert account");
    transaction
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: invalid_primary,
            normalized_email: format!("invalid-{invalid_primary}@example.com"),
            is_primary: false,
            verified_at: Utc::now(),
        })
        .await
        .expect("insert until deferred check");
    assert!(transaction.commit().await.is_err());
    assert!(
        database
            .users()
            .find_by_id(invalid_primary)
            .await
            .expect("lookup invalid account")
            .is_none()
    );

    let first = insert_user(&database, "first").await;
    let second = insert_user(&database, "second").await;

    database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: TokenId::new(),
            user_id: None,
            session_id: None,
            kind: "registration".into(),
            challenge_digest: vec![2; 32],
            state: serde_json::json!({"bootstrap":true}),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("bootstrap ceremony before user creation");
    database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: TokenId::new(),
            user_id: Some(first),
            session_id: None,
            kind: "enrollment".into(),
            challenge_digest: vec![3; 32],
            state: serde_json::json!({"enrollment":true}),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("enrollment ceremony");

    let ceremony_id = TokenId::new();
    database
        .passkeys()
        .insert_ceremony(&InsertCeremony {
            id: ceremony_id,
            user_id: Some(first),
            session_id: None,
            kind: "authentication".into(),
            challenge_digest: vec![1; 32],
            state: serde_json::json!({"test":true}),
            expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("ceremony");
    let one = database.clone();
    let two = database.clone();
    let (left, right) = tokio::join!(
        async move {
            one.passkeys()
                .consume_ceremony(ceremony_id, "authentication")
                .await
        },
        async move {
            two.passkeys()
                .consume_ceremony(ceremony_id, "authentication")
                .await
        }
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    let credential_id = vec![7_u8; 32];
    database
        .passkeys()
        .insert(&InsertPasskey {
            id: TokenId::new(),
            credential_id: credential_id.clone(),
            user_id: first,
            credential: serde_json::json!({"fixture":true}),
            friendly_name: "First".into(),
        })
        .await
        .expect("passkey");
    assert!(matches!(
        database
            .passkeys()
            .insert(&InsertPasskey {
                id: TokenId::new(),
                credential_id,
                user_id: second,
                credential: serde_json::json!({"fixture":true}),
                friendly_name: "Duplicate".into()
            })
            .await,
        Err(DatabaseError::Conflict)
    ));

    for suffix in 0_u8..20 {
        let mut additional_credential_id = vec![suffix; 32];
        additional_credential_id.push(42);
        database
            .passkeys()
            .insert(&InsertPasskey {
                id: TokenId::new(),
                credential_id: additional_credential_id,
                user_id: first,
                credential: serde_json::json!({"fixture":true}),
                friendly_name: format!("Additional {suffix}"),
            })
            .await
            .expect("additional passkey");
    }
    assert_eq!(
        database
            .passkeys()
            .list_active(first)
            .await
            .expect("list every passkey")
            .len(),
        21
    );

    let normalized = format!("race-{}@example.com", UserId::new());
    let one = database.clone();
    let two = database.clone();
    let first_claim = InsertVerifiedEmail {
        id: TokenId::new(),
        user_id: first,
        normalized_email: normalized.clone(),
        is_primary: true,
        verified_at: Utc::now(),
    };
    let second_claim = InsertVerifiedEmail {
        id: TokenId::new(),
        user_id: second,
        normalized_email: normalized,
        is_primary: true,
        verified_at: Utc::now(),
    };
    let (left, right) = tokio::join!(
        async move {
            let mut tx = one.begin().await?;
            tx.emails().insert_verified(&first_claim).await?;
            tx.commit().await
        },
        async move {
            let mut tx = two.begin().await?;
            tx.emails().insert_verified(&second_claim).await?;
            tx.commit().await
        }
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    let profile = database
        .users()
        .find_by_id(first)
        .await
        .expect("lookup")
        .expect("user");
    database
        .users()
        .update_profile(&UpdateUserProfile {
            id: first,
            expected_version: profile.profile_version,
            username: profile.username.clone(),
            display_name: "Updated".into(),
        })
        .await
        .expect("first update");
    assert!(matches!(
        database
            .users()
            .update_profile(&UpdateUserProfile {
                id: first,
                expected_version: profile.profile_version,
                username: profile.username,
                display_name: "Stale".into()
            })
            .await,
        Err(DatabaseError::Conflict)
    ));

    let session_id = SessionId::new();
    database
        .sessions()
        .insert(&InsertSession {
            id: session_id,
            user_id: first,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + ChronoDuration::hours(1),
            user_agent_family: None,
        })
        .await
        .expect("session");
    assert!(
        database
            .sessions()
            .revoke(session_id)
            .await
            .expect("revoke")
    );
    assert!(
        !database
            .sessions()
            .revoke(session_id)
            .await
            .expect("idempotent revoke")
    );

    let event = |kind: &str| AppendInternalEvent {
        id: TokenId::new(),
        aggregate_type: "user".into(),
        aggregate_id: first,
        event_type: kind.into(),
        schema_version: 1,
        payload: serde_json::json!({}),
    };
    let sequence_one = database
        .internal_events()
        .append(&event("profile.updated"))
        .await
        .expect("event one");
    let sequence_two = database
        .internal_events()
        .append(&event("profile.updated"))
        .await
        .expect("event two");
    assert_eq!((sequence_one, sequence_two), (1, 2));

    let disabled_one = insert_user(&database, "disabled_a").await;
    let disabled_two = insert_user(&database, "disabled_b").await;
    database
        .users()
        .set_status(disabled_one, AccountStatus::Disabled)
        .await
        .expect("disable");
    database
        .users()
        .set_status(disabled_two, AccountStatus::Disabled)
        .await
        .expect("disable");
    let shared = format!("disabled-{}@example.com", UserId::new());
    database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: disabled_one,
            normalized_email: shared.clone(),
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("email one");
    database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: disabled_two,
            normalized_email: shared,
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("email two");
    let one = database.clone();
    let two = database.clone();
    let (left, right) = tokio::join!(
        async move {
            one.users()
                .set_status(disabled_one, AccountStatus::Active)
                .await
        },
        async move {
            two.users()
                .set_status(disabled_two, AccountStatus::Active)
                .await
        }
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    // Verified-email insertion and disablement must serialize on the user row.
    // Regardless of which operation wins, lookup must never expose a disabled
    // account through stale ownership state.
    for _ in 0..20 {
        let user = insert_user(&database, "disable_email_race").await;
        let normalized = format!("disable-race-{user}@example.com");
        database
            .emails()
            .insert_verified(&InsertVerifiedEmail {
                id: TokenId::new(),
                user_id: user,
                normalized_email: normalized.clone(),
                is_primary: true,
                verified_at: Utc::now(),
            })
            .await
            .expect("initial email");
        let one = database.clone();
        let two = database.clone();
        let concurrent_email = InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: user,
            normalized_email: normalized.clone(),
            is_primary: false,
            verified_at: Utc::now(),
        };
        let (disabled, inserted) = tokio::join!(
            async move { one.users().set_status(user, AccountStatus::Disabled).await },
            async move { two.emails().insert_verified(&concurrent_email).await }
        );
        assert!(disabled.expect("disable race"));
        inserted.expect("concurrent email");
        assert!(
            database
                .emails()
                .find_active_verified(&normalized)
                .await
                .expect("active email lookup")
                .is_none()
        );
    }

    // Updating user_id affects both sides of the deferred primary-email
    // invariant. A transfer must not strand the source with no primary.
    let source = insert_user(&database, "transfer_source").await;
    let destination = insert_user(&database, "transfer_destination").await;
    let primary_id = TokenId::new();
    database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: primary_id,
            user_id: source,
            normalized_email: format!("transfer-primary-{source}@example.com"),
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("source primary");
    database
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: TokenId::new(),
            user_id: source,
            normalized_email: format!("transfer-secondary-{source}@example.com"),
            is_primary: false,
            verified_at: Utc::now(),
        })
        .await
        .expect("source secondary");
    database
        .users()
        .set_status(source, AccountStatus::Disabled)
        .await
        .expect("disable transfer source");
    let raw = sqlx::PgPool::connect(&env::var("TEST_DATABASE_URL").expect("database URL"))
        .await
        .expect("raw constraint test connection");
    let mut transfer = raw.begin().await.expect("begin transfer");
    sqlx::query("UPDATE user_emails SET user_id=$1 WHERE id=$2")
        .bind(destination.as_uuid())
        .bind(primary_id.as_uuid())
        .execute(&mut *transfer)
        .await
        .expect("update remains deferred");
    assert!(transfer.commit().await.is_err());
    raw.close().await;
}
