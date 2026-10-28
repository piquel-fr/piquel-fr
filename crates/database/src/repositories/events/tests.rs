//! Recording, personal data, the consumer cursor and the audit log import.
use super::*;
use crate::{Database, DatabaseTransaction};
use piquel_common::{PasskeyId, Provider, events::RevocationReason};
use sqlx::{Connection, PgConnection, PgPool};
use std::time::Duration;

/// Inserts an active account to be the subject of recorded events.
async fn insert_user(pool: &PgPool) -> UserId {
    let user = UserId::new();
    sqlx::query("INSERT INTO users(id,display_name) VALUES($1,'Event test')")
        .bind(user.as_uuid())
        .execute(pool)
        .await
        .expect("user");
    user
}

/// A context with request personal data, acting as `user`.
fn context(user: UserId) -> EventContext {
    EventContext {
        actor: Actor::User {
            user_id: user,
            session_id: None,
        },
        origin: RequestOrigin {
            client_ip: Some(IpAddr::from([192, 0, 2, 7])),
            user_agent_family: Some(UserAgentFamily {
                browser: Browser::Firefox,
                platform: Platform::Linux,
            }),
        },
        reason: Some("Reported for spam".into()),
    }
}

/// Records `event` about `user` in its own committed transaction.
async fn record(pool: &PgPool, user: UserId, event: DomainEvent) {
    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    tx.record(&context(user), Some(user), event)
        .await
        .expect("record");
    tx.commit().await.expect("commit");
}

/// Events commit and roll back with their transaction. Personal values, the
/// request origin and the reason stay out of the event row, read back while kept,
/// and read as erased once their row is deleted. Deleting the account leaves its
/// history.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn personal_data_is_stored_apart_and_erases() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let subject = format!("subject-{user}");
    let linked = || DomainEvent::IdentityLinked {
        provider: Provider::GitHub,
        subject: Personal::Value(subject.clone()),
    };
    let history = || async {
        EventRepository::from_pool(&pool)
            .history_for_user(user, 10)
            .await
            .expect("history")
    };

    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    tx.record(&context(user), Some(user), linked())
        .await
        .expect("record");
    tx.rollback().await.expect("rollback");
    assert!(
        history().await.is_empty(),
        "a rolled-back change leaves no event"
    );

    record(&pool, user, linked()).await;
    let [stored] = <[StoredEvent; 1]>::try_from(history().await).expect("one event");
    assert_eq!(stored.event, RecordedEvent::Known(linked()));
    assert_eq!(stored.actor, context(user).actor);
    assert_eq!(stored.origin, Personal::Value(context(user).origin));
    assert_eq!(stored.reason, context(user).reason);
    let (event_row, personal_row): (String, String) = sqlx::query_as(
        "SELECT to_jsonb(e)::text, to_jsonb(p)::text
        FROM domain_events e JOIN event_personal_data p ON p.event_id = e.id
        WHERE e.id = $1",
    )
    .bind(stored.id.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("rows");
    for personal in [
        subject.as_str(),
        "192.0.2.7",
        "firefox",
        "Reported for spam",
    ] {
        assert!(!event_row.contains(personal), "{personal} in {event_row}");
        assert!(
            personal_row.contains(personal),
            "{personal} in {personal_row}"
        );
    }

    sqlx::query("DELETE FROM event_personal_data WHERE event_id = $1")
        .bind(stored.id.as_uuid())
        .execute(&pool)
        .await
        .expect("erase");
    let [erased] = <[StoredEvent; 1]>::try_from(history().await).expect("one event");
    assert_eq!(
        erased.event,
        RecordedEvent::Known(DomainEvent::IdentityLinked {
            provider: Provider::GitHub,
            subject: Personal::Erased,
        })
    );
    assert_eq!(erased.origin, Personal::Erased);
    assert_eq!(erased.reason, None);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.as_uuid())
        .execute(&pool)
        .await
        .expect("events never block deleting their account");
    assert_eq!(history().await.len(), 1, "history outlives the account");
}

/// Reads `user`'s events from `consumer`'s cursor until `count` arrived,
/// acknowledging everything read. Other tests write events concurrently, and their
/// open transactions can briefly hold the stream back.
async fn consume(
    pool: &PgPool,
    consumer: &'static str,
    user: UserId,
    count: usize,
) -> Vec<DomainEvent> {
    let mut events = Vec::new();
    for _ in 0..100 {
        let batch = EventRepository::from_pool(pool)
            .read_after(consumer, 100)
            .await
            .expect("read");
        let Some(last) = batch.last().map(|event| event.cursor) else {
            if events.len() >= count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        events.extend(
            batch
                .into_iter()
                .filter(|event| event.subject == Some(user))
                .map(|event| event.event.known().cloned().expect("a known event")),
        );
        EventRepository::from_pool(pool)
            .acknowledge(consumer, last)
            .await
            .expect("acknowledge");
    }
    events
}

/// An event that commits after a later one is still read, and before it: the
/// consumer waits for the earlier transaction instead of skipping its event.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn read_after_never_skips_an_event_committed_out_of_order() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let consumer: &'static str = format!("test-{user}").leak();
    consume(&pool, consumer, user, 0).await;
    let added = || DomainEvent::PasskeyAdded {
        passkey_id: PasskeyId::new(),
    };
    let (first, second) = (added(), added());

    let mut earlier = DatabaseTransaction::new(pool.begin().await.expect("earlier"));
    earlier
        .record(&context(user), Some(user), first.clone())
        .await
        .expect("record first");
    record(&pool, user, second.clone()).await;
    assert!(
        consume(&pool, consumer, user, 0).await.is_empty(),
        "the committed event waits for the earlier transaction"
    );
    earlier.commit().await.expect("commit earlier");
    assert_eq!(consume(&pool, consumer, user, 2).await, [first, second]);
}

/// An event whose payload an older release could not decode is written in its
/// kind's next version, and this release reads it back. Other events of the kind
/// keep the first version.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn versions_are_per_event() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let revoked = |reason| DomainEvent::SessionRevoked {
        session_id: SessionId::new(),
        reason,
    };
    let events = [
        revoked(RevocationReason::Logout),
        revoked(RevocationReason::UserRevoked),
    ];
    for event in events.clone() {
        record(&pool, user, event).await;
    }
    let stored = EventRepository::from_pool(&pool)
        .history_for_user(user, 10)
        .await
        .expect("history");
    assert_eq!(
        stored
            .iter()
            .rev()
            .map(|stored| &stored.event)
            .collect::<Vec<_>>(),
        events
            .iter()
            .cloned()
            .map(RecordedEvent::Known)
            .collect::<Vec<_>>()
            .iter()
            .collect::<Vec<_>>()
    );
    let versions: Vec<i16> = sqlx::query_scalar(
        "SELECT version FROM domain_events WHERE subject_user_id = $1 ORDER BY sequence",
    )
    .bind(user.as_uuid())
    .fetch_all(&pool)
    .await
    .expect("versions");
    assert_eq!(versions, [1, 2]);
}

/// Events a newer release wrote, of a kind this one does not know or a known kind
/// in a newer payload version, read as unknown with their data. A known kind
/// whose payload does not decode still fails.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn events_a_newer_release_wrote_read_as_unknown() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let mut events = EventRepository::from_pool(&pool);
    let data = serde_json::json!({"client_id": "deleted"});
    for (kind, version) in [
        ("from_a_newer_release", DomainEvent::FIRST_VERSION),
        ("passkey_added", DomainEvent::FIRST_VERSION + 1),
    ] {
        events
            .insert_written_elsewhere(user, kind, version, &data)
            .await
            .expect("event");
    }
    let unknown = |kind: &str, version| RecordedEvent::Unknown {
        kind: kind.into(),
        version,
        data: data.clone(),
    };
    assert_eq!(
        events
            .history_for_user(user, 10)
            .await
            .expect("history")
            .into_iter()
            .map(|stored| stored.event)
            .collect::<Vec<_>>(),
        [
            unknown("passkey_added", DomainEvent::FIRST_VERSION + 1),
            unknown("from_a_newer_release", DomainEvent::FIRST_VERSION),
        ]
    );

    // Rolled back, so that consumers of every event never read it.
    let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    tx.events()
        .insert_written_elsewhere(user, "passkey_added", DomainEvent::FIRST_VERSION, &data)
        .await
        .expect("malformed event");
    assert!(matches!(
        tx.events().history_for_user(user, 10).await,
        Err(DatabaseError::InvalidStoredData { .. })
    ));
    tx.rollback().await.expect("rollback");
}

/// Migration `0005` turns audit rows into imported events with their action, outcome
/// and metadata, and `0018` imports the rows written since, then drops the log. It
/// runs in a scratch schema, since the test database is migrated.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn migration_imports_the_audit_log() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let mut connection = PgConnection::connect(&url).await.expect("connect");
    let user = UserId::new();
    let schema = format!("import_{}", user.as_uuid().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .execute(&mut connection)
    .await
    .expect("schema");
    for migration in [
        include_str!("../../../migrations/0001_initial.sql"),
        include_str!("../../../migrations/0002_refresh_family_authorization_code.sql"),
        include_str!("../../../migrations/0003_session_passkey_confirmation.sql"),
        include_str!("../../../migrations/0004_authentication_claims.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(&mut connection)
            .await
            .expect("earlier migration");
    }
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,'imported','Import test')")
        .bind(user.as_uuid())
        .execute(&mut connection)
        .await
        .expect("user");
    let audit = async |connection: &mut PgConnection, action: &str, metadata: &str, age: i32| {
        sqlx::query(
            "INSERT INTO security_audit_log(id,user_id,action,outcome,request_metadata,created_at)
            VALUES($1,$2,$3,'success',$4::jsonb,now() - make_interval(hours => $5))",
        )
        .bind(EventId::new().as_uuid())
        .bind(user.as_uuid())
        .bind(action)
        .bind(metadata)
        .bind(age)
        .execute(connection)
        .await
        .expect("audit row");
    };
    audit(&mut connection, "passkey.login", "{}", 3).await;
    audit(
        &mut connection,
        "federation.link",
        r#"{"provider":"github"}"#,
        2,
    )
    .await;
    sqlx::raw_sql(include_str!("../../../migrations/0005_domain_events.sql"))
        .execute(&mut connection)
        .await
        .expect("migration");
    // The release before 0005 keeps writing to the log during that deploy.
    audit(&mut connection, "passkey.login", "{}", 1).await;
    // The rest bring the schema to the one this release reads.
    for migration in [
        include_str!("../../../migrations/0006_deliveries.sql"),
        include_str!("../../../migrations/0007_administrators.sql"),
        include_str!("../../../migrations/0008_oidc_client_registry.sql"),
        include_str!("../../../migrations/0009_pushed_authorization_requests.sql"),
        include_str!("../../../migrations/0010_session_devices.sql"),
        include_str!("../../../migrations/0015_event_reasons.sql"),
        include_str!("../../../migrations/0018_contract_audit_log_and_legacy_secrets.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(&mut connection)
            .await
            .expect("later migration");
    }

    let history = EventRepository::from_connection(&mut connection)
        .history_for_user(user, 10)
        .await
        .expect("history");
    let imported: Vec<_> = history
        .iter()
        .map(|stored| match &stored.event {
            RecordedEvent::Known(DomainEvent::Imported(audit)) => {
                assert_eq!(stored.actor, Actor::Unrecorded);
                (audit.action(), audit.outcome(), audit.metadata().clone())
            }
            event => panic!("unexpected {event:?}"),
        })
        .collect();
    assert_eq!(
        imported,
        [
            ("passkey.login", "success", serde_json::json!({})),
            (
                "federation.link",
                "success",
                serde_json::json!({"provider": "github"})
            ),
            ("passkey.login", "success", serde_json::json!({})),
        ]
    );
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .expect("drop schema");
}
