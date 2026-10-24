//! Persistence guarantees behind recovery links.
use chrono::{Duration, Utc};
use piquel_common::{Handle, PasskeyId, RecoveryId, UserId};
use piquel_repository::{Database, DatabaseConfig, InsertRecovery, InsertUser};

/// A link that expires while its finish waits, as it would for the account lock,
/// does not complete, though the transaction started before the deadline.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_link_that_expires_while_finishing_does_not_complete() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let db = Database::connect(
        DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("config"),
    )
    .await
    .expect("connect");
    db.run_migrations().await.expect("migrate");
    let user = UserId::new();
    db.users()
        .insert(&InsertUser {
            id: user,
            handle: Handle::parse(&format!("recover-{}", &user.to_string()[24..])).expect("handle"),
            display_name: "Recovery test".into(),
        })
        .await
        .expect("user");
    let id = RecoveryId::new();
    let digest = id.as_uuid().as_bytes().repeat(2);
    db.recoveries()
        .insert(&InsertRecovery {
            id,
            user_id: user,
            secret_digest: &digest,
            primary_email_id: None,
            expires_at: Utc::now() + Duration::milliseconds(500),
        })
        .await
        .expect("recovery");

    let mut tx = db.begin().await.expect("transaction");
    tx.users()
        .find_active_by_id_for_update(user)
        .await
        .expect("lock")
        .expect("user");
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let completed = tx.recoveries().complete(user, id, PasskeyId::new()).await;
    assert!(!completed.expect("complete"), "expired while waiting");
}
