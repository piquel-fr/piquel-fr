//! Persistence guarantees behind recovery links.
use chrono::{Duration, Utc};
use piquel_common::{Handle, PasskeyId, RecoveryId, UserId};
use piquel_repository::{Database, DatabaseConfig, InsertRecovery, InsertUser};

/// Connects to the migrated test database and creates an account.
async fn account() -> (Database, UserId) {
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
    (db, user)
}

/// A new recovery `id` of `user`, whose link's token has `digest`, expiring
/// after `lifetime`.
fn recovery(user: UserId, id: RecoveryId, digest: &[u8], lifetime: Duration) -> InsertRecovery<'_> {
    InsertRecovery {
        id,
        user_id: user,
        secret_digest: digest,
        primary_email_id: None,
        expires_at: Utc::now() + lifetime,
    }
}

/// A link that expires while its finish waits, as it would for the account lock,
/// does not complete, though the transaction started before the deadline.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_link_that_expires_while_finishing_does_not_complete() {
    let (db, user) = account().await;
    let id = RecoveryId::new();
    let digest = id.as_uuid().as_bytes().repeat(2);
    db.recoveries()
        .insert(&recovery(user, id, &digest, Duration::milliseconds(500)))
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

/// Recoveries sort in the order they were stored, not the order their
/// transactions began: one that waited for the account lock while another
/// started and was used is the newest.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn the_newest_recovery_is_the_last_stored() {
    let (db, user) = account().await;
    let (waiting, finished) = (RecoveryId::new(), RecoveryId::new());
    let digests = [waiting, finished].map(|id| id.as_uuid().as_bytes().repeat(2));
    let mut tx = db.begin().await.expect("transaction");
    tx.users()
        .find_active_by_id_for_update(user)
        .await
        .expect("lock")
        .expect("user");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // Started and used while the first transaction was already open.
    db.recoveries()
        .insert(&recovery(user, finished, &digests[1], Duration::hours(1)))
        .await
        .expect("finished recovery");
    let completed = db
        .recoveries()
        .complete(user, finished, PasskeyId::new())
        .await;
    assert!(completed.expect("complete"));
    tx.recoveries()
        .insert(&recovery(user, waiting, &digests[0], Duration::hours(1)))
        .await
        .expect("waiting recovery");
    tx.commit().await.expect("commit");

    let settled_before = Utc::now() - Duration::days(30);
    let undoable = db.recoveries().undoable(user, settled_before).await;
    let newest = undoable
        .expect("undoable")
        .first()
        .map(|recovery| recovery.id);
    assert_eq!(newest, Some(waiting));
}
