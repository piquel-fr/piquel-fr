//! Notifications commit with their event, page without gaps, read and unread,
//! and stay their owner's.
use super::*;
use crate::{Database, DatabaseTransaction, InsertUser};
use sourceorigin_common::{
    Personal, SessionId,
    events::{Actor, DomainEvent, EventContext, RequestOrigin},
};
use sqlx::PgPool;
use std::collections::HashSet;

/// A new account, with the database its tests use.
async fn account(name: &str) -> (Database, UserId) {
    let database = Database {
        pool: Database::test_pool().await,
    };
    let account = InsertUser::named(name);
    database.users().insert(&account).await.expect("user");
    (database, account.id)
}

/// `actor` causing an event.
fn by(actor: Actor) -> EventContext {
    EventContext {
        actor,
        origin: RequestOrigin::default(),
        reason: None,
    }
}

/// The display name changing.
fn renamed() -> DomainEvent {
    DomainEvent::DisplayNameChanged {
        old: Personal::Value("Old".to_owned()),
        new: Personal::Value("New".to_owned()),
    }
}

/// Every notification of `user`'s, newest first.
async fn inbox(pool: &PgPool, user: UserId) -> Vec<StoredNotification> {
    NotificationRepository::from_pool(pool)
        .list(user, None, 100)
        .await
        .expect("inbox")
}

/// An event that notifies writes one notification for its subject, from it, in
/// its transaction: a rolled-back one writes none, and an owner renaming their
/// own account is told nothing.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn notifications_commit_with_their_event() {
    let (database, user) = account("notified").await;
    let admin = by(Actor::Admin {
        user_id: UserId::new(),
        session_id: SessionId::new(),
    });
    let owner = by(Actor::User {
        user_id: user,
        session_id: None,
    });

    let mut tx = database.begin().await.expect("transaction");
    tx.record(&admin, Some(user), renamed())
        .await
        .expect("record");
    tx.rollback().await.expect("rollback");
    assert_eq!(inbox(&database.pool, user).await, []);

    let mut tx = database.begin().await.expect("transaction");
    tx.record(&owner, Some(user), renamed())
        .await
        .expect("record");
    tx.record(&admin, Some(user), renamed())
        .await
        .expect("record");
    tx.commit().await.expect("commit");
    let [notification]: [StoredNotification; 1] = inbox(&database.pool, user)
        .await
        .try_into()
        .expect("one notification");
    assert_eq!(
        notification.notification,
        Some(Notification::DisplayNameChanged)
    );
    assert_eq!(notification.read_at, None);
    let [by_admin, _] = database
        .events()
        .history_for_user(user, 10)
        .await
        .expect("events")
        .try_into()
        .expect("two events, newest first");
    assert_eq!(notification.event_id, Some(by_admin.id));
}

/// Notifications written together share a time, and pages still list each once.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn pages_continue_across_equal_times() {
    let (database, user) = account("paged").await;
    let mut tx: DatabaseTransaction<'_> = database.begin().await.expect("transaction");
    for _ in 0..5 {
        tx.notifications()
            .insert(user, None, &Notification::AccountEnabled)
            .await
            .expect("insert");
    }
    tx.commit().await.expect("commit");

    let mut notifications = database.notifications();
    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let page = notifications.list(user, before, 2).await.expect("page");
        let Some(last) = page.last() else { break };
        before = Some(last.id);
        seen.extend(page.iter().map(|stored| stored.id));
    }
    let all: Vec<_> = inbox(&database.pool, user)
        .await
        .into_iter()
        .map(|stored| stored.id)
        .collect();
    assert_eq!(seen, all);
    assert_eq!(seen.iter().collect::<HashSet<_>>().len(), 5);
}

/// A kind a newer release wrote reads as unknown, not as corrupt.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn newer_kinds_read_as_unknown() {
    let (database, user) = account("future").await;
    sqlx::query(
        r#"INSERT INTO notifications (id, user_id, payload)
        VALUES ($1, $2, '{"kind": "from_a_newer_release"}')"#,
    )
    .bind(NotificationId::new().as_uuid())
    .bind(user.as_uuid())
    .execute(&database.pool)
    .await
    .expect("insert");
    let [stored]: [StoredNotification; 1] = inbox(&database.pool, user)
        .await
        .try_into()
        .expect("one notification");
    assert_eq!(stored.notification, None);
}

/// Reading marks one notification read, keeping when it was first read; it can
/// be marked unread again, and every one read at once. Another account can
/// neither read nor mark it.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn owners_read_and_unread_their_own() {
    let (database, user) = account("reader").await;
    let (_, other) = account("stranger").await;
    let mut notifications = database.notifications();
    let first = notifications
        .insert(user, None, &Notification::AccountEnabled)
        .await
        .expect("insert")
        .expect("the account exists");
    notifications
        .insert(user, None, &Notification::AccountRestored)
        .await
        .expect("insert");
    assert_eq!(notifications.unread(user).await.expect("unread"), 2);

    assert!(!notifications.mark(other, first, true).await.expect("mark"));
    assert_eq!(notifications.find(other, first).await.expect("find"), None);

    assert!(notifications.mark(user, first, true).await.expect("mark"));
    let read_at = notifications
        .find(user, first)
        .await
        .expect("find")
        .and_then(|stored| stored.read_at)
        .expect("read");
    assert!(notifications.mark(user, first, true).await.expect("mark"));
    let again = notifications.find(user, first).await.expect("find");
    assert_eq!(again.and_then(|stored| stored.read_at), Some(read_at));
    assert_eq!(notifications.unread(user).await.expect("unread"), 1);

    assert!(notifications.mark(user, first, false).await.expect("mark"));
    assert_eq!(notifications.unread(user).await.expect("unread"), 2);
    notifications.mark_all_read(user).await.expect("all read");
    assert_eq!(notifications.unread(user).await.expect("unread"), 0);
}
