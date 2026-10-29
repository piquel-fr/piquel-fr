//! Focused persistence and security contract tests.
use crate::Database;

use crate::repositories::{
    SessionRepository, UserRepository,
    sessions::{InsertSession, LAST_SEEN_INTERVAL, SessionScope},
    users::InsertUser,
};
use chrono::Utc;
use piquel_common::{
    SessionId, UserId,
    events::{Browser, Platform, UserAgentFamily},
};
use sqlx::PgPool;
use std::{net::IpAddr, time::Duration};

/// Inserts an active account for one lock scenario.
async fn insert_user(pool: &PgPool) -> UserId {
    UserRepository::from_pool(pool)
        .insert(&InsertUser::named("lock"))
        .await
        .expect("user")
        .id
}

/// A session valid from now until tomorrow.
fn session_for(user: UserId) -> InsertSession {
    let now = Utc::now();
    InsertSession {
        id: SessionId::new(),
        user_id: user,
        authentication_methods: Vec::new(),
        authenticated_at: now,
        expires_at: now + chrono::Duration::days(1),
        user_agent_family: UserAgentFamily {
            browser: Browser::Firefox,
            platform: Platform::Linux,
        },
        ip: IpAddr::from([192, 0, 2, 1]),
        passkey_confirmed_at: None,
        passkey_id: None,
    }
}
/// Inserts a passkey row, which references the account through a foreign key.
async fn insert_reference(connection: &mut sqlx::PgConnection, user: UserId) {
    sqlx::query(
        "INSERT INTO passkey_credentials(id,credential_id,user_id,credential,friendly_name)
        VALUES($1,$2,$3,'{}','Lock test')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(uuid::Uuid::now_v7().as_bytes().to_vec())
    .bind(user.as_uuid())
    .execute(connection)
    .await
    .expect("reference");
}

/// Account locks let other transactions insert rows referencing the account.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn account_locks_allow_foreign_key_checks() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let mut account = pool.begin().await.expect("account transaction");
    UserRepository::from_connection(&mut account)
        .find_active_by_id_for_update(user)
        .await
        .expect("account lock")
        .expect("active account");
    let mut reference = pool.begin().await.expect("reference transaction");
    tokio::time::timeout(
        Duration::from_secs(2),
        insert_reference(&mut reference, user),
    )
    .await
    .expect("account lock must allow foreign-key checks");
    reference.rollback().await.expect("rollback reference");
    account.rollback().await.expect("rollback account");
}

/// Session creation and email claims lock the account too. They must not wait on a
/// concurrent foreign-key check, or they deadlock with requests that reference it.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn account_locks_do_not_wait_on_foreign_key_checks() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let mut reference = pool.begin().await.expect("reference transaction");
    insert_reference(&mut reference, user).await;
    let mut account = pool.begin().await.expect("account transaction");
    tokio::time::timeout(
        Duration::from_secs(2),
        SessionRepository::from_connection(&mut account).insert(&session_for(user)),
    )
    .await
    .expect("session creation must not wait on foreign-key checks")
    .expect("session");
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query(
            "INSERT INTO user_emails (id, user_id, normalized_email, verified_at)
            VALUES ($1, $2, $3, now())",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(user.as_uuid())
        .bind(format!("{user}@example.com"))
        .execute(&mut *account),
    )
    .await
    .expect("email claims must not wait on foreign-key checks")
    .expect("email");
    account.rollback().await.expect("rollback account");
    reference.rollback().await.expect("rollback reference");
}

/// Code exchange revalidates its session under lock, so it sees a concurrent logout.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn locked_session_lookup_waits_for_concurrent_logout() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let session = SessionRepository::from_pool(&pool)
        .insert(&session_for(user))
        .await
        .expect("session")
        .id;
    let mut logout = pool.begin().await.expect("logout transaction");
    assert_eq!(
        SessionRepository::from_connection(&mut logout)
            .revoke(user, SessionScope::One(session))
            .await
            .expect("revoke"),
        [session]
    );
    let exchange = tokio::spawn(async move {
        let mut exchange = pool.begin().await.expect("exchange transaction");
        SessionRepository::from_connection(&mut exchange)
            .find_active_by_id_for_update(session)
            .await
            .expect("lookup")
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!exchange.is_finished(), "lookup must wait for the logout");
    logout.commit().await.expect("commit logout");
    assert!(exchange.await.expect("exchange task").is_none());
}

/// Activity is recorded at most once per interval: a fresh session keeps its first
/// IP, and a stale one takes the new one.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn touch_records_activity_at_most_once_per_interval() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let mut sessions = SessionRepository::from_pool(&pool);
    let session = sessions.insert(&session_for(user)).await.expect("session");
    let elsewhere = IpAddr::from([198, 51, 100, 9]);
    let pool = &pool;
    let last_seen = |id| async move {
        let session = SessionRepository::from_pool(pool)
            .find_by_id(id)
            .await
            .expect("lookup")
            .expect("session");
        (session.last_seen_at, session.last_seen_ip)
    };

    sessions.touch(session.id, elsewhere).await.expect("touch");
    assert_eq!(
        last_seen(session.id).await,
        (session.last_seen_at, session.last_seen_ip),
        "a fresh session is not written"
    );

    sqlx::query("UPDATE sessions SET last_seen_at = $2 WHERE id = $1")
        .bind(session.id.as_uuid())
        .bind(Utc::now() - LAST_SEEN_INTERVAL - chrono::Duration::seconds(1))
        .execute(pool)
        .await
        .expect("age session");
    sessions.touch(session.id, elsewhere).await.expect("touch");
    let (at, ip) = last_seen(session.id).await;
    assert!(at > session.last_seen_at);
    assert_eq!(ip, Some(elsewhere));
}
