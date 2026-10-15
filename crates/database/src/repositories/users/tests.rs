//! Focused persistence and security contract tests.
use crate::Database;

use crate::repositories::{SessionRepository, UserRepository, sessions::InsertSession};
use chrono::Utc;
use piquel_auth_protocol::{SessionId, UserId};
use sqlx::PgPool;
use std::time::Duration;

/// Inserts an active account for one lock scenario.
async fn insert_user(pool: &PgPool) -> UserId {
    let user = UserId::new();
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Lock test')")
        .bind(user.as_uuid())
        .bind(format!("lock_{user}"))
        .execute(pool)
        .await
        .expect("user");
    user
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
        user_agent_family: None,
        passkey_confirmed_at: None,
    }
}
/// Account locks allow logout to insert audit records without a foreign-key deadlock.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn account_locks_allow_logout_audit_foreign_keys() {
    let pool = Database::test_pool().await;
    let user = insert_user(&pool).await;
    let mut account = pool.begin().await.expect("account transaction");
    UserRepository::from_connection(&mut account)
        .find_active_by_id_for_update(user)
        .await
        .expect("account lock")
        .expect("active account");
    let mut logout = pool.begin().await.expect("logout transaction");
    tokio::time::timeout(Duration::from_secs(2),sqlx::query(
        "INSERT INTO security_audit_log(id,user_id,action,outcome) VALUES($1,$2,'logout','success')"
    ).bind(uuid::Uuid::now_v7()).bind(user.as_uuid()).execute(&mut *logout))
        .await.expect("account lock must allow logout foreign-key checks").expect("audit");
    logout.rollback().await.expect("rollback logout");
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
    sqlx::query(
        "INSERT INTO security_audit_log(id,user_id,action,outcome) VALUES($1,$2,'login','success')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(user.as_uuid())
    .execute(&mut *reference)
    .await
    .expect("audit");
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
    assert!(
        SessionRepository::from_connection(&mut logout)
            .revoke(session)
            .await
            .expect("revoke")
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
