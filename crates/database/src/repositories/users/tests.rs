use crate::repositories::{SessionRepository, UserRepository, sessions::InsertSession, test_pool};
use chrono::Utc;
use piquel_auth_protocol::{SessionId, UserId};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn account_locks_allow_logout_audit_foreign_keys() {
    let pool = test_pool().await;
    let user = UserId::new();
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Lock test')")
        .bind(user.as_uuid())
        .bind(format!("audit_{user}"))
        .execute(&pool)
        .await
        .expect("user");
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
    let pool = test_pool().await;
    let user = UserId::new();
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Lock test')")
        .bind(user.as_uuid())
        .bind(format!("fk_{user}"))
        .execute(&pool)
        .await
        .expect("user");
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
    let now = Utc::now();
    tokio::time::timeout(
        Duration::from_secs(2),
        SessionRepository::from_connection(&mut account).insert(&InsertSession {
            id: SessionId::new(),
            user_id: user,
            authentication_methods: Vec::new(),
            authenticated_at: now,
            expires_at: now + chrono::Duration::days(1),
            user_agent_family: None,
        }),
    )
    .await
    .expect("session creation must not wait on foreign-key checks")
    .expect("session");
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query(
            "INSERT INTO user_emails(id,user_id,normalized_email,verified_at) VALUES($1,$2,$3,now())",
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
