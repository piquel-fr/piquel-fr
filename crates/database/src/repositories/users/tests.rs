use crate::repositories::{UserRepository, test_pool};
use piquel_auth_protocol::UserId;
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
