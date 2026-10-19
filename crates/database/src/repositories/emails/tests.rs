//! Focused persistence and security contract tests.
use crate::Database;

use piquel_common::UserId;
/// Verified email ownership follows active account status and verification changes.
#[expect(
    clippy::too_many_lines,
    reason = "Keep the ownership lifecycle scenario of one address together."
)]
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn verified_email_updates_preserve_and_release_ownership() {
    let pool = Database::test_pool().await;
    let mut tx = pool.begin().await.expect("transaction");
    let users = [UserId::new(), UserId::new()];
    for user in users {
        sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Email test')")
            .bind(user.as_uuid())
            .bind(format!("email_{user}"))
            .execute(&mut *tx)
            .await
            .expect("user");
    }
    let email = uuid::Uuid::now_v7();
    let address = format!("{email}@example.test");
    sqlx::query(
        "INSERT INTO user_emails (id, user_id, normalized_email, verified_at, is_primary)
        VALUES ($1, $2, $3, now(), true)",
    )
    .bind(email)
    .bind(users[0].as_uuid())
    .bind(&address)
    .execute(&mut *tx)
    .await
    .expect("email");
    for update in [
        "verified_at=verified_at",
        "verified_at=now()+interval '1 second'",
    ] {
        sqlx::query(&format!("UPDATE user_emails SET {update} WHERE id=$1"))
            .bind(email)
            .execute(&mut *tx)
            .await
            .expect("update verification");
        let owner: uuid::Uuid = sqlx::query_scalar(
            "SELECT user_id FROM active_verified_email_ownership WHERE normalized_email=$1",
        )
        .bind(&address)
        .fetch_one(&mut *tx)
        .await
        .expect("ownership retained");
        assert_eq!(owner, users[0].as_uuid());
    }
    sqlx::query("SAVEPOINT duplicate_email")
        .execute(&mut *tx)
        .await
        .expect("savepoint");
    assert!(
        sqlx::query(
            "INSERT INTO user_emails (id, user_id, normalized_email, verified_at, is_primary)
            VALUES ($1, $2, $3, now(), true)"
        )
        .bind(uuid::Uuid::now_v7())
        .bind(users[1].as_uuid())
        .bind(&address)
        .execute(&mut *tx)
        .await
        .is_err()
    );
    sqlx::query("ROLLBACK TO duplicate_email")
        .execute(&mut *tx)
        .await
        .expect("rollback duplicate");
    sqlx::query(
        "UPDATE user_emails SET normalized_email=normalized_email||'.new',user_id=$2 WHERE id=$1",
    )
    .bind(email)
    .bind(users[1].as_uuid())
    .execute(&mut *tx)
    .await
    .expect("move address and owner");
    let old_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM active_verified_email_ownership WHERE normalized_email=$1)",
    )
    .bind(&address)
    .fetch_one(&mut *tx)
    .await
    .expect("old ownership");
    assert!(!old_exists);
    sqlx::query("UPDATE user_emails SET verified_at=NULL,is_primary=false WHERE id=$1")
        .bind(email)
        .execute(&mut *tx)
        .await
        .expect("unverify");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM active_verified_email_ownership WHERE user_id=ANY($1)",
    )
    .bind(users.map(UserId::as_uuid).as_slice())
    .fetch_one(&mut *tx)
    .await
    .expect("ownership count");
    assert_eq!(count, 0);
    sqlx::query("UPDATE user_emails SET verified_at=now(),is_primary=true WHERE id=$1")
        .bind(email)
        .execute(&mut *tx)
        .await
        .expect("reverify");
    sqlx::query("DELETE FROM user_emails WHERE id=$1")
        .bind(email)
        .execute(&mut *tx)
        .await
        .expect("delete");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM active_verified_email_ownership WHERE user_id=ANY($1)",
    )
    .bind(users.map(UserId::as_uuid).as_slice())
    .fetch_one(&mut *tx)
    .await
    .expect("ownership count");
    assert_eq!(count, 0);
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect("primary invariants");
    tx.rollback().await.expect("rollback");
}
