use super::*;
use chrono::{Duration, Utc};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration as Wait;

async fn pool() -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL"))
        .await
        .expect("connect");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate");
    pool
}

async fn family(pool: &PgPool, client: &str) -> (TokenId, Vec<u8>, SessionId) {
    let user = UserId::new();
    let session = SessionId::new();
    let family = TokenId::new();
    let token = TokenId::new();
    let digest = token.as_uuid().as_bytes().repeat(2);
    let mut tx = pool.begin().await.expect("transaction");
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Lock test')")
        .bind(user.as_uuid())
        .bind(format!("lock_{user}"))
        .execute(&mut *tx)
        .await
        .expect("user");
    sqlx::query("INSERT INTO sessions(id,user_id,authentication_methods,authenticated_at,expires_at,last_seen_at) VALUES($1,$2,'[]',now(),now()+interval '1 hour',now())")
        .bind(session.as_uuid()).bind(user.as_uuid()).execute(&mut *tx).await.expect("session");
    TokenRepository::from_connection(&mut tx)
        .insert_family(
            &InsertRefreshFamily {
                id: family,
                user_id: user,
                session_id: session,
                client_id: client.into(),
                audience: "test".into(),
                scopes: vec!["openid".into()],
            },
            &InsertRefreshToken {
                id: token,
                family_id: family,
                secret_digest: digest.clone(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        )
        .await
        .expect("family");
    tx.commit().await.expect("commit");
    (token, digest, session)
}

#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn independent_refreshes_share_client_and_logout_does_not_deadlock() {
    let pool = pool().await;
    let client = format!("locks_{}", UserId::new());
    sqlx::query("INSERT INTO oidc_clients(id,display_name,allowed_scopes,allowed_audiences,allow_refresh) VALUES($1,'Lock test','[\"openid\"]','[\"test\"]',true)")
        .bind(&client).execute(&pool).await.expect("client");
    let (first, digest_first, session) = family(&pool, &client).await;
    let (second, digest_second, _) = family(&pool, &client).await;
    let mut first_tx = pool.begin().await.expect("first transaction");
    TokenRepository::from_connection(&mut first_tx)
        .consume_for_rotation(first, &digest_first, &client)
        .await
        .expect("first refresh");
    let mut second_tx = pool.begin().await.expect("second transaction");
    tokio::time::timeout(
        Wait::from_secs(2),
        TokenRepository::from_connection(&mut second_tx).consume_for_rotation(
            second,
            &digest_second,
            &client,
        ),
    )
    .await
    .expect("independent users must not serialize on their client")
    .expect("second refresh");
    first_tx.rollback().await.expect("rollback");
    second_tx.rollback().await.expect("rollback");

    let mut logout = pool.begin().await.expect("logout transaction");
    sqlx::query("UPDATE sessions SET revoked_at=now() WHERE id=$1")
        .bind(session.as_uuid())
        .execute(&mut *logout)
        .await
        .expect("lock session");
    let mut rotation = pool.begin().await.expect("rotation transaction");
    let backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *rotation)
        .await
        .expect("backend pid");
    let rotation_task = tokio::spawn(async move {
        let result = TokenRepository::from_connection(&mut rotation)
            .consume_for_rotation(first, &digest_first, &client)
            .await;
        rotation.rollback().await.expect("rollback rotation");
        result
    });
    tokio::time::timeout(Wait::from_secs(2),async {
        loop {
            let waiting: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')")
                .bind(backend).fetch_one(&pool).await.expect("wait state");
            if waiting {break;}
            tokio::time::sleep(Wait::from_millis(10)).await;
        }
    }).await.expect("rotation waits for logout session lock");
    tokio::time::timeout(
        Wait::from_secs(2),
        OidcRepository::from_connection(&mut logout).revoke_session(session),
    )
    .await
    .expect("logout must not wait for refresh family locks")
    .expect("logout");
    logout.commit().await.expect("commit logout");
    let result = rotation_task.await.expect("rotation task");
    assert!(
        matches!(result, Err(RefreshRotationError::Invalid)),
        "{result:?}"
    );
}

#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn verified_email_updates_preserve_and_release_ownership() {
    let pool = pool().await;
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
    sqlx::query("INSERT INTO user_emails(id,user_id,normalized_email,verified_at,is_primary) VALUES($1,$2,$3,now(),true)")
        .bind(email).bind(users[0].as_uuid()).bind(&address).execute(&mut *tx).await.expect("email");
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
    assert!(sqlx::query("INSERT INTO user_emails(id,user_id,normalized_email,verified_at,is_primary) VALUES($1,$2,$3,now(),true)")
        .bind(uuid::Uuid::now_v7()).bind(users[1].as_uuid()).bind(&address).execute(&mut *tx).await.is_err());
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

#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn account_locks_allow_logout_audit_foreign_keys() {
    let pool = pool().await;
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
    tokio::time::timeout(Wait::from_secs(2),sqlx::query(
        "INSERT INTO security_audit_log(id,user_id,action,outcome) VALUES($1,$2,'logout','success')"
    ).bind(uuid::Uuid::now_v7()).bind(user.as_uuid()).execute(&mut *logout))
        .await.expect("account lock must allow logout foreign-key checks").expect("audit");
    logout.rollback().await.expect("rollback logout");
    account.rollback().await.expect("rollback account");
}
