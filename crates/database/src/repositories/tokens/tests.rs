use super::{InsertRefreshFamily, InsertRefreshToken, RefreshRotationError};
use crate::repositories::{OidcRepository, TokenRepository, test_pool};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use sqlx::PgPool;
use std::time::Duration as Wait;

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
    let pool = test_pool().await;
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
