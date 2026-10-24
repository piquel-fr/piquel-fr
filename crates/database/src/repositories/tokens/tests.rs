//! Focused persistence and security contract tests.
use crate::Database;

use super::{InsertRefreshFamily, InsertRefreshToken, RefreshRotationError};
use crate::repositories::{OidcRepository, SessionRepository, TokenRepository};
use crate::{CodeRedemptionError, DatabaseTransaction, SessionAuthentication, SessionScope};
use chrono::{Duration, Utc};
use piquel_common::{
    ClientId, SessionId, TokenId, UserId,
    protocol::claims::{Acr, Amr},
};
use sqlx::{PgConnection, PgPool};
use std::time::Duration as Wait;

/// Authorization callback registered for every fixture client.
const REDIRECT_URI: &str = "https://client.example/callback";

/// Registers a refresh-capable client whose policy allows fixture codes.
async fn client(pool: &PgPool) -> ClientId {
    let client: ClientId = format!("locks_{}", UserId::new())
        .parse()
        .expect("client ID");
    sqlx::query(
        "INSERT INTO oidc_clients (
            id, display_name, allowed_scopes, allowed_audiences, allow_refresh
        ) VALUES ($1, 'Lock test', '[\"openid\"]', '[\"test\"]', true)",
    )
    .bind(client.as_str())
    .execute(pool)
    .await
    .expect("client");
    sqlx::query(
        "INSERT INTO oidc_redirect_uris (client_id, uri, kind, origin)
        VALUES ($1, $2, 'authorization', 'https://client.example')",
    )
    .bind(client.as_str())
    .bind(REDIRECT_URI)
    .execute(pool)
    .await
    .expect("redirect");
    client
}

/// Authentication recorded on every fixture grant.
fn authentication() -> SessionAuthentication {
    SessionAuthentication {
        acr: Acr::PhishingResistant,
        auth_time: Utc::now(),
        amr: vec![Amr::Pop],
    }
}

/// Returns the server process of a connection, to observe its lock waits.
async fn backend(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .expect("backend pid")
}

/// Waits until the server process `backend` is blocked on a lock.
async fn wait_for_lock(pool: &PgPool, backend: i32) {
    tokio::time::timeout(Wait::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity
                    WHERE pid = $1
                    AND wait_event_type = 'Lock'
                )",
            )
            .bind(backend)
            .fetch_one(pool)
            .await
            .expect("wait state");
            if waiting {
                break;
            }
            tokio::time::sleep(Wait::from_millis(10)).await;
        }
    })
    .await
    .expect("the transaction waits for a lock");
}

/// A committed account, browser session and unredeemed authorization code.
struct Grant {
    /// Account the code was issued to.
    user: UserId,
    /// Session that authorized the code.
    session: SessionId,
    /// Authorization code identifier.
    code: TokenId,
    /// Digest of the code secret.
    code_digest: Vec<u8>,
}

impl Grant {
    /// Commits a fresh account, session and code issued to `client`.
    async fn new(pool: &PgPool, client: &ClientId) -> Self {
        let grant = Self {
            user: UserId::new(),
            session: SessionId::new(),
            code: TokenId::new(),
            code_digest: TokenId::new().as_uuid().as_bytes().repeat(2),
        };
        let mut tx = pool.begin().await.expect("transaction");
        sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Lock test')")
            .bind(grant.user.as_uuid())
            .bind(format!("lock_{}", grant.user))
            .execute(&mut *tx)
            .await
            .expect("user");
        sqlx::query(
            "INSERT INTO sessions (
                id, user_id, authentication_methods, authenticated_at, expires_at, last_seen_at
            ) VALUES ($1, $2, '[]', now(), now() + interval '1 hour', now())",
        )
        .bind(grant.session.as_uuid())
        .bind(grant.user.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("session");
        sqlx::query(
            "INSERT INTO authorization_codes (
                id, secret_digest, client_id, user_id, session_id, redirect_uri,
                pkce_challenge, scopes, audience, expires_at, authentication
            ) VALUES ($1, $2, $3, $4, $5, $6, 'challenge', '[\"openid\"]', 'test',
                now() + interval '1 minute', $7)",
        )
        .bind(grant.code.as_uuid())
        .bind(&grant.code_digest)
        .bind(client.as_str())
        .bind(grant.user.as_uuid())
        .bind(grant.session.as_uuid())
        .bind(REDIRECT_URI)
        .bind(sqlx::types::Json(authentication()))
        .execute(&mut *tx)
        .await
        .expect("code");
        tx.commit().await.expect("commit");
        grant
    }

    /// Creates a refresh family redeemed from this grant's code and returns its
    /// first token with that token's digest.
    async fn family(
        &self,
        tokens: &mut TokenRepository<'_>,
        client: &ClientId,
    ) -> (TokenId, Vec<u8>) {
        let family = TokenId::new();
        let token = TokenId::new();
        let digest = token.as_uuid().as_bytes().repeat(2);
        tokens
            .insert_family(
                &InsertRefreshFamily {
                    id: family,
                    user_id: self.user,
                    session_id: self.session,
                    client_id: client.to_string(),
                    authorization_code_id: self.code,
                    audience: "test".into(),
                    scopes: vec!["openid".into()],
                    authentication: authentication(),
                },
                &InsertRefreshToken {
                    id: token,
                    family_id: family,
                    secret_digest: digest.clone(),
                    digest_key: "test".into(),
                    expires_at: Utc::now() + Duration::hours(1),
                },
            )
            .await
            .expect("family");
        (token, digest)
    }
}

/// Shared client policy permits independent refreshes while logout waits in the
/// documented lock order.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn independent_refreshes_share_client_and_logout_does_not_deadlock() {
    let pool = Database::test_pool().await;
    let client = client(&pool).await;
    let grant = Grant::new(&pool, &client).await;
    let (first, digest_first) = grant
        .family(&mut TokenRepository::from_pool(&pool), &client)
        .await;
    let (second, digest_second) = Grant::new(&pool, &client)
        .await
        .family(&mut TokenRepository::from_pool(&pool), &client)
        .await;
    let mut first_tx = pool.begin().await.expect("first transaction");
    TokenRepository::from_connection(&mut first_tx)
        .consume_for_rotation(first, std::slice::from_ref(&digest_first), client.as_str())
        .await
        .expect("first refresh");
    let mut second_tx = pool.begin().await.expect("second transaction");
    tokio::time::timeout(
        Wait::from_secs(2),
        TokenRepository::from_connection(&mut second_tx).consume_for_rotation(
            second,
            std::slice::from_ref(&digest_second),
            client.as_str(),
        ),
    )
    .await
    .expect("independent users must not serialize on their client")
    .expect("second refresh");
    first_tx.rollback().await.expect("rollback");
    second_tx.rollback().await.expect("rollback");

    let mut logout = pool.begin().await.expect("logout transaction");
    sqlx::query("UPDATE sessions SET revoked_at=now() WHERE id=$1")
        .bind(grant.session.as_uuid())
        .execute(&mut *logout)
        .await
        .expect("lock session");
    let mut rotation = pool.begin().await.expect("rotation transaction");
    let rotation_backend = backend(&mut rotation).await;
    let rotation_task = tokio::spawn(async move {
        let result = TokenRepository::from_connection(&mut rotation)
            .consume_for_rotation(first, std::slice::from_ref(&digest_first), client.as_str())
            .await;
        rotation.rollback().await.expect("rollback rotation");
        result
    });
    wait_for_lock(&pool, rotation_backend).await;
    tokio::time::timeout(
        Wait::from_secs(2),
        SessionRepository::from_connection(&mut logout)
            .revoke(grant.user, SessionScope::One(grant.session)),
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

/// Replay revokes the family before the grant's JSON is decoded, so invalid stored
/// scopes cannot keep a replayed family alive.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn replay_revokes_family_despite_invalid_scopes() {
    let pool = Database::test_pool().await;
    let client = client(&pool).await;
    let (token, digest) = Grant::new(&pool, &client)
        .await
        .family(&mut TokenRepository::from_pool(&pool), &client)
        .await;
    for statement in [
        "UPDATE refresh_tokens SET consumed_at=now() WHERE id=$1",
        "UPDATE refresh_token_families SET scopes='[1]'
        WHERE id=(SELECT family_id FROM refresh_tokens WHERE id=$1)",
    ] {
        sqlx::query(statement)
            .bind(token.as_uuid())
            .execute(&pool)
            .await
            .expect("consumed token with invalid scopes");
    }
    let mut tx = pool.begin().await.expect("transaction");
    let result = TokenRepository::from_connection(&mut tx)
        .consume_for_rotation(token, std::slice::from_ref(&digest), client.as_str())
        .await;
    assert!(
        matches!(result, Err(RefreshRotationError::Replay { .. })),
        "{result:?}"
    );
    tx.commit().await.expect("commit");
    let revoked: bool = sqlx::query_scalar(
        "SELECT f.revoked_at IS NOT NULL
        FROM refresh_token_families f
        JOIN refresh_tokens t ON t.family_id = f.id
        WHERE t.id = $1",
    )
    .bind(token.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("family");
    assert!(revoked);
}

/// A replay racing the first redemption waits for it, then revokes the family
/// that redemption committed. While the code still looks redeemable the replay's
/// consuming update waits; once the client drops the code's redirect URI that
/// update skips the row without waiting, so the replay lookup must wait instead.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn code_replay_waits_for_first_redemption_and_revokes_its_family() {
    let pool = Database::test_pool().await;
    for redeemable in [true, false] {
        let client = client(&pool).await;
        let grant = Grant::new(&pool, &client).await;
        let mut first = DatabaseTransaction::new(pool.begin().await.expect("first redemption"));
        first
            .oidc()
            .consume_code(
                grant.code,
                std::slice::from_ref(&grant.code_digest),
                &client,
            )
            .await
            .expect("first redemption");
        let (token, digest) = grant.family(&mut first.tokens(), &client).await;
        if !redeemable {
            sqlx::query("DELETE FROM oidc_redirect_uris WHERE client_id = $1")
                .bind(client.as_str())
                .execute(&pool)
                .await
                .expect("remove redirect URI");
        }
        let mut replay = DatabaseTransaction::new(pool.begin().await.expect("replay"));
        let replay_backend = backend(&mut replay.inner).await;
        let (code, code_digest, replay_client) =
            (grant.code, grant.code_digest.clone(), client.clone());
        let replay_task = tokio::spawn(async move {
            let result = replay
                .oidc()
                .consume_code(code, std::slice::from_ref(&code_digest), &replay_client)
                .await;
            replay.commit().await.expect("commit replay");
            result
        });
        wait_for_lock(&pool, replay_backend).await;
        first.commit().await.expect("commit first redemption");
        let result = replay_task.await.expect("replay task");
        assert!(
            matches!(result, Err(CodeRedemptionError::Replay { user_id, .. }) if user_id == grant.user),
            "redeemable {redeemable}: {result:?}"
        );
        let mut rotation = pool.begin().await.expect("rotation transaction");
        let result = TokenRepository::from_connection(&mut rotation)
            .consume_for_rotation(token, std::slice::from_ref(&digest), client.as_str())
            .await;
        assert!(
            matches!(result, Err(RefreshRotationError::Invalid)),
            "redeemable {redeemable}: {result:?}"
        );
    }
}

/// A redeemed code presented by another client is invalid and revokes nothing.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn code_replay_by_another_client_revokes_nothing() {
    let pool = Database::test_pool().await;
    let client = client(&pool).await;
    let grant = Grant::new(&pool, &client).await;
    let mut oidc = OidcRepository::from_pool(&pool);
    oidc.consume_code(
        grant.code,
        std::slice::from_ref(&grant.code_digest),
        &client,
    )
    .await
    .expect("first redemption");
    let (token, digest) = grant
        .family(&mut TokenRepository::from_pool(&pool), &client)
        .await;
    let result = oidc
        .consume_code(
            grant.code,
            std::slice::from_ref(&grant.code_digest),
            &"another-client".parse().expect("client ID"),
        )
        .await;
    assert!(
        matches!(result, Err(CodeRedemptionError::Invalid)),
        "{result:?}"
    );
    let mut rotation = pool.begin().await.expect("rotation transaction");
    TokenRepository::from_connection(&mut rotation)
        .consume_for_rotation(token, std::slice::from_ref(&digest), client.as_str())
        .await
        .expect("the family still rotates");
}

/// Revoking a session ends the refresh families issued from it, and never touches
/// another account's session, whatever the scope names, or an expired one.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn session_revocation_ends_its_families_and_only_its_owners() {
    let pool = Database::test_pool().await;
    let client = client(&pool).await;
    let mut tokens = TokenRepository::from_pool(&pool);
    let mine = Grant::new(&pool, &client).await;
    let theirs = Grant::new(&pool, &client).await;
    let expired = SessionId::new();
    sqlx::query(
        "INSERT INTO sessions (
            id, user_id, authentication_methods, authenticated_at, expires_at, last_seen_at
        ) VALUES ($1, $2, '[]', now() - interval '2 hours', now() - interval '1 hour',
            now() - interval '2 hours')",
    )
    .bind(expired.as_uuid())
    .bind(mine.user.as_uuid())
    .execute(&pool)
    .await
    .expect("expired session");
    mine.family(&mut tokens, &client).await;
    theirs.family(&mut tokens, &client).await;
    let family_revoked = |grant: &Grant| {
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at IS NOT NULL FROM refresh_token_families WHERE session_id = $1",
        )
        .bind(grant.session.as_uuid())
        .fetch_one(&pool)
    };
    let mut sessions = SessionRepository::from_pool(&pool);

    for scope in [SessionScope::One(theirs.session), SessionScope::All] {
        let revoked = sessions.revoke(mine.user, scope).await.expect("revoke");
        assert!(!revoked.contains(&theirs.session), "{scope:?}");
        assert!(!revoked.contains(&expired), "{scope:?}");
    }
    assert!(
        sessions
            .find_active_by_id(theirs.session)
            .await
            .expect("lookup")
            .is_some(),
        "another account's session stays active"
    );
    assert!(!family_revoked(&theirs).await.expect("their family"));
    assert!(family_revoked(&mine).await.expect("my family"));
    assert!(
        sessions
            .revoke(mine.user, SessionScope::One(mine.session))
            .await
            .expect("revoke again")
            .is_empty(),
        "a revoked session is not revoked twice"
    );
}

/// A logout that waits for a code exchange holding the session's lock still
/// revokes the family that exchange committed.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn logout_revokes_a_family_committed_while_it_waited() {
    let pool = Database::test_pool().await;
    let client = client(&pool).await;
    let grant = Grant::new(&pool, &client).await;
    let mut exchange = pool.begin().await.expect("exchange transaction");
    SessionRepository::from_connection(&mut exchange)
        .find_active_by_id_for_update(grant.session)
        .await
        .expect("lock")
        .expect("active session");
    grant
        .family(
            &mut TokenRepository::from_connection(&mut exchange),
            &client,
        )
        .await;
    let mut logout = pool.begin().await.expect("logout transaction");
    let logout_backend = backend(&mut logout).await;
    let (user, session) = (grant.user, grant.session);
    let logout_task = tokio::spawn(async move {
        let revoked = SessionRepository::from_connection(&mut logout)
            .revoke(user, SessionScope::One(session))
            .await
            .expect("logout");
        logout.commit().await.expect("commit logout");
        revoked
    });
    wait_for_lock(&pool, logout_backend).await;
    exchange.commit().await.expect("commit exchange");
    assert_eq!(logout_task.await.expect("logout task"), [session]);
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM refresh_token_families WHERE session_id = $1",
    )
    .bind(session.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("family");
    assert!(revoked, "the family committed during the wait is revoked");
}
