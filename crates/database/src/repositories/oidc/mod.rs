//! Client registrations, authorization requests, codes and consent.

use super::{JsonArray, OidcRepository, RepositoryExecutor};
use crate::{DatabaseError, SessionAuthentication};
use chrono::{DateTime, Utc};
use piquel_admin_api::Consent;
use piquel_common::{ClientId, SessionId, TokenId, UserId, protocol::claims::Acr};
use sqlx::types::Json;

piquel_common::str_enum! {
    /// Purpose of a registered OIDC continuation.
    pub enum OidcRedirectKind {
        /// Receives the authorization code.
        Authorization = "authorization",
        /// Receives the browser after RP-initiated logout.
        PostLogout = "post_logout",
    }
}

/// A validated authorization request, stored while the user logs in and
/// consents. A pushed one waits for the browser to claim it first.
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "The flags are the row's independent boolean columns."
)]
pub struct InsertAuthorizationRequest {
    /// Request identifier.
    pub id: TokenId,
    /// Digest of the request secret: the browser's, or the `request_uri`'s for a
    /// pushed request.
    pub secret_digest: Vec<u8>,
    /// Whether the client pushed the request (RFC 9126), so the browser must claim
    /// it with [`OidcRepository::claim_pushed_authorization_request`].
    pub pushed: bool,
    /// Requesting client.
    pub client_id: ClientId,
    /// Registered redirect URI to answer on.
    pub redirect_uri: String,
    /// The client's opaque `state` parameter.
    pub client_state: String,
    /// The client's `nonce` parameter, echoed in the ID token.
    pub nonce: Option<String>,
    /// PKCE `S256` code challenge.
    pub pkce_challenge: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Requested token audience.
    pub audience: String,
    /// `prompt=login` or `select_account`: the user must authenticate again.
    pub force_login: bool,
    /// `prompt=consent`: the user must consent again.
    pub force_consent: bool,
    /// `prompt=none`: fail rather than show the user a page.
    pub prompt_none: bool,
    /// `max_age` in seconds since the last authentication.
    pub max_age: Option<i64>,
    /// Account the client asked for, kept across login and consent.
    pub hinted_user_id: Option<UserId>,
    /// Class the session must reach, chosen from `acr_values`.
    pub target_acr: Option<Acr>,
    /// When the request stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// A pending authorization request of an enabled client.
#[derive(Clone, Debug)]
pub struct StoredAuthorizationRequest {
    /// Request identifier.
    pub id: TokenId,
    /// Requesting client.
    pub client_id: ClientId,
    /// The client's current consent-screen name.
    pub client_display_name: String,
    /// Registered redirect URI to answer on.
    pub redirect_uri: String,
    /// The client's opaque `state` parameter.
    pub client_state: String,
    /// The client's `nonce` parameter.
    pub nonce: Option<String>,
    /// PKCE `S256` code challenge.
    pub pkce_challenge: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Requested token audience.
    pub audience: String,
    /// `prompt=login` or `select_account`: the user must authenticate again.
    pub force_login: bool,
    /// `prompt=consent`: the user must consent again.
    pub force_consent: bool,
    /// `prompt=none`: fail rather than show the user a page.
    pub prompt_none: bool,
    /// `max_age` in seconds since the last authentication.
    pub max_age: Option<i64>,
    /// Account the client asked for.
    pub hinted_user_id: Option<UserId>,
    /// Class the session must reach, chosen from `acr_values`.
    pub target_acr: Option<Acr>,
    /// When the browser arrived with the request: when it was stored, or claimed
    /// if pushed. Only a sign-in since then is fresh.
    pub started_at: DateTime<Utc>,
}

/// A single-use authorization code, bound to its client, redirect URI, PKCE
/// challenge and session.
#[derive(Clone, Debug)]
pub struct InsertAuthorizationCode {
    /// Code identifier.
    pub id: TokenId,
    /// Digest of the code secret.
    pub secret_digest: Vec<u8>,
    /// Client the code was issued to.
    pub client_id: ClientId,
    /// Authorizing account.
    pub user_id: UserId,
    /// Session that authorized the code.
    pub session_id: SessionId,
    /// Redirect URI the code was delivered to.
    pub redirect_uri: String,
    /// PKCE `S256` code challenge.
    pub pkce_challenge: String,
    /// The client's `nonce` parameter.
    pub nonce: Option<String>,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Granted token audience.
    pub audience: String,
    /// How the session had authenticated when the code was issued.
    pub authentication: SessionAuthentication,
    /// When the code stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// A code taken by [`OidcRepository::consume_code`]. The caller still checks
/// the client, redirect URI and PKCE verifier against it.
#[derive(Clone, Debug)]
pub struct ConsumedAuthorizationCode {
    /// Code identifier, recorded on the refresh family the exchange creates.
    pub id: TokenId,
    /// Client the code was issued to.
    pub client_id: ClientId,
    /// Authorizing account.
    pub user_id: UserId,
    /// Session that authorized the code.
    pub session_id: SessionId,
    /// Redirect URI the code was delivered to.
    pub redirect_uri: String,
    /// PKCE `S256` code challenge.
    pub pkce_challenge: String,
    /// The client's `nonce` parameter.
    pub nonce: Option<String>,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Granted token audience.
    pub audience: String,
    /// How the session had authenticated when the code was issued.
    pub authentication: SessionAuthentication,
}

/// Why [`OidcRepository::consume_code`] could not redeem a code.
#[derive(Debug, thiserror::Error)]
pub enum CodeRedemptionError {
    /// The database failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// The code is unknown or expired, or its client, session or account no
    /// longer allows it.
    #[error("the authorization code is invalid")]
    Invalid,
    /// The code was already redeemed; any refresh families issued from it are
    /// now revoked.
    #[error("the authorization code was replayed")]
    Replay {
        /// Account whose grant was revoked.
        user_id: UserId,
        /// The refresh families this replay revoked; empty if the code produced
        /// none, or they were already revoked.
        revoked_families: Vec<TokenId>,
    },
}

impl OidcRepository<'_> {
    /// Stores an authorization request.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown client.
    pub async fn insert_authorization_request(
        &mut self,
        input: &InsertAuthorizationRequest,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO authorization_requests (
                    id, secret_digest, client_id, redirect_uri, client_state,
                    nonce, pkce_challenge, scopes, audience, force_login,
                    max_age, expires_at, force_consent, hinted_user_id, target_acr,
                    pushed, prompt_none
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
                )",
                input.id.as_uuid(),
                input.secret_digest,
                input.client_id.as_str(),
                input.redirect_uri,
                input.client_state,
                input.nonce,
                input.pkce_challenge,
                Json(&input.scopes) as _,
                input.audience,
                input.force_login,
                input.max_age,
                input.expires_at,
                input.force_consent,
                input.hinted_user_id.map(UserId::as_uuid),
                input.target_acr.map(Acr::as_str),
                input.pushed,
                input.prompt_none,
            )
        )?;
        Ok(())
    }

    /// Claims a pushed request for the browser, once: it must be `client`'s, and
    /// neither claimed nor expired. Its secret becomes `new_digest`, so the
    /// `request_uri` stops working, and it now expires at `expires_at`. Returns
    /// `None` if no such request exists.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn claim_pushed_authorization_request(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client: &str,
        new_digest: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<Option<StoredAuthorizationRequest>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredAuthorizationRequest,
                r#"UPDATE authorization_requests r
                SET claimed_at = now(), secret_digest = $4, expires_at = $5
                FROM oidc_clients c
                WHERE r.id = $1
                AND r.secret_digest = $2
                AND r.client_id = $3
                AND r.pushed
                AND r.claimed_at IS NULL
                AND r.consumed_at IS NULL
                AND r.expires_at > now()
                AND c.id = r.client_id
                AND c.enabled
                RETURNING
                    r.id AS "id: TokenId", r.client_id AS "client_id: ClientId",
                    c.display_name AS client_display_name,
                    r.redirect_uri, r.client_state, r.nonce, r.pkce_challenge,
                    r.scopes AS "scopes: JsonArray<String>", r.audience, r.force_login,
                    r.force_consent, r.prompt_none, r.max_age,
                    r.hinted_user_id AS "hinted_user_id: UserId",
                    r.target_acr AS "target_acr: Acr",
                    r.claimed_at AS "started_at!""#,
                id.as_uuid(),
                digest,
                client,
                new_digest,
                expires_at,
            )
        )
    }

    /// Finds an unconsumed, unexpired request of an enabled client by its id
    /// and secret digest. A pushed request must be claimed first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_authorization_request(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<Option<StoredAuthorizationRequest>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredAuthorizationRequest,
                r#"SELECT
                    r.id AS "id: TokenId", r.client_id AS "client_id: ClientId",
                    c.display_name AS client_display_name,
                    r.redirect_uri, r.client_state, r.nonce, r.pkce_challenge,
                    r.scopes AS "scopes: JsonArray<String>", r.audience, r.force_login,
                    r.force_consent, r.prompt_none, r.max_age,
                    r.hinted_user_id AS "hinted_user_id: UserId",
                    r.target_acr AS "target_acr: Acr",
                    COALESCE(r.claimed_at, r.created_at) AS "started_at!"
                FROM authorization_requests r
                JOIN oidc_clients c ON c.id = r.client_id
                WHERE r.id = $1
                AND r.secret_digest = $2
                AND r.consumed_at IS NULL
                AND r.expires_at > now()
                AND (NOT r.pushed OR r.claimed_at IS NOT NULL)
                AND c.enabled"#,
                id.as_uuid(),
                digest,
            )
        )
    }

    /// Consumes a request that the client's current policy still allows:
    /// its scopes, audience and redirect URI must remain registered. A pushed
    /// request must be claimed first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if no such request exists, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn consume_authorization_request(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<StoredAuthorizationRequest, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredAuthorizationRequest,
                r#"UPDATE authorization_requests r
                SET consumed_at = now()
                FROM oidc_clients c
                WHERE r.id = $1
                AND r.secret_digest = $2
                AND r.consumed_at IS NULL
                AND r.expires_at > now()
                AND (NOT r.pushed OR r.claimed_at IS NOT NULL)
                AND c.id = r.client_id
                AND c.enabled
                AND c.allowed_scopes @> r.scopes
                AND c.allowed_audiences ? r.audience
                AND EXISTS (
                    SELECT 1
                    FROM oidc_redirect_uris d
                    WHERE d.client_id = c.id
                    AND d.kind = 'authorization'
                    AND d.uri = r.redirect_uri
                )
                RETURNING
                    r.id AS "id: TokenId", r.client_id AS "client_id: ClientId",
                    c.display_name AS client_display_name,
                    r.redirect_uri, r.client_state, r.nonce, r.pkce_challenge,
                    r.scopes AS "scopes: JsonArray<String>", r.audience, r.force_login,
                    r.force_consent, r.prompt_none, r.max_age,
                    r.hinted_user_id AS "hinted_user_id: UserId",
                    r.target_acr AS "target_acr: Acr",
                    COALESCE(r.claimed_at, r.created_at) AS "started_at!""#,
                id.as_uuid(),
                digest,
            )
        )
    }

    /// Stores an issued authorization code.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails.
    pub async fn insert_code(
        &mut self,
        input: &InsertAuthorizationCode,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO authorization_codes (
                    id, secret_digest, client_id, user_id, session_id, redirect_uri,
                    pkce_challenge, nonce, scopes, audience, expires_at, authentication
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                input.id.as_uuid(),
                input.secret_digest,
                input.client_id.as_str(),
                input.user_id.as_uuid(),
                input.session_id.as_uuid(),
                input.redirect_uri,
                input.pkce_challenge,
                input.nonce,
                Json(&input.scopes) as _,
                input.audience,
                input.expires_at,
                Json(&input.authentication) as _,
            )
        )?;
        Ok(())
    }

    /// Consumes an unexpired code once. The client's current policy must still
    /// allow it, and its session and account must still be active.
    ///
    /// Redeeming an already consumed code with its secret, as the authenticated
    /// `client_id` it was issued to, is a replay (RFC 6749 section 4.1.2): the
    /// refresh families issued from the code are revoked in this transaction, which
    /// the caller commits even though the exchange fails. The caller still checks
    /// the returned code's client, so `client_id` only scopes replay detection.
    ///
    /// # Errors
    ///
    /// Returns [`CodeRedemptionError::Replay`] after revoking the code's refresh
    /// families, [`CodeRedemptionError::Invalid`] if the code is otherwise not
    /// usable, or [`CodeRedemptionError::Database`] if a query fails.
    pub async fn consume_code(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client_id: &ClientId,
    ) -> Result<ConsumedAuthorizationCode, CodeRedemptionError> {
        // If the code still looks redeemable, this update waits on a concurrent
        // first redemption's row lock, then re-reads the row and skips it if that
        // exchange committed. Otherwise it skips the row without waiting, and the
        // replay lookup below waits instead.
        let code = run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                ConsumedAuthorizationCode,
                r#"UPDATE authorization_codes c
                SET consumed_at = now()
                FROM oidc_clients cl, sessions s, users u
                WHERE c.id = $1
                AND c.secret_digest = $2
                AND c.consumed_at IS NULL
                AND c.expires_at > now()
                AND cl.id = c.client_id
                AND cl.enabled
                AND cl.allowed_scopes @> c.scopes
                AND cl.allowed_audiences ? c.audience
                AND EXISTS (
                    SELECT 1
                    FROM oidc_redirect_uris d
                    WHERE d.client_id = cl.id
                    AND d.kind = 'authorization'
                    AND d.uri = c.redirect_uri
                )
                AND s.id = c.session_id
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.id = c.user_id
                AND u.status = 'active'
                RETURNING
                    c.id AS "id: TokenId", c.client_id AS "client_id: ClientId",
                    c.user_id AS "user_id: UserId",
                    c.session_id AS "session_id: SessionId", c.redirect_uri, c.pkce_challenge,
                    c.nonce, c.scopes AS "scopes: JsonArray<String>", c.audience,
                    c.authentication AS "authentication: SessionAuthentication""#,
                id.as_uuid(),
                digest,
            )
        )?;
        match code {
            Some(code) => Ok(code),
            None => Err(
                match self.revoke_replayed_code(id, digest, client_id).await? {
                    Some((user_id, revoked_families)) => CodeRedemptionError::Replay {
                        user_id,
                        revoked_families,
                    },
                    None => CodeRedemptionError::Invalid,
                },
            ),
        }
    }

    /// Revokes the refresh families issued from an already consumed code and
    /// returns its account and the families it revoked, or `None` if `id`,
    /// `digest` and `client_id` match no
    /// consumed code. Matching the secret digest and client means neither a guessed
    /// code ID nor a leaked code presented by another client can revoke a grant.
    async fn revoke_replayed_code(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client_id: &ClientId,
    ) -> Result<Option<(UserId, Vec<TokenId>)>, DatabaseError> {
        // The row qualifies whether or not it is consumed, so FOR SHARE waits for
        // an in-flight first redemption and then reads the committed row, together
        // with its family. Filtering on `consumed_at` would test this statement's
        // snapshot, where an uncommitted redemption is invisible, and skip the wait.
        // The lock also stops cleanup from purging the code, and unlinking the
        // family, before this transaction commits.
        let Some(code) = run!(
            self,
            fetch_optional,
            sqlx::query!(
                r#"SELECT user_id AS "user_id: UserId", consumed_at IS NOT NULL AS "consumed!"
                FROM authorization_codes
                WHERE id = $1
                AND secret_digest = $2
                AND client_id = $3
                FOR SHARE"#,
                id.as_uuid(),
                digest,
                client_id.as_str(),
            )
        )?
        .filter(|code| code.consumed) else {
            return Ok(None);
        };
        // A separate statement takes a fresh snapshot, which includes a family
        // committed while the lock above waited. Only the family lock is taken, so
        // this stays within the user -> session -> family order of rotation.
        let revoked = run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                r#"UPDATE refresh_token_families
                SET revoked_at = now()
                WHERE authorization_code_id = $1
                AND revoked_at IS NULL
                RETURNING id AS "id: TokenId""#,
                id.as_uuid(),
            )
        )?;
        Ok(Some((code.user_id, revoked)))
    }

    /// Reports whether the user already consented to all of `scopes` for this
    /// client and audience.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn consented(
        &mut self,
        user: UserId,
        client: &ClientId,
        audience: &str,
        scopes: &[String],
    ) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT EXISTS (
                    SELECT
                    FROM oidc_consents
                    WHERE user_id = $1
                    AND client_id = $2
                    AND audience = $3
                    AND scopes @> $4
                ) AS "consented!""#,
                user.as_uuid(),
                client.as_str(),
                audience,
                Json(scopes) as _,
            )
        )
    }

    /// Lists the user's remembered consents, by client and audience.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_consents(&mut self, user: UserId) -> Result<Vec<Consent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                Consent,
                r#"SELECT client_id, audience, scopes AS "scopes: JsonArray<String>"
                FROM oidc_consents
                WHERE user_id = $1
                ORDER BY client_id, audience"#,
                user.as_uuid(),
            )
        )
    }

    /// Adds `scopes` to the user's consent for this client and audience.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn save_consent(
        &mut self,
        user: UserId,
        client: &ClientId,
        audience: &str,
        scopes: &[String],
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO oidc_consents (user_id, client_id, audience, scopes)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, client_id, audience) DO UPDATE
                SET scopes = (
                    SELECT jsonb_agg(DISTINCT value)
                    FROM jsonb_array_elements(oidc_consents.scopes || EXCLUDED.scopes)
                )",
                user.as_uuid(),
                client.as_str(),
                audience,
                Json(scopes) as _,
            )
        )?;
        Ok(())
    }

    /// Returns the user's verified email for the `email` claim, preferring the
    /// primary address.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn primary_email(&mut self, user: UserId) -> Result<Option<String>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT normalized_email
                FROM user_emails
                WHERE user_id = $1
                AND verified_at IS NOT NULL
                ORDER BY is_primary DESC, created_at
                LIMIT 1",
                user.as_uuid(),
            )
        )
    }
}
/// Client registrations, secrets and the origins of public clients.
mod clients;
pub use clients::{StoredClientSecret, StoredOidcClient};
/// Database-backed client registration and migration scenarios.
#[cfg(test)]
mod tests;
