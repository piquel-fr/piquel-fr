//! Static client provisioning, authorization requests, codes and consent.

use super::{JsonArray, OidcRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use serde::Serialize;
use sqlx::types::Json;

/// Largest identifier, scope or audience accepted by provisioning.
const MAX_IDENTIFIER_LENGTH: usize = 64;
/// Maximum number of user-visible display-name characters.
const MAX_NAME_CHARS: usize = 80;
/// Bound on each redirect allowlist.
const MAX_REDIRECTS: usize = 16;
/// Bound on a client's configured scopes.
const MAX_SCOPES: usize = 32;
/// Bound on a client's configured audiences.
const MAX_AUDIENCES: usize = 16;
/// Length of a persisted SHA-256 client-secret digest.
const CLIENT_SECRET_DIGEST_LENGTH: usize = 32;

piquel_common::str_enum! {
    /// Purpose of a registered OIDC continuation.
    pub enum OidcRedirectKind {
        /// Receives the authorization code.
        Authorization = "authorization",
        /// Receives the browser after RP-initiated logout.
        PostLogout = "post_logout",
    }
}

/// Actionable failures of a statically configured client's provisioning contract.
#[derive(Debug, thiserror::Error)]
pub enum ClientConfigurationError {
    /// The client ID violates the shared identifier syntax.
    #[error("client ID must match [A-Za-z0-9._-]{{1,64}}")]
    Identifier,
    /// Consent-screen names must be present and bounded.
    #[error("client display name must be nonblank and contain at most 80 characters")]
    DisplayName,
    /// Persisted secrets must already be hashed.
    #[error("client secret hash must contain exactly 32 bytes")]
    SecretDigest,
    /// An allowlist is missing or too large.
    #[error("{kind} redirects must contain {minimum} to 16 URIs")]
    RedirectCount {
        /// Which allowlist needs correction.
        kind: OidcRedirectKind,
        /// Authorization requires one URI; post-logout permits none.
        minimum: usize,
    },
    /// A redirect could not be parsed as an absolute URL.
    #[error("{kind} redirect must be an absolute HTTPS URL")]
    RedirectUrl {
        /// Which allowlist contains the malformed URL.
        kind: OidcRedirectKind,
        /// URL parser failure, without logging the supplied URI.
        #[source]
        source: url::ParseError,
    },
    /// A redirect violates the transport and authority policy.
    #[error("{kind} redirect must use HTTPS with a host and no credentials or fragment")]
    RedirectPolicy {
        /// Which allowlist violates the redirect policy.
        kind: OidcRedirectKind,
    },
    /// Scope identifiers are missing, too numerous or malformed.
    #[error("client scopes must contain 1 to 32 values matching [A-Za-z0-9._-]{{1,64}}")]
    Scopes,
    /// Audience identifiers are missing, too numerous or malformed.
    #[error("client audiences must contain 1 to 16 values matching [A-Za-z0-9._-]{{1,64}}")]
    Audiences,
}

/// A registered OIDC client with its exact URI allowlists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredOidcClient {
    /// Client identifier.
    pub id: String,
    /// Name shown on consent screens.
    pub display_name: String,
    /// Exact allowed authorization redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Exact allowed post-logout redirect URIs.
    pub post_logout_uris: Vec<String>,
    /// Scopes the client may request.
    pub allowed_scopes: Vec<String>,
    /// Audiences the client may request tokens for.
    pub allowed_audiences: Vec<String>,
    /// Whether the client may receive refresh tokens.
    pub allow_refresh: bool,
    /// Disabled clients are rejected everywhere.
    pub enabled: bool,
    /// Whether the client skips the consent screen.
    pub trusted: bool,
    /// SHA-256 hash of the client secret; `None` for public clients.
    pub client_secret_hash: Option<Vec<u8>>,
}

/// The scopes an account consented to for one client and audience.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoredConsent {
    /// Client the consent was given to.
    pub client_id: String,
    /// Audience of the tokens the client receives.
    pub audience: String,
    /// Consented scopes.
    pub scopes: Vec<String>,
}

/// Statically reviewed client configuration provisioned at startup.
///
/// [`OidcRepository::bootstrap_client`] rejects identifiers, scopes and
/// audiences outside `[A-Za-z0-9._-]{1,64}`, display names longer than 80
/// characters, and redirect URIs that are not HTTPS or
/// carry credentials or a fragment.
#[derive(Clone, Debug)]
pub struct BootstrapOidcClient {
    /// Client identifier.
    pub id: String,
    /// Name shown on consent screens; must not be blank.
    pub display_name: String,
    /// 1 to 16 exact authorization redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Up to 16 exact post-logout redirect URIs.
    pub post_logout_uris: Vec<String>,
    /// 1 to 32 scopes the client may request.
    pub allowed_scopes: Vec<String>,
    /// 1 to 16 audiences the client may request tokens for.
    pub allowed_audiences: Vec<String>,
    /// Whether the client may receive refresh tokens.
    pub allow_refresh: bool,
    /// Whether the client is usable.
    pub enabled: bool,
    /// Whether the client skips the consent screen.
    pub trusted: bool,
    /// 32-byte SHA-256 hash of the client secret; `None` for public clients.
    pub client_secret_hash: Option<Vec<u8>>,
}

impl BootstrapOidcClient {
    /// Validates a startup client against the database's provisioning contract.
    ///
    /// # Errors
    /// Identifies the invalid field or redirect allowlist and preserves URL parser failures.
    pub fn validate(&self) -> Result<(), ClientConfigurationError> {
        if self
            .client_secret_hash
            .as_ref()
            .is_some_and(|hash| hash.len() != CLIENT_SECRET_DIGEST_LENGTH)
        {
            return Err(ClientConfigurationError::SecretDigest);
        }
        if !Self::valid_identifier(&self.id) {
            return Err(ClientConfigurationError::Identifier);
        }
        if self.display_name.trim().is_empty() || self.display_name.chars().count() > MAX_NAME_CHARS
        {
            return Err(ClientConfigurationError::DisplayName);
        }
        Self::validate_redirects(OidcRedirectKind::Authorization, &self.redirect_uris)?;
        Self::validate_redirects(OidcRedirectKind::PostLogout, &self.post_logout_uris)?;
        if !Self::valid_identifiers(&self.allowed_scopes, MAX_SCOPES) {
            return Err(ClientConfigurationError::Scopes);
        }
        if !Self::valid_identifiers(&self.allowed_audiences, MAX_AUDIENCES) {
            return Err(ClientConfigurationError::Audiences);
        }
        Ok(())
    }

    /// Checks a nonempty list of at most `max` valid identifiers.
    fn valid_identifiers(values: &[String], max: usize) -> bool {
        (1..=max).contains(&values.len())
            && values.iter().all(|value| Self::valid_identifier(value))
    }

    /// The same bounded ASCII syntax applies to IDs, scopes and audiences.
    fn valid_identifier(value: &str) -> bool {
        (1..=MAX_IDENTIFIER_LENGTH).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }

    /// Validates each exact continuation while allowing query parameters used by RPs.
    fn validate_redirects(
        kind: OidcRedirectKind,
        uris: &[String],
    ) -> Result<(), ClientConfigurationError> {
        let minimum = match kind {
            OidcRedirectKind::Authorization => 1,
            OidcRedirectKind::PostLogout => 0,
        };
        if !(minimum..=MAX_REDIRECTS).contains(&uris.len()) {
            return Err(ClientConfigurationError::RedirectCount { kind, minimum });
        }
        for uri in uris {
            let url = url::Url::parse(uri)
                .map_err(|source| ClientConfigurationError::RedirectUrl { kind, source })?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(ClientConfigurationError::RedirectPolicy { kind });
            }
        }
        Ok(())
    }
}

/// A validated authorization request, stored while the user logs in and
/// consents.
#[derive(Clone, Debug)]
pub struct InsertAuthorizationRequest {
    /// Request identifier.
    pub id: TokenId,
    /// Digest of the browser-held request secret.
    pub secret_digest: Vec<u8>,
    /// Requesting client.
    pub client_id: String,
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
    /// `max_age` in seconds since the last authentication.
    pub max_age: Option<i64>,
    /// Account the client asked for, kept across login and consent.
    pub hinted_user_id: Option<UserId>,
    /// When the request stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// A pending authorization request of an enabled client.
#[derive(Clone, Debug)]
pub struct StoredAuthorizationRequest {
    /// Request identifier.
    pub id: TokenId,
    /// Requesting client.
    pub client_id: String,
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
    /// `max_age` in seconds since the last authentication.
    pub max_age: Option<i64>,
    /// Account the client asked for.
    pub hinted_user_id: Option<UserId>,
    /// When the request was stored.
    pub created_at: DateTime<Utc>,
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
    pub client_id: String,
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
    pub client_id: String,
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
    },
}

impl OidcRepository<'_> {
    /// Disables every client. Startup provisioning calls it in the same
    /// transaction as [`Self::bootstrap_client`], so removed clients fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn disable_all_clients(&mut self) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!("UPDATE oidc_clients SET enabled=FALSE")
        )?;
        Ok(())
    }

    /// Idempotently provisions a client and replaces its URI allowlists.
    ///
    /// # Errors
    ///
    /// Preserves [`ClientConfigurationError`] as an operation source when configuration is
    /// invalid, or retains the driver failure if provisioning fails.
    pub async fn bootstrap_client(
        &mut self,
        input: &BootstrapOidcClient,
    ) -> Result<(), DatabaseError> {
        input
            .validate()
            .map_err(|source| DatabaseError::Operation(Box::new(source)))?;
        // The statement returns the upserted id; every CTE runs regardless.
        run!(
            self,
            fetch_one,
            sqlx::query!(
                "WITH upsert AS (
                    INSERT INTO oidc_clients (
                        id, display_name, allowed_scopes, allowed_audiences, allow_refresh,
                        enabled, trusted, client_secret_hash
                    ) VALUES ($1, $2, $3, $4, $5, $8, $9, $10)
                    ON CONFLICT (id) DO UPDATE
                    SET display_name = EXCLUDED.display_name,
                        allowed_scopes = EXCLUDED.allowed_scopes,
                        allowed_audiences = EXCLUDED.allowed_audiences,
                        allow_refresh = EXCLUDED.allow_refresh,
                        enabled = EXCLUDED.enabled,
                        trusted = EXCLUDED.trusted,
                        client_secret_hash = EXCLUDED.client_secret_hash
                    RETURNING id
                ),
                desired (uri, kind) AS (
                    SELECT unnest($6::text[]), 'authorization'
                    UNION ALL
                    SELECT unnest($7::text[]), 'post_logout'
                ),
                inserted AS (
                    INSERT INTO oidc_redirect_uris (client_id, uri, kind)
                    SELECT $1, d.uri, d.kind
                    FROM desired d, upsert
                    ON CONFLICT DO NOTHING
                    RETURNING uri
                ),
                removed AS (
                    DELETE FROM oidc_redirect_uris r
                    WHERE r.client_id = $1
                    AND NOT EXISTS (
                        SELECT 1
                        FROM desired d
                        WHERE d.uri = r.uri
                        AND d.kind = r.kind
                    )
                    RETURNING uri
                )
                SELECT id
                FROM upsert",
                input.id,
                input.display_name,
                Json(&input.allowed_scopes) as _,
                Json(&input.allowed_audiences) as _,
                input.allow_refresh,
                &input.redirect_uris,
                &input.post_logout_uris,
                input.enabled,
                input.trusted,
                input.client_secret_hash,
            )
        )?;
        Ok(())
    }

    /// Finds a client, enabled or not, with its URI allowlists.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_client(
        &mut self,
        id: &str,
    ) -> Result<Option<StoredOidcClient>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredOidcClient,
                r#"SELECT
                    c.id, c.display_name, c.enabled,
                    c.allowed_scopes AS "allowed_scopes: JsonArray<String>",
                    c.allowed_audiences AS "allowed_audiences: JsonArray<String>",
                    c.allow_refresh, c.trusted, c.client_secret_hash,
                    COALESCE(
                        jsonb_agg(r.uri) FILTER (WHERE r.kind = 'authorization'),
                        '[]'::jsonb
                    ) AS "redirect_uris!: JsonArray<String>",
                    COALESCE(
                        jsonb_agg(r.uri) FILTER (WHERE r.kind = 'post_logout'),
                        '[]'::jsonb
                    ) AS "post_logout_uris!: JsonArray<String>"
                FROM oidc_clients c
                LEFT JOIN oidc_redirect_uris r ON r.client_id = c.id
                WHERE c.id = $1
                GROUP BY c.id"#,
                id,
            )
        )
    }

    /// Lists every client, enabled or not, with its URI allowlists, by ID.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_clients(&mut self) -> Result<Vec<StoredOidcClient>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredOidcClient,
                r#"SELECT
                    c.id, c.display_name, c.enabled,
                    c.allowed_scopes AS "allowed_scopes: JsonArray<String>",
                    c.allowed_audiences AS "allowed_audiences: JsonArray<String>",
                    c.allow_refresh, c.trusted, c.client_secret_hash,
                    COALESCE(
                        jsonb_agg(r.uri) FILTER (WHERE r.kind = 'authorization'),
                        '[]'::jsonb
                    ) AS "redirect_uris!: JsonArray<String>",
                    COALESCE(
                        jsonb_agg(r.uri) FILTER (WHERE r.kind = 'post_logout'),
                        '[]'::jsonb
                    ) AS "post_logout_uris!: JsonArray<String>"
                FROM oidc_clients c
                LEFT JOIN oidc_redirect_uris r ON r.client_id = c.id
                GROUP BY c.id
                ORDER BY c.id"#
            )
        )
    }

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
                    max_age, expires_at, force_consent, hinted_user_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                input.id.as_uuid(),
                input.secret_digest,
                input.client_id,
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
            )
        )?;
        Ok(())
    }

    /// Finds an unconsumed, unexpired request of an enabled client by its id
    /// and secret digest.
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
                    r.id AS "id: TokenId", r.client_id, c.display_name AS client_display_name,
                    r.redirect_uri, r.client_state, r.nonce, r.pkce_challenge,
                    r.scopes AS "scopes: JsonArray<String>", r.audience, r.force_login,
                    r.force_consent, r.max_age, r.hinted_user_id AS "hinted_user_id: UserId",
                    r.created_at
                FROM authorization_requests r
                JOIN oidc_clients c ON c.id = r.client_id
                WHERE r.id = $1
                AND r.secret_digest = $2
                AND r.consumed_at IS NULL
                AND r.expires_at > now()
                AND c.enabled"#,
                id.as_uuid(),
                digest,
            )
        )
    }

    /// Consumes a request that the client's current policy still allows:
    /// its scopes, audience and redirect URI must remain registered.
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
                    r.id AS "id: TokenId", r.client_id, c.display_name AS client_display_name,
                    r.redirect_uri, r.client_state, r.nonce, r.pkce_challenge,
                    r.scopes AS "scopes: JsonArray<String>", r.audience, r.force_login,
                    r.force_consent, r.max_age, r.hinted_user_id AS "hinted_user_id: UserId",
                    r.created_at"#,
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
                    pkce_challenge, nonce, scopes, audience, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                input.id.as_uuid(),
                input.secret_digest,
                input.client_id,
                input.user_id.as_uuid(),
                input.session_id.as_uuid(),
                input.redirect_uri,
                input.pkce_challenge,
                input.nonce,
                Json(&input.scopes) as _,
                input.audience,
                input.expires_at,
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
        client_id: &str,
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
                    c.id AS "id: TokenId", c.client_id, c.user_id AS "user_id: UserId",
                    c.session_id AS "session_id: SessionId", c.redirect_uri, c.pkce_challenge,
                    c.nonce, c.scopes AS "scopes: JsonArray<String>", c.audience"#,
                id.as_uuid(),
                digest,
            )
        )?;
        match code {
            Some(code) => Ok(code),
            None => Err(
                match self.revoke_replayed_code(id, digest, client_id).await? {
                    Some(user_id) => CodeRedemptionError::Replay { user_id },
                    None => CodeRedemptionError::Invalid,
                },
            ),
        }
    }

    /// Revokes the refresh families issued from an already consumed code and
    /// returns its account, or `None` if `id`, `digest` and `client_id` match no
    /// consumed code. Matching the secret digest and client means neither a guessed
    /// code ID nor a leaked code presented by another client can revoke a grant.
    async fn revoke_replayed_code(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client_id: &str,
    ) -> Result<Option<UserId>, DatabaseError> {
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
                client_id,
            )
        )?
        .filter(|code| code.consumed) else {
            return Ok(None);
        };
        // A separate statement takes a fresh snapshot, which includes a family
        // committed while the lock above waited. Only the family lock is taken, so
        // this stays within the user -> session -> family order of rotation.
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE refresh_token_families
                SET revoked_at = now()
                WHERE authorization_code_id = $1
                AND revoked_at IS NULL",
                id.as_uuid(),
            )
        )?;
        Ok(Some(code.user_id))
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
        client: &str,
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
                client,
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
    pub async fn list_consents(
        &mut self,
        user: UserId,
    ) -> Result<Vec<StoredConsent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredConsent,
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
        client: &str,
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
                client,
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

    /// Revokes a session (OIDC logout) and every refresh token family issued
    /// from it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails.
    pub async fn revoke_session(&mut self, session: SessionId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1",
                session.as_uuid(),
            )
        )?;
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE refresh_token_families
                SET revoked_at = COALESCE(revoked_at, now())
                WHERE session_id = $1",
                session.as_uuid(),
            )
        )?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    //! Pure provisioning validation without a running database.
    use super::*;

    impl BootstrapOidcClient {
        /// A valid public client for exercising individual provisioning constraints.
        fn fixture() -> Self {
            Self {
                id: "test-client".into(),
                display_name: "Test client".into(),
                redirect_uris: vec!["https://client.example/callback?flow=one".into()],
                post_logout_uris: Vec::new(),
                allowed_scopes: vec!["openid".into()],
                allowed_audiences: vec!["test-client".into()],
                allow_refresh: false,
                enabled: true,
                trusted: false,
                client_secret_hash: None,
            }
        }
    }

    /// URI validation preserves URL syntax errors and names the affected allowlist.
    #[test]
    fn redirect_validation_preserves_sources_and_applies_both_policies() {
        let mut client = BootstrapOidcClient::fixture();
        assert!(client.validate().is_ok());
        client.redirect_uris.clear();
        assert!(matches!(
            client.validate(),
            Err(ClientConfigurationError::RedirectCount {
                kind: OidcRedirectKind::Authorization,
                minimum: 1
            })
        ));
        client.redirect_uris.push("/relative".into());
        let error = client.validate().expect_err("absolute URL required");
        assert!(std::error::Error::source(&error).is_some());
        for invalid in [
            "http://client.example",
            "https://user@client.example",
            "https://user:secret@client.example",
            "https://client.example/#fragment",
        ] {
            client.redirect_uris = vec![invalid.into()];
            assert!(matches!(
                client.validate(),
                Err(ClientConfigurationError::RedirectPolicy {
                    kind: OidcRedirectKind::Authorization
                })
            ));
            client.redirect_uris = BootstrapOidcClient::fixture().redirect_uris;
            client.post_logout_uris = vec![invalid.into()];
            assert!(matches!(
                client.validate(),
                Err(ClientConfigurationError::RedirectPolicy {
                    kind: OidcRedirectKind::PostLogout
                })
            ));
            client.post_logout_uris.clear();
        }
    }

    /// Identifiers, labels and digests enforce the provisioning contract at its exact bounds.
    #[test]
    fn provisioning_bounds_identifiers_labels_and_digests() {
        for (value, valid) in [
            ("", false),
            ("has space", false),
            ("a._-Z09", true),
            (&"x".repeat(64), true),
            (&"x".repeat(65), false),
        ] {
            assert_eq!(BootstrapOidcClient::valid_identifier(value), valid);
        }
        let mut client = BootstrapOidcClient::fixture();
        client.display_name = "é".repeat(80);
        client.client_secret_hash = Some(vec![0; 32]);
        assert!(client.validate().is_ok());
        client.display_name.push('é');
        assert!(matches!(
            client.validate(),
            Err(ClientConfigurationError::DisplayName)
        ));
        client.display_name = "Test".into();
        client.client_secret_hash = Some(vec![0; 31]);
        assert!(matches!(
            client.validate(),
            Err(ClientConfigurationError::SecretDigest)
        ));
        client.client_secret_hash = None;
        client.allowed_scopes.clear();
        assert!(matches!(
            client.validate(),
            Err(ClientConfigurationError::Scopes)
        ));
        client.allowed_scopes = vec!["openid".into()];
        client.allowed_audiences.clear();
        assert!(matches!(
            client.validate(),
            Err(ClientConfigurationError::Audiences)
        ));
    }
}
