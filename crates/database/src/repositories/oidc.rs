//! Static client provisioning, authorization requests, codes and consent.

use super::{OidcRepository, RepositoryExecutor, StoredRow};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use sqlx::{postgres::PgRow, types::Json};

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

impl StoredAuthorizationRequest {
    /// Decodes a stored row, retaining the column name and cause for invalid data.
    fn from_row(row: &PgRow) -> Result<Self, DatabaseError> {
        Ok(Self {
            id: row.id("id")?,
            client_id: row.column("client_id")?,
            client_display_name: row.column("client_display_name")?,
            redirect_uri: row.column("redirect_uri")?,
            client_state: row.column("client_state")?,
            nonce: row.column("nonce")?,
            pkce_challenge: row.column("pkce_challenge")?,
            scopes: row.json("scopes")?,
            audience: row.column("audience")?,
            force_login: row.column("force_login")?,
            force_consent: row.column("force_consent")?,
            max_age: row.column("max_age")?,
            hinted_user_id: row.id("hinted_user_id")?,
            created_at: row.column("created_at")?,
        })
    }
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
            sqlx::query("UPDATE oidc_clients SET enabled=FALSE")
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
        run!(
            self,
            execute,
            sqlx::query(
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
                FROM upsert"
            )
            .bind(&input.id)
            .bind(&input.display_name)
            .bind(Json(&input.allowed_scopes))
            .bind(Json(&input.allowed_audiences))
            .bind(input.allow_refresh)
            .bind(&input.redirect_uris)
            .bind(&input.post_logout_uris)
            .bind(input.enabled)
            .bind(input.trusted)
            .bind(&input.client_secret_hash)
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
        let row = run!(
            self,
            fetch_optional,
            sqlx::query(
                "SELECT
                    c.id, c.display_name, c.enabled, c.allowed_scopes, c.allowed_audiences,
                    c.allow_refresh, c.trusted, c.client_secret_hash,
                    COALESCE(
                        jsonb_agg(r.uri) FILTER (WHERE r.kind = 'authorization'),
                        '[]'::jsonb
                    ) AS redirect_uris,
                    COALESCE(
                        jsonb_agg(r.uri) FILTER (WHERE r.kind = 'post_logout'),
                        '[]'::jsonb
                    ) AS post_logout_uris
                FROM oidc_clients c
                LEFT JOIN oidc_redirect_uris r ON r.client_id = c.id
                WHERE c.id = $1
                GROUP BY c.id"
            )
            .bind(id)
        )?;
        row.map(|row| {
            Ok(StoredOidcClient {
                id: row.column("id")?,
                display_name: row.column("display_name")?,
                redirect_uris: row.json("redirect_uris")?,
                post_logout_uris: row.json("post_logout_uris")?,
                allowed_scopes: row.json("allowed_scopes")?,
                allowed_audiences: row.json("allowed_audiences")?,
                allow_refresh: row.column("allow_refresh")?,
                enabled: row.column("enabled")?,
                trusted: row.column("trusted")?,
                client_secret_hash: row.column("client_secret_hash")?,
            })
        })
        .transpose()
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
            sqlx::query(
                "INSERT INTO authorization_requests (
                    id, secret_digest, client_id, redirect_uri, client_state,
                    nonce, pkce_challenge, scopes, audience, force_login,
                    max_age, expires_at, force_consent, hinted_user_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"
            )
            .bind(input.id.as_uuid())
            .bind(&input.secret_digest)
            .bind(&input.client_id)
            .bind(&input.redirect_uri)
            .bind(&input.client_state)
            .bind(&input.nonce)
            .bind(&input.pkce_challenge)
            .bind(Json(&input.scopes))
            .bind(&input.audience)
            .bind(input.force_login)
            .bind(input.max_age)
            .bind(input.expires_at)
            .bind(input.force_consent)
            .bind(input.hinted_user_id.map(UserId::as_uuid))
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
            sqlx::query(
                "SELECT
                    r.id, r.client_id, c.display_name AS client_display_name, r.redirect_uri,
                    r.client_state, r.nonce, r.pkce_challenge, r.scopes, r.audience,
                    r.force_login, r.force_consent, r.max_age, r.hinted_user_id, r.created_at
                FROM authorization_requests r
                JOIN oidc_clients c ON c.id = r.client_id
                WHERE r.id = $1
                AND r.secret_digest = $2
                AND r.consumed_at IS NULL
                AND r.expires_at > now()
                AND c.enabled"
            )
            .bind(id.as_uuid())
            .bind(digest)
        )?
        .as_ref()
        .map(StoredAuthorizationRequest::from_row)
        .transpose()
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
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "UPDATE authorization_requests r
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
                    r.id, r.client_id, c.display_name AS client_display_name, r.redirect_uri,
                    r.client_state, r.nonce, r.pkce_challenge, r.scopes, r.audience,
                    r.force_login, r.force_consent, r.max_age, r.hinted_user_id, r.created_at"
            )
            .bind(id.as_uuid())
            .bind(digest)
        )?;
        StoredAuthorizationRequest::from_row(&row)
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
            sqlx::query(
                "INSERT INTO authorization_codes (
                    id, secret_digest, client_id, user_id, session_id, redirect_uri,
                    pkce_challenge, nonce, scopes, audience, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
            )
            .bind(input.id.as_uuid())
            .bind(&input.secret_digest)
            .bind(&input.client_id)
            .bind(input.user_id.as_uuid())
            .bind(input.session_id.as_uuid())
            .bind(&input.redirect_uri)
            .bind(&input.pkce_challenge)
            .bind(&input.nonce)
            .bind(Json(&input.scopes))
            .bind(&input.audience)
            .bind(input.expires_at)
        )?;
        Ok(())
    }

    /// Consumes an unexpired code once. The client's current policy must still
    /// allow it, and its session and account must still be active.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if no such code exists, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn consume_code(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<ConsumedAuthorizationCode, DatabaseError> {
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "UPDATE authorization_codes c
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
                    c.client_id, c.user_id, c.session_id, c.redirect_uri, c.pkce_challenge,
                    c.nonce, c.scopes, c.audience"
            )
            .bind(id.as_uuid())
            .bind(digest)
        )?;
        Ok(ConsumedAuthorizationCode {
            client_id: row.column("client_id")?,
            user_id: row.id("user_id")?,
            session_id: row.id("session_id")?,
            redirect_uri: row.column("redirect_uri")?,
            pkce_challenge: row.column("pkce_challenge")?,
            nonce: row.column("nonce")?,
            scopes: row.json("scopes")?,
            audience: row.column("audience")?,
        })
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
        Ok(run!(
            self,
            fetch_optional,
            sqlx::query(
                "SELECT 1
                FROM oidc_consents
                WHERE user_id = $1
                AND client_id = $2
                AND audience = $3
                AND scopes @> $4"
            )
            .bind(user.as_uuid())
            .bind(client)
            .bind(audience)
            .bind(Json(scopes))
        )?
        .is_some())
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
            sqlx::query(
                "INSERT INTO oidc_consents (user_id, client_id, audience, scopes)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, client_id, audience) DO UPDATE
                SET scopes = (
                    SELECT jsonb_agg(DISTINCT value)
                    FROM jsonb_array_elements(oidc_consents.scopes || EXCLUDED.scopes)
                )"
            )
            .bind(user.as_uuid())
            .bind(client)
            .bind(audience)
            .bind(Json(scopes))
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
            sqlx::query(
                "SELECT normalized_email
                FROM user_emails
                WHERE user_id = $1
                AND verified_at IS NOT NULL
                ORDER BY is_primary DESC, created_at
                LIMIT 1"
            )
            .bind(user.as_uuid())
        )?
        .map(|row| row.column("normalized_email"))
        .transpose()
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
            sqlx::query("UPDATE sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1")
                .bind(session.as_uuid())
        )?;
        run!(
            self,
            execute,
            sqlx::query(
                "UPDATE refresh_token_families
                SET revoked_at = COALESCE(revoked_at, now())
                WHERE session_id = $1"
            )
            .bind(session.as_uuid())
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
