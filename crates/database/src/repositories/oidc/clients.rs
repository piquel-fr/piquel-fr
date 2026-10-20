//! Client registrations, their secrets, and the origins of public clients.
//!
//! Registrations are written only from a [`ClientRegistration`], whose types have
//! already validated every field. Reads return the stored strings, so a row
//! written under older rules still loads.

use super::OidcRedirectKind;
use crate::{
    DatabaseError,
    repositories::{JsonArray, OidcRepository, RepositoryExecutor},
};
use chrono::{DateTime, Duration, Utc};
use piquel_admin_api::Client;
use piquel_common::{
    ClientId, ClientSecretId,
    clients::{ClientKind, ClientRegistration, RedirectUri, ScopeName},
    protocol::oauth::ClientAuthMethod,
};
use serde::Serialize;
use sqlx::types::Json;
use url::Url;

/// A registered client with its exact URI allowlists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoredOidcClient {
    /// Client identifier.
    pub id: ClientId,
    /// Name shown on consent screens.
    pub display_name: String,
    /// Public, or confidential with secrets.
    pub kind: ClientKind,
    /// Exact allowed authorization redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Exact allowed post-logout redirect URIs.
    pub post_logout_uris: Vec<String>,
    /// Scopes the client may request.
    pub allowed_scopes: Vec<String>,
    /// Audiences the client may request tokens for: its own ID, until #71.
    pub allowed_audiences: Vec<String>,
    /// Whether the client may receive refresh tokens.
    pub allow_refresh: bool,
    /// Disabled clients are rejected everywhere.
    pub enabled: bool,
    /// Whether the client skips the consent screen.
    pub trusted: bool,
    /// When the client was registered.
    pub created_at: DateTime<Utc>,
    /// When its registration last changed.
    pub updated_at: DateTime<Utc>,
}

impl From<StoredOidcClient> for Client {
    /// Shows the client without its secrets, only the authentication method its kind implies.
    fn from(client: StoredOidcClient) -> Self {
        Self {
            token_endpoint_auth_method: match client.kind {
                ClientKind::Public => ClientAuthMethod::None,
                ClientKind::Confidential => ClientAuthMethod::ClientSecretBasic,
            },
            id: client.id,
            display_name: client.display_name,
            redirect_uris: client.redirect_uris,
            post_logout_uris: client.post_logout_uris,
            allowed_scopes: client.allowed_scopes,
            allowed_audiences: client.allowed_audiences,
            allow_refresh: client.allow_refresh,
            enabled: client.enabled,
            trusted: client.trusted,
        }
    }
}

/// One of a confidential client's secrets. Its digest stays in the database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoredClientSecret {
    /// Secret identifier.
    pub id: ClientSecretId,
    /// When the secret was generated.
    pub created_at: DateTime<Utc>,
    /// When a rotation made it stop working; `None` while it has no end.
    pub expires_at: Option<DateTime<Utc>>,
}

/// The `oidc_redirect_uris` rows of a registration, as parallel arrays for `unnest`.
struct RedirectRows {
    /// Each URI.
    uris: Vec<String>,
    /// Its [`OidcRedirectKind`].
    kinds: Vec<String>,
    /// Its origin, which public clients' CORS looks up.
    origins: Vec<String>,
}

impl RedirectRows {
    /// Lists the authorization, then the post-logout redirect URIs.
    fn new(registration: &ClientRegistration) -> Self {
        let rows: Vec<(&RedirectUri, OidcRedirectKind)> = registration
            .redirect_uris
            .iter()
            .map(|uri| (uri, OidcRedirectKind::Authorization))
            .chain(
                registration
                    .post_logout_uris
                    .iter()
                    .map(|uri| (uri, OidcRedirectKind::PostLogout)),
            )
            .collect();
        Self {
            uris: rows.iter().map(|(uri, _)| uri.to_string()).collect(),
            kinds: rows.iter().map(|(_, kind)| kind.to_string()).collect(),
            origins: rows.iter().map(|(uri, _)| uri.origin()).collect(),
        }
    }
}

impl OidcRepository<'_> {
    /// Registers a new, enabled client. A confidential client has no secret until
    /// [`Self::insert_client_secret`] adds one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the ID is taken, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn create_client(
        &mut self,
        registration: &ClientRegistration,
    ) -> Result<(), DatabaseError> {
        let redirects = RedirectRows::new(registration);
        // The redirect rows reference the client inserted by the same statement.
        run!(
            self,
            execute,
            sqlx::query!(
                "WITH client AS (
                    INSERT INTO oidc_clients (
                        id, display_name, client_type, allowed_scopes, allowed_audiences,
                        allow_refresh, trusted
                    ) VALUES ($1, $2, $3, $4, jsonb_build_array($1::text), $5, $6)
                    RETURNING id
                )
                INSERT INTO oidc_redirect_uris (client_id, uri, kind, origin)
                SELECT client.id, r.uri, r.kind, r.origin
                FROM client, unnest($7::text[], $8::text[], $9::text[]) AS r(uri, kind, origin)",
                registration.id.as_str(),
                registration.display_name.as_str(),
                registration.kind.as_str(),
                Json(Self::scopes(registration)) as _,
                registration.allow_refresh,
                registration.trusted,
                &redirects.uris,
                &redirects.kinds,
                &redirects.origins,
            )
        )?;
        Ok(())
    }

    /// Replaces a client's registration and redirect URIs. Its kind, enabled state,
    /// secrets and audiences stay: `ClientRegistry` refuses to change a kind.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] for an unknown client, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn update_client(
        &mut self,
        registration: &ClientRegistration,
    ) -> Result<(), DatabaseError> {
        let redirects = RedirectRows::new(registration);
        // Every CTE runs; the statement returns the updated ID, so an unknown client
        // is `NotFound`.
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "WITH client AS (
                    UPDATE oidc_clients
                    SET display_name = $2,
                        allowed_scopes = $3,
                        allow_refresh = $4,
                        trusted = $5,
                        updated_at = now()
                    WHERE id = $1
                    RETURNING id
                ),
                desired (uri, kind, origin) AS (
                    SELECT * FROM unnest($6::text[], $7::text[], $8::text[])
                ),
                upserted AS (
                    INSERT INTO oidc_redirect_uris (client_id, uri, kind, origin)
                    SELECT client.id, d.uri, d.kind, d.origin
                    FROM client, desired d
                    ON CONFLICT (client_id, uri, kind) DO UPDATE SET origin = EXCLUDED.origin
                ),
                removed AS (
                    DELETE FROM oidc_redirect_uris r
                    USING client
                    WHERE r.client_id = client.id
                    AND NOT EXISTS (
                        SELECT 1 FROM desired d WHERE d.uri = r.uri AND d.kind = r.kind
                    )
                )
                SELECT id FROM client",
                registration.id.as_str(),
                registration.display_name.as_str(),
                Json(Self::scopes(registration)) as _,
                registration.allow_refresh,
                registration.trusted,
                &redirects.uris,
                &redirects.kinds,
                &redirects.origins,
            )
        )?;
        Ok(())
    }

    /// The allowed scopes as stored, a JSON array of strings.
    fn scopes(registration: &ClientRegistration) -> Vec<&str> {
        registration
            .allowed_scopes
            .iter()
            .map(ScopeName::as_str)
            .collect()
    }

    /// Enables or disables a client. Returns whether that changed its state.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] for an unknown client, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn set_client_enabled(
        &mut self,
        id: &ClientId,
        enabled: bool,
    ) -> Result<bool, DatabaseError> {
        // The locked subquery reads the state this update replaces.
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"UPDATE oidc_clients c
                SET enabled = $2, updated_at = now()
                FROM (SELECT id, enabled FROM oidc_clients WHERE id = $1 FOR NO KEY UPDATE) previous
                WHERE c.id = previous.id
                RETURNING previous.enabled <> $2 AS "changed!""#,
                id.as_str(),
                enabled,
            )
        )
    }

    /// Locks a client's row until the transaction ends, so changes that read the
    /// client before writing it, such as an update or a rotation, run one at a time.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] for an unknown client, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn lock_client(&mut self, id: &ClientId) -> Result<(), DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "SELECT id FROM oidc_clients WHERE id = $1 FOR NO KEY UPDATE",
                id.as_str(),
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
        Ok(self.clients(Some(id)).await?.pop())
    }

    /// Lists every client, enabled or not, by ID.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_clients(&mut self) -> Result<Vec<StoredOidcClient>, DatabaseError> {
        self.clients(None).await
    }

    /// The client with ID `id`, or every client when `id` is `None`, by ID.
    async fn clients(&mut self, id: Option<&str>) -> Result<Vec<StoredOidcClient>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredOidcClient,
                r#"SELECT
                    c.id AS "id: ClientId", c.display_name, c.client_type AS "kind: ClientKind",
                    c.enabled, c.allow_refresh, c.trusted, c.created_at, c.updated_at,
                    c.allowed_scopes AS "allowed_scopes: JsonArray<String>",
                    c.allowed_audiences AS "allowed_audiences: JsonArray<String>",
                    COALESCE(
                        jsonb_agg(r.uri ORDER BY r.uri) FILTER (WHERE r.kind = 'authorization'),
                        '[]'::jsonb
                    ) AS "redirect_uris!: JsonArray<String>",
                    COALESCE(
                        jsonb_agg(r.uri ORDER BY r.uri) FILTER (WHERE r.kind = 'post_logout'),
                        '[]'::jsonb
                    ) AS "post_logout_uris!: JsonArray<String>"
                FROM oidc_clients c
                LEFT JOIN oidc_redirect_uris r ON r.client_id = c.id
                WHERE $1::text IS NULL OR c.id = $1
                GROUP BY c.id
                ORDER BY c.id"#,
                id,
            )
        )
    }

    /// Fills in the origin of redirect URIs that have none: those registered before
    /// migration `0008`, or by the previous release since. Origins are serialized
    /// by the same URL parser as on registration, which SQL cannot reproduce for
    /// forms such as `https://app.example:0443/` or Unicode hosts. A URI without a
    /// tuple origin keeps none, and allows no browser origin.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails.
    pub async fn fill_redirect_origins(&mut self) -> Result<(), DatabaseError> {
        let missing = run!(
            self,
            fetch_all,
            sqlx::query_scalar!("SELECT DISTINCT uri FROM oidc_redirect_uris WHERE origin IS NULL")
        )?;
        let (uris, origins): (Vec<String>, Vec<String>) = missing
            .into_iter()
            .filter_map(|uri| {
                let origin = Url::parse(&uri).ok()?.origin();
                origin
                    .is_tuple()
                    .then(|| (uri, origin.ascii_serialization()))
            })
            .unzip();
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE oidc_redirect_uris r
                SET origin = f.origin
                FROM unnest($1::text[], $2::text[]) AS f(uri, origin)
                WHERE r.uri = f.uri
                AND r.origin IS NULL",
                &uris,
                &origins,
            )
        )?;
        Ok(())
    }

    /// Whether an enabled public client has an authorization redirect URI on
    /// `origin`, serialized as browsers send it in an `Origin` header.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn public_client_origin(&mut self, origin: &str) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT EXISTS (
                    SELECT 1
                    FROM oidc_redirect_uris r
                    JOIN oidc_clients c ON c.id = r.client_id
                    WHERE r.origin = $1
                    AND r.kind = 'authorization'
                    AND c.enabled
                    AND c.client_type = 'public'
                ) AS "allowed!""#,
                origin,
            )
        )
    }

    /// Adds a secret, by its SHA-256 digest, to a client.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the client does not exist or the query fails.
    pub async fn insert_client_secret(
        &mut self,
        id: &ClientId,
        digest: &[u8; 32],
    ) -> Result<(), DatabaseError> {
        // The previous release authenticates with `client_secret_hash`, so it holds the
        // newest secret too.
        run!(
            self,
            execute,
            sqlx::query!(
                "WITH secret AS (
                    INSERT INTO oidc_client_secrets (id, client_id, secret_digest)
                    VALUES ($1, $2, $3)
                )
                UPDATE oidc_clients SET client_secret_hash = $3 WHERE id = $2",
                ClientSecretId::new().as_uuid(),
                id.as_str(),
                digest.as_slice(),
            )
        )?;
        Ok(())
    }

    /// Makes the client's secrets that still work stop at `now() + grace` at the
    /// latest, and returns that time. An expired secret stays expired, and a secret
    /// that already stops earlier keeps its earlier end.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn cap_client_secrets(
        &mut self,
        id: &ClientId,
        grace: Duration,
    ) -> Result<DateTime<Utc>, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"WITH cap AS (SELECT now() + $2::bigint * interval '1 second' AS at),
                capped AS (
                    UPDATE oidc_client_secrets
                    SET expires_at = LEAST(COALESCE(expires_at, 'infinity'), cap.at)
                    FROM cap
                    WHERE client_id = $1
                    AND (expires_at IS NULL OR expires_at > now())
                )
                SELECT at AS "at!" FROM cap"#,
                id.as_str(),
                grace.num_seconds(),
            )
        )
    }

    /// The digests of the client's secrets that still work.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn active_secret_digests(&mut self, id: &str) -> Result<Vec<Vec<u8>>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                "SELECT secret_digest
                FROM oidc_client_secrets
                WHERE client_id = $1
                AND (expires_at IS NULL OR expires_at > now())",
                id,
            )
        )
    }

    /// Every secret of the client, expired ones included, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn client_secrets(
        &mut self,
        id: &ClientId,
    ) -> Result<Vec<StoredClientSecret>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredClientSecret,
                r#"SELECT id AS "id: ClientSecretId", created_at, expires_at
                FROM oidc_client_secrets
                WHERE client_id = $1
                ORDER BY created_at, id"#,
                id.as_str(),
            )
        )
    }
}
