//! Client registrations, their secrets, and the origins of public clients.
//!
//! Registrations are written only from a [`ClientRegistration`], whose types have
//! already validated every field. Reads return the stored strings, so a row
//! written under older rules still loads.

use super::OidcRedirectKind;
use crate::{
    DatabaseError,
    repositories::{JsonArray, OidcRepository, RepositoryExecutor, Unsigned},
};
use chrono::{DateTime, Duration, Utc};
use piquel_admin_api::Client;
use piquel_common::{
    ClientId, ClientSecretId, UserId,
    clients::{ClientField, ClientKind, ClientOwner, ClientRegistration, RedirectUri, ScopeName},
    protocol::oauth::ClientAuthMethod,
};
use serde::Serialize;
use sqlx::types::Json;

/// A registered client with its exact URI allowlists. A deleted client is still
/// returned, disabled, with its `deleted_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Each flag is an independent registration setting."
)]
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
    /// Whether the client must push its authorization requests.
    pub require_pushed_authorization_requests: bool,
    /// Where logout tokens are posted when a session it holds tokens from ends.
    pub backchannel_logout_uri: Option<String>,
    /// When the client was registered.
    pub created_at: DateTime<Utc>,
    /// When its registration last changed.
    pub updated_at: DateTime<Utc>,
    /// The account that manages it; `None` for clients operators manage.
    pub owner_id: Option<UserId>,
    /// When a token was last issued to it, to within an hour.
    pub last_used_at: Option<DateTime<Utc>>,
    /// When it was deleted. Its row stays, disabled, so its ID is never reused.
    pub deleted_at: Option<DateTime<Utc>>,
    /// When an operator suspended it. A suspended client stays disabled, and its
    /// owner cannot enable it.
    pub suspended_at: Option<DateTime<Utc>>,
}

/// How many clients an owner manages, and how many it registered recently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedClientCounts {
    /// Clients that are not deleted.
    pub live: u64,
    /// Clients registered within the window asked for, deleted ones included.
    pub registered_recently: u64,
}

impl StoredOidcClient {
    /// The settings that writing `registration` over this client would change;
    /// empty if it is stored exactly so. Lists compare as sets, since only their
    /// members matter. The ID and kind never change, so they are not compared.
    #[must_use]
    pub fn changes(&self, registration: &ClientRegistration) -> Vec<ClientField> {
        /// The URIs as written.
        fn uris(uris: &[RedirectUri]) -> Vec<&str> {
            uris.iter().map(RedirectUri::as_str).collect()
        }
        let same = |stored: &[String], given: &[&str]| {
            let mut stored: Vec<&str> = stored.iter().map(String::as_str).collect();
            let mut given = given.to_vec();
            stored.sort_unstable();
            given.sort_unstable();
            stored == given
        };
        let scopes: Vec<&str> = registration
            .allowed_scopes
            .iter()
            .map(ScopeName::as_str)
            .collect();
        [
            (
                ClientField::DisplayName,
                self.display_name == registration.display_name.as_str(),
            ),
            (
                ClientField::RedirectUris,
                same(&self.redirect_uris, &uris(&registration.redirect_uris)),
            ),
            (
                ClientField::PostLogoutUris,
                same(
                    &self.post_logout_uris,
                    &uris(&registration.post_logout_uris),
                ),
            ),
            (
                ClientField::AllowedScopes,
                same(&self.allowed_scopes, &scopes),
            ),
            (
                ClientField::AllowRefresh,
                self.allow_refresh == registration.allow_refresh,
            ),
            (ClientField::Trusted, self.trusted == registration.trusted),
            (
                ClientField::RequirePushedAuthorizationRequests,
                self.require_pushed_authorization_requests
                    == registration.require_pushed_authorization_requests,
            ),
            (
                ClientField::BackchannelLogoutUri,
                self.backchannel_logout_uri.as_deref()
                    == registration
                        .backchannel_logout_uri
                        .as_ref()
                        .map(RedirectUri::as_str),
            ),
        ]
        .into_iter()
        .filter_map(|(field, same)| (!same).then_some(field))
        .collect()
    }
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
            require_pushed_authorization_requests: client.require_pushed_authorization_requests,
            backchannel_logout_uri: client.backchannel_logout_uri,
            owner_id: client.owner_id,
            last_used_at: client.last_used_at,
            suspended_at: client.suspended_at,
            deleted_at: client.deleted_at,
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
    /// Registers a new, enabled client managed by `owner`. A confidential client
    /// has no secret until [`Self::insert_client_secret`] adds one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the ID is taken, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn create_client(
        &mut self,
        registration: &ClientRegistration,
        owner: ClientOwner,
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
                        allow_refresh, trusted, owner_id, created_via,
                        require_pushed_authorization_requests, backchannel_logout_uri
                    ) VALUES (
                        $1, $2, $3, $4, jsonb_build_array($1::text), $5, $6, $7, $8, $12, $13
                    )
                    RETURNING id
                )
                INSERT INTO oidc_redirect_uris (client_id, uri, kind, origin)
                SELECT client.id, r.uri, r.kind, r.origin
                FROM client, unnest($9::text[], $10::text[], $11::text[]) AS r(uri, kind, origin)",
                registration.id.as_str(),
                registration.display_name.as_str(),
                registration.kind.as_str(),
                Json(Self::scopes(registration)) as _,
                registration.allow_refresh,
                registration.trusted,
                owner.user_id().map(UserId::as_uuid),
                owner.created_via().as_str(),
                &redirects.uris,
                &redirects.kinds,
                &redirects.origins,
                registration.require_pushed_authorization_requests,
                registration
                    .backchannel_logout_uri
                    .as_ref()
                    .map(RedirectUri::as_str),
            )
        )?;
        Ok(())
    }

    /// Replaces a client's registration and redirect URIs. Its kind, owner, enabled
    /// state, secrets and audiences stay: `ClientRegistry` refuses to change a kind.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] for an unknown or deleted client, or another
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
                        require_pushed_authorization_requests = $9,
                        backchannel_logout_uri = $10,
                        updated_at = now()
                    WHERE id = $1 AND deleted_at IS NULL
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
                registration.require_pushed_authorization_requests,
                registration
                    .backchannel_logout_uri
                    .as_ref()
                    .map(RedirectUri::as_str),
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

    /// Deletes a client, leaving its row as a tombstone so its ID is never reused:
    /// disables it, revokes its refresh families, and removes its secrets and
    /// consents. Pending authorization requests and codes need an enabled client,
    /// so they stop working too.
    ///
    /// The caller locks the client's families first, as
    /// [`TokenRepository::lock_client_families`](crate::TokenRepository::lock_client_families)
    /// explains. A family granted since then is skipped if another transaction
    /// holds it: either that one revokes it, or it is a rotation, which locked the
    /// family before the client and will find the client disabled. Waiting for it
    /// would deadlock with that rotation.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] for an unknown or already deleted
    /// client, or another [`DatabaseError`] if the query fails.
    pub async fn delete_client(&mut self, id: &ClientId) -> Result<(), DatabaseError> {
        // Every CTE runs; the statement returns the deleted ID, so an unknown client
        // is `NotFound`.
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "WITH client AS (
                    UPDATE oidc_clients
                    SET deleted_at = now(), enabled = FALSE, updated_at = now()
                    WHERE id = $1 AND deleted_at IS NULL
                    RETURNING id
                ),
                secrets AS (
                    DELETE FROM oidc_client_secrets s USING client WHERE s.client_id = client.id
                ),
                consents AS (
                    DELETE FROM oidc_consents c USING client WHERE c.client_id = client.id
                ),
                families AS (
                    UPDATE refresh_token_families f
                    SET revoked_at = now()
                    FROM client, LATERAL (
                        SELECT id FROM refresh_token_families
                        WHERE client_id = client.id AND revoked_at IS NULL
                        ORDER BY id
                        FOR UPDATE SKIP LOCKED
                    ) free
                    WHERE f.id = free.id
                )
                SELECT id FROM client",
                id.as_str(),
            )
        )?;
        Ok(())
    }

    /// How many clients `owner` manages, deleted ones aside, and how many it
    /// registered in the last `window`, deleted ones included.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn count_owned_clients(
        &mut self,
        owner: UserId,
        window: Duration,
    ) -> Result<OwnedClientCounts, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                OwnedClientCounts,
                r#"SELECT
                    count(*) FILTER (WHERE deleted_at IS NULL) AS "live!: Unsigned",
                    count(*) FILTER (
                        WHERE created_at > now() - $2::bigint * interval '1 second'
                    ) AS "registered_recently!: Unsigned"
                FROM oidc_clients
                WHERE owner_id = $1"#,
                owner.as_uuid(),
                window.num_seconds(),
            )
        )
    }

    /// Suspends a client, which also disables it, or lifts its suspension, which
    /// leaves it disabled. Returns whether that changed its state.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn set_client_suspended(
        &mut self,
        id: &ClientId,
        suspended: bool,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE oidc_clients
                SET suspended_at = CASE WHEN $2 THEN now() END,
                    enabled = enabled AND NOT $2,
                    updated_at = now()
                WHERE id = $1 AND (suspended_at IS NULL) = $2",
                id.as_str(),
                suspended,
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Records that a token was issued to the client, at most once an hour so
    /// frequent grants do not write the row each time.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn touch_client(&mut self, id: &ClientId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE oidc_clients
                SET last_used_at = now()
                WHERE id = $1
                AND (last_used_at IS NULL OR last_used_at < now() - interval '1 hour')",
                id.as_str(),
            )
        )?;
        Ok(())
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
        Ok(self.clients(Some(id), None).await?.pop())
    }

    /// Lists every client, enabled, disabled or deleted, by ID.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_clients(&mut self) -> Result<Vec<StoredOidcClient>, DatabaseError> {
        self.clients(None, None).await
    }

    /// Lists the clients `owner` manages, deleted ones aside, by ID.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_owned_clients(
        &mut self,
        owner: UserId,
    ) -> Result<Vec<StoredOidcClient>, DatabaseError> {
        self.clients(None, Some(owner)).await
    }

    /// The client with ID `id`, or every client when `id` is `None`, by ID. With
    /// an `owner`, only the live clients it manages.
    async fn clients(
        &mut self,
        id: Option<&str>,
        owner: Option<UserId>,
    ) -> Result<Vec<StoredOidcClient>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredOidcClient,
                r#"SELECT
                    c.id AS "id: ClientId", c.display_name, c.client_type AS "kind: ClientKind",
                    c.enabled, c.allow_refresh, c.trusted,
                    c.require_pushed_authorization_requests, c.backchannel_logout_uri,
                    c.created_at, c.updated_at,
                    c.owner_id AS "owner_id: UserId", c.last_used_at, c.deleted_at,
                    c.suspended_at,
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
                WHERE ($1::text IS NULL OR c.id = $1)
                AND ($2::uuid IS NULL OR (c.owner_id = $2 AND c.deleted_at IS NULL))
                GROUP BY c.id
                ORDER BY c.id"#,
                id,
                owner.map(UserId::as_uuid),
            )
        )
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
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO oidc_client_secrets (id, client_id, secret_digest)
                VALUES ($1, $2, $3)",
                ClientSecretId::new().as_uuid(),
                id.as_str(),
                digest.as_slice(),
            )
        )?;
        Ok(())
    }

    /// Makes the client's secrets that still work stop at `now() + grace` at the
    /// latest, except the one whose digest is `keep`, and returns that time and
    /// whether any secret's end moved. An expired secret stays expired, and a
    /// secret that already stops earlier keeps its earlier end.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn cap_client_secrets(
        &mut self,
        id: &ClientId,
        grace: Duration,
        keep: Option<&[u8; 32]>,
    ) -> Result<(DateTime<Utc>, bool), DatabaseError> {
        let capped = run!(
            self,
            fetch_one,
            sqlx::query!(
                r#"WITH cap AS (SELECT now() + $2::bigint * interval '1 second' AS at),
                capped AS (
                    UPDATE oidc_client_secrets
                    SET expires_at = cap.at
                    FROM cap
                    WHERE client_id = $1
                    AND (expires_at IS NULL OR expires_at > cap.at)
                    AND secret_digest IS DISTINCT FROM $3
                    RETURNING 1
                )
                SELECT at AS "at!", EXISTS (SELECT 1 FROM capped) AS "capped!" FROM cap"#,
                id.as_str(),
                grace.num_seconds(),
                keep.map(<[u8; 32]>::as_slice),
            )
        )?;
        Ok((capped.at, capped.capped))
    }

    /// Whether the client has a secret with digest `digest` that no rotation has
    /// given an end yet.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn has_lasting_secret(
        &mut self,
        id: &ClientId,
        digest: &[u8; 32],
    ) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT EXISTS (
                    SELECT 1 FROM oidc_client_secrets
                    WHERE client_id = $1 AND secret_digest = $2 AND expires_at IS NULL
                ) AS "lasting!""#,
                id.as_str(),
                digest.as_slice(),
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
