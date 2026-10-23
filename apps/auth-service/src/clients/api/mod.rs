//! The account API for the OIDC clients an account manages: thin handlers over
//! [`ClientRegistry`], so they share its validation and events with the `client`
//! command. Like every account route, they accept only the first-party frontends'
//! exact origins and the session cookie, and mutations need the CSRF header.

use super::{ClientDetails, ClientRegistry, DEFAULT_CLIENT_SCOPES};
use crate::{
    GracePeriod, routes,
    security::{ApiError, Confirmed, RequestContext, Session},
};
use axum::{
    Json, Router,
    extract::{FromRef, FromRequestParts, Path, State},
    http::{StatusCode, request::Parts},
    routing::{get, post},
};
use piquel_common::{
    ClientId,
    clients::{
        AllowedScopes, ClientField, ClientKind, ClientOwner, ClientRegistration, PostLogoutUris,
        RedirectUri, RedirectUris, ScopeName,
    },
    protocol::oauth::Scope,
};
use piquel_crypto::Secret;
use piquel_repository::{Database, DatabaseTransaction, StoredOidcClient, StoredSession};
use serde::{Deserialize, Serialize};

/// Client API failures and their browser response mapping.
mod error;
use error::{ClientApiError, InvalidSetting};

/// The account's clients: list, register, show, change, pause, rotate, delete.
#[derive(Clone)]
pub(crate) struct ClientApplication {
    /// Registrations, sessions and events.
    database: Database,
}

/// A live client the signed-in account manages, loaded by the `{id}` of its path.
/// Any other ID, a deleted client's or another account's included, is answered
/// with 404, so probing IDs reveals nothing. Handlers never check ownership again:
/// it never changes, and the registry refuses a client deleted since.
pub(crate) struct OwnedClient {
    /// The signed-in session, as extracted; handlers lock it before changing anything.
    session: StoredSession,
    /// The client, as it was when the request arrived.
    client: StoredOidcClient,
}

/// The settings an owner chooses, in the shape `GET` returns them. This is the
/// policy for clients accounts manage, enforced by the types here rather than by
/// handlers: there is no field for the ID, which auth generates, or for trust, so
/// an owner's client always shows the consent screen, and scopes are limited to
/// the standard [`Scope`]s.
#[derive(Deserialize)]
struct ClientSettings {
    /// The name consent screens show.
    display_name: String,
    /// Authorization callbacks, matched exactly.
    redirect_uris: Vec<String>,
    /// Pages the browser may return to after logout.
    #[serde(default)]
    post_logout_uris: Vec<String>,
    /// Scopes the client may request; `openid`, `profile` and `email` when omitted.
    #[serde(default = "ClientSettings::default_scopes")]
    allowed_scopes: Vec<String>,
    /// Whether the client may receive refresh tokens, with `offline_access`.
    #[serde(default)]
    allow_refresh: bool,
    /// Whether the client must push its authorization requests (RFC 9126).
    #[serde(default)]
    require_pushed_authorization_requests: bool,
}

/// The body of a registration.
#[derive(Deserialize)]
struct NewClient {
    /// Public, or confidential with a secret auth generates.
    kind: ClientKind,
    /// Everything else.
    #[serde(flatten)]
    settings: ClientSettings,
}

/// The body of a change: each given setting replaces the stored one.
#[derive(Deserialize)]
struct ClientPatch {
    /// A new consent-screen name.
    display_name: Option<String>,
    /// New authorization callbacks; changing them needs a passkey confirmation.
    redirect_uris: Option<Vec<String>>,
    /// New post-logout pages; changing them needs a passkey confirmation.
    post_logout_uris: Option<Vec<String>>,
    /// New scopes.
    allowed_scopes: Option<Vec<String>>,
    /// Whether refresh tokens are allowed.
    allow_refresh: Option<bool>,
    /// Whether authorization requests must be pushed.
    require_pushed_authorization_requests: Option<bool>,
}

/// The body of a secret rotation.
#[derive(Deserialize)]
struct Rotation {
    /// How long earlier secrets keep working, e.g. `30m`, `24h` or `7d`; `0`
    /// revokes them now. A day when omitted, 30 days at most.
    #[serde(default)]
    grace: GracePeriod,
}

/// A registered client, with a confidential client's first secret.
#[derive(Serialize)]
struct Registered {
    /// The registration.
    #[serde(flatten)]
    client: StoredOidcClient,
    /// The secret, shown only in this answer; `None` for a public client.
    client_secret: Option<String>,
}

/// A confidential client's new secret.
#[derive(Serialize)]
struct Rotated {
    /// The secret, shown only in this answer.
    client_secret: String,
}

impl ClientSettings {
    /// The scopes a client gets when none are given.
    fn default_scopes() -> Vec<String> {
        DEFAULT_CLIENT_SCOPES
            .map(|scope| scope.as_str().to_owned())
            .into()
    }

    /// Validates every setting, naming the first one that is invalid, and builds
    /// the registration of an untrusted client `id` of `kind`.
    fn registration(
        self,
        id: ClientId,
        kind: ClientKind,
    ) -> Result<ClientRegistration, InvalidSetting> {
        let scopes = self
            .allowed_scopes
            .iter()
            .map(|scope| {
                scope.parse::<Scope>().map(ScopeName::from).map_err(|_| {
                    let allowed = Scope::ALL.map(Scope::as_str).join(", ");
                    InvalidSetting::new(
                        ClientField::AllowedScopes,
                        format!("scope {scope:?} is not one of {allowed}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ClientRegistration {
            id,
            display_name: self
                .display_name
                .parse()
                .map_err(InvalidSetting::with(ClientField::DisplayName))?,
            kind,
            redirect_uris: RedirectUris::new(Self::uris(
                &ClientField::RedirectUris,
                &self.redirect_uris,
            )?)
            .map_err(InvalidSetting::with(ClientField::RedirectUris))?,
            post_logout_uris: PostLogoutUris::new(Self::uris(
                &ClientField::PostLogoutUris,
                &self.post_logout_uris,
            )?)
            .map_err(InvalidSetting::with(ClientField::PostLogoutUris))?,
            allowed_scopes: AllowedScopes::new(scopes)
                .map_err(InvalidSetting::with(ClientField::AllowedScopes))?,
            allow_refresh: self.allow_refresh,
            trusted: false,
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
        })
    }

    /// Parses the URIs of `field`.
    fn uris(field: &ClientField, uris: &[String]) -> Result<Vec<RedirectUri>, InvalidSetting> {
        uris.iter()
            .map(|uri| uri.parse().map_err(InvalidSetting::with(field.clone())))
            .collect()
    }
}

impl ClientPatch {
    /// The registration of `current` with the given settings replaced. It is
    /// validated as a new one is, so a change cannot do what registration may not.
    fn apply(self, current: &StoredOidcClient) -> Result<ClientRegistration, InvalidSetting> {
        ClientSettings {
            display_name: self
                .display_name
                .unwrap_or_else(|| current.display_name.clone()),
            redirect_uris: self
                .redirect_uris
                .unwrap_or_else(|| current.redirect_uris.clone()),
            post_logout_uris: self
                .post_logout_uris
                .unwrap_or_else(|| current.post_logout_uris.clone()),
            allowed_scopes: self
                .allowed_scopes
                .unwrap_or_else(|| current.allowed_scopes.clone()),
            allow_refresh: self.allow_refresh.unwrap_or(current.allow_refresh),
            require_pushed_authorization_requests: self
                .require_pushed_authorization_requests
                .unwrap_or(current.require_pushed_authorization_requests),
        }
        .registration(current.id.clone(), current.kind)
    }
}

impl OwnedClient {
    /// Locks the account and session in `tx`, as [`Session::lock`] does, and
    /// returns the session as it is now.
    async fn lock(&self, tx: &mut DatabaseTransaction<'_>) -> Result<StoredSession, ApiError> {
        Ok(Session::lock(tx, &self.session).await?)
    }

    /// [`Self::lock`], then requires a recent passkey confirmation of the session.
    async fn confirm(&self, tx: &mut DatabaseTransaction<'_>) -> Result<StoredSession, ApiError> {
        let session = self.lock(tx).await?;
        <Confirmed>::check(&session)?;
        Ok(session)
    }
}

impl<S> FromRequestParts<S> for OwnedClient
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// Requires a session, then loads the client its account manages.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Session(session) = Session::from_request_parts(parts, state).await?;
        let Path(id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| ClientApiError::NotFound)?;
        let client = Database::from_ref(state)
            .oidc()
            .find_client(&id)
            .await?
            .filter(|client| {
                client.owner_id == Some(session.user_id) && client.deleted_at.is_none()
            })
            .ok_or(ClientApiError::NotFound)?;
        Ok(Self { session, client })
    }
}

impl ClientApplication {
    /// Serves the account's clients from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns the client routes with this application as state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::clients::LIST, get(Self::list).post(Self::create))
            .route(
                routes::clients::ITEM,
                get(Self::show).patch(Self::update).delete(Self::delete),
            )
            .route(routes::clients::DISABLE, post(Self::disable))
            .route(routes::clients::ENABLE, post(Self::enable))
            .route(routes::clients::SECRETS, post(Self::rotate))
            .with_state(self)
    }

    /// Lists the account's live clients. Clients operators manage are never shown.
    async fn list(
        State(app): State<Self>,
        Session(session): Session,
    ) -> Result<Json<Vec<StoredOidcClient>>, ApiError> {
        Ok(Json(
            app.database
                .oidc()
                .list_owned_clients(session.user_id)
                .await?,
        ))
    }

    /// Registers a client the account manages, with an ID auth generates, and
    /// returns it with a confidential client's secret, shown only here. Needs a
    /// passkey confirmation, and fails once the account manages
    /// [`MAX_OWNED_CLIENTS`](super::MAX_OWNED_CLIENTS) clients.
    async fn create(
        State(app): State<Self>,
        context: RequestContext,
        confirmed: Confirmed,
        Json(body): Json<NewClient>,
    ) -> Result<(StatusCode, Json<Registered>), ApiError> {
        let random = Secret::generate().map_err(ApiError::internal)?;
        let registration = body
            .settings
            .registration(ClientId::generated(random.as_bytes()), body.kind)?;
        let mut tx = app.database.begin().await?;
        confirmed.lock(&mut tx).await?;
        let secret = ClientRegistry::new(&mut tx, context.user(&confirmed.0))
            .create(
                ClientOwner::Account(confirmed.0.user_id),
                &registration,
                None,
            )
            .await?;
        let client = Self::read(&mut tx, &registration.id).await?;
        tx.commit().await?;
        Ok((
            StatusCode::CREATED,
            Json(Registered {
                client,
                client_secret: secret.map(|secret| secret.expose().to_owned()),
            }),
        ))
    }

    /// Shows a client with the lifetimes of its secrets, never their values.
    async fn show(
        State(app): State<Self>,
        owned: OwnedClient,
    ) -> Result<Json<ClientDetails>, ApiError> {
        let secrets = app.database.oidc().client_secrets(&owned.client.id).await?;
        Ok(Json(ClientDetails {
            client: owned.client,
            secrets,
        }))
    }

    /// Changes the given settings and returns the client. Changing where auth may
    /// send the browser needs a passkey confirmation: with a stolen session cookie,
    /// someone could otherwise add their own redirect URI and collect
    /// authorization codes.
    async fn update(
        State(app): State<Self>,
        context: RequestContext,
        owned: OwnedClient,
        Json(patch): Json<ClientPatch>,
    ) -> Result<Json<StoredOidcClient>, ApiError> {
        let mut tx = app.database.begin().await?;
        let session = owned.lock(&mut tx).await?;
        let changed = ClientRegistry::new(&mut tx, context.user(&session))
            .update(&owned.client.id, |current| {
                patch.apply(current).map_err(ApiError::from)
            })
            .await?;
        if changed.iter().any(ClientField::redirects) {
            <Confirmed>::check(&session)?;
        }
        let client = Self::read(&mut tx, &owned.client.id).await?;
        tx.commit().await?;
        Ok(Json(client))
    }

    /// Pauses a client: it can no longer authorize, exchange codes or refresh.
    async fn disable(
        State(app): State<Self>,
        context: RequestContext,
        owned: OwnedClient,
    ) -> Result<StatusCode, ApiError> {
        app.set_enabled(context, owned, false).await
    }

    /// Lets a paused client work again.
    async fn enable(
        State(app): State<Self>,
        context: RequestContext,
        owned: OwnedClient,
    ) -> Result<StatusCode, ApiError> {
        app.set_enabled(context, owned, true).await
    }

    /// Enables or disables a client. A session is enough: either is undone as easily.
    async fn set_enabled(
        &self,
        context: RequestContext,
        owned: OwnedClient,
        enabled: bool,
    ) -> Result<StatusCode, ApiError> {
        let mut tx = self.database.begin().await?;
        let session = owned.lock(&mut tx).await?;
        ClientRegistry::new(&mut tx, context.user(&session))
            .set_enabled(&owned.client.id, enabled)
            .await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Gives a confidential client a new secret, shown only in this answer. Earlier
    /// secrets keep working for the grace period. Needs a passkey confirmation.
    async fn rotate(
        State(app): State<Self>,
        context: RequestContext,
        owned: OwnedClient,
        Json(rotation): Json<Rotation>,
    ) -> Result<Json<Rotated>, ApiError> {
        let mut tx = app.database.begin().await?;
        let session = owned.confirm(&mut tx).await?;
        let secret = ClientRegistry::new(&mut tx, context.user(&session))
            .rotate_secret(&owned.client.id, rotation.grace)
            .await?;
        tx.commit().await?;
        Ok(Json(Rotated {
            client_secret: secret.expose().to_owned(),
        }))
    }

    /// Deletes a client for good: it stops working at once, and its ID is never
    /// used again. Needs a passkey confirmation.
    async fn delete(
        State(app): State<Self>,
        context: RequestContext,
        owned: OwnedClient,
    ) -> Result<StatusCode, ApiError> {
        let mut tx = app.database.begin().await?;
        let session = owned.confirm(&mut tx).await?;
        ClientRegistry::new(&mut tx, context.user(&session))
            .delete(&owned.client.id)
            .await?;
        tx.commit().await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Reads back client `id` as the transaction changed it.
    async fn read(
        tx: &mut DatabaseTransaction<'_>,
        id: &ClientId,
    ) -> Result<StoredOidcClient, ApiError> {
        Ok(tx
            .oidc()
            .find_client(id.as_str())
            .await?
            .ok_or(ClientApiError::NotFound)?)
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl FromRef<ClientApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &ClientApplication) -> Self {
        application.database.clone()
    }
}

/// Database-backed scenarios of the account's client routes.
#[cfg(test)]
mod tests;
