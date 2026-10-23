//! The account API for the OIDC clients an account manages: thin JSON adapters
//! over the owner's [`AccountService`] operations, which hold the policy and
//! share [`ClientRegistry`](super::ClientRegistry)'s validation and events with
//! the `client` command. Like every account route, they accept only the
//! first-party frontends' exact origins and the session cookie, and mutations need
//! the CSRF header.

use super::{ClientDetails, ClientPatch, NewClient, Rotation};
use crate::{
    account::{AccountService, ConfirmedOwner, Owner},
    routes,
    security::ApiError,
};
use axum::{
    Json, Router,
    extract::{FromRef, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use piquel_repository::{Database, StoredOidcClient};
use serde::Serialize;

/// The account's clients: list, register, show, change, pause, rotate, delete.
#[derive(Clone)]
pub(crate) struct ClientApplication {
    /// Registrations, sessions and events.
    database: Database,
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

    /// The owner's operations on clients.
    fn service(&self) -> AccountService {
        AccountService::new(self.database.clone())
    }

    /// Lists the owner's live clients.
    async fn list(
        State(app): State<Self>,
        owner: Owner,
    ) -> Result<Json<Vec<StoredOidcClient>>, ApiError> {
        Ok(Json(app.service().clients(&owner).await?))
    }

    /// Registers a client, and returns it with a confidential client's secret.
    /// An unconfirmed session is asked to confirm before its settings are read.
    async fn create(
        State(app): State<Self>,
        owner: ConfirmedOwner,
        Json(new): Json<NewClient>,
    ) -> Result<(StatusCode, Json<Registered>), ApiError> {
        let (client, secret) = app.service().create_client(&owner, new).await?;
        Ok((
            StatusCode::CREATED,
            Json(Registered {
                client,
                client_secret: secret.map(|secret| secret.expose().to_owned()),
            }),
        ))
    }

    /// Shows a client with the lifetimes of its secrets.
    async fn show(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<String>,
    ) -> Result<Json<ClientDetails>, ApiError> {
        Ok(Json(app.service().client(&owner, &id).await?))
    }

    /// Changes the given settings and returns the client.
    async fn update(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<String>,
        Json(patch): Json<ClientPatch>,
    ) -> Result<Json<StoredOidcClient>, ApiError> {
        Ok(Json(app.service().update_client(&owner, &id, patch).await?))
    }

    /// Pauses a client: it can no longer authorize, exchange codes or refresh.
    async fn disable(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        app.service().set_client_enabled(&owner, &id, false).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Lets a paused client work again.
    async fn enable(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        app.service().set_client_enabled(&owner, &id, true).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// Gives a confidential client a new secret, shown only in this answer.
    async fn rotate(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<String>,
        Json(rotation): Json<Rotation>,
    ) -> Result<Json<Rotated>, ApiError> {
        let secret = app
            .service()
            .rotate_client_secret(&owner, &id, rotation.grace)
            .await?;
        Ok(Json(Rotated {
            client_secret: secret.expose().to_owned(),
        }))
    }

    /// Deletes a client for good.
    async fn delete(
        State(app): State<Self>,
        owner: Owner,
        Path(id): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        app.service().delete_client(&owner, &id).await?;
        Ok(StatusCode::NO_CONTENT)
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
