//! Built-in health routes.
use crate::{SigningKeys, routes, security::ApiError};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use sourceorigin_repository::Database;

/// Service-wide endpoints with the same construction pattern as feature applications.
#[derive(Clone)]
pub(crate) struct ServiceApplication {
    /// Database checked by readiness.
    database: Database,
    /// Signing keys, which readiness requires to have been reloaded recently.
    keys: SigningKeys,
}

impl ServiceApplication {
    /// Builds the health routes over `database` and this replica's `keys`.
    pub(crate) const fn new(database: Database, keys: SigningKeys) -> Self {
        Self { database, keys }
    }

    /// Returns all service-wide endpoints with this application as state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::service::LIVE, get(Self::live))
            .route(routes::service::READY, get(Self::ready))
            .with_state(self)
    }

    /// Answers liveness independently of database availability.
    fn live() -> std::future::Ready<StatusCode> {
        std::future::ready(StatusCode::NO_CONTENT)
    }

    /// Reports that the database can serve requests, and that this replica's
    /// signing keys were reloaded recently, so it trusts no key revoked since.
    async fn ready(State(app): State<Self>) -> Result<StatusCode, ApiError> {
        app.keys.ready()?;
        app.database.health_check().await?;
        Ok(StatusCode::NO_CONTENT)
    }
}
