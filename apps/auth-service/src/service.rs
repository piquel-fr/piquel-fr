//! Built-in health routes.
use crate::{routes, security::ApiError};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use piquel_repository::Database;

/// Service-wide endpoints with the same construction pattern as feature applications.
#[derive(Clone)]
pub(crate) struct ServiceApplication {
    /// Database checked by readiness.
    database: Database,
}

impl ServiceApplication {
    /// Builds the health routes over `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
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

    /// Reports that the database can serve requests.
    async fn ready(State(app): State<Self>) -> Result<StatusCode, ApiError> {
        app.database.health_check().await?;
        Ok(StatusCode::NO_CONTENT)
    }
}
