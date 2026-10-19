//! Built-in health and public configuration routes.
use crate::{AuthConfig, config::FrontendOrigins, routes, security::ApiError};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use piquel_common::Provider;
use piquel_repository::Database;
use serde::Serialize;

/// Configuration sent to browser applications; field names are a stable API.
#[derive(Clone, Serialize)]
struct PublicConfig {
    // Keep fields in the original JSON object's sorted order for byte-for-byte replies.
    /// Frontend origins that sign-in may return to.
    frontend_origins: FrontendOrigins,
    /// Whether signup requires a single-use invitation.
    invite_required: bool,
    /// Enabled social login choices, in protocol declaration order.
    providers: Vec<Provider>,
    /// Exact settings continuation after authentication.
    settings_url: url::Url,
}

/// Service-wide endpoints with the same construction pattern as feature applications.
#[derive(Clone)]
pub(crate) struct ServiceApplication {
    /// Database checked by readiness.
    database: Database,
    /// Stable public browser configuration.
    public_config: PublicConfig,
}

impl ServiceApplication {
    /// Builds public configuration from validated application sections.
    pub(crate) fn new(database: Database, config: &AuthConfig) -> Self {
        let providers: Vec<_> = Provider::ALL
            .into_iter()
            .filter(|provider| config.federation.providers.contains_key(provider))
            .collect();
        Self {
            database,
            public_config: PublicConfig {
                frontend_origins: config.federation.frontends.clone(),
                settings_url: config.federation.settings_url.as_url().clone(),
                providers,
                invite_required: config.passkey.invite_required,
            },
        }
    }

    /// Returns all service-wide endpoints with this application as state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::service::LIVE, get(Self::live))
            .route(routes::service::READY, get(Self::ready))
            .route(routes::service::CONFIG, get(Self::config))
            .with_state(self)
    }

    /// Answers liveness independently of database availability.
    fn live() -> std::future::Ready<StatusCode> {
        std::future::ready(StatusCode::NO_CONTENT)
    }

    /// Returns browser configuration without exposing service secrets.
    fn config(State(app): State<Self>) -> std::future::Ready<Json<PublicConfig>> {
        std::future::ready(Json(app.public_config))
    }

    /// Reports that the database can serve requests.
    async fn ready(State(app): State<Self>) -> Result<StatusCode, ApiError> {
        app.database.health_check().await?;
        Ok(StatusCode::NO_CONTENT)
    }
}
