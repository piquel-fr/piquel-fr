//! The deployable Piquel authentication authority.
// Future policy modules remain private to this application.

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use piquel_configuration::{ConfigurationError, PublicUrl, SecretReference, socket_addr};
use piquel_repository::{Database, DatabaseConfig};
use std::{env, net::SocketAddr, time::Duration};

/// Typed auth-service configuration.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Public issuer/base URL.
    pub public_base_url: PublicUrl,
    /// Public HTTP listener address.
    pub public_listener: SocketAddr,
    /// Reserved private RPC listener address; no RPC is exposed yet.
    pub internal_listener: SocketAddr,
    /// Database connection settings.
    pub database: DatabaseConfig,
    /// Key-provider locator, never a literal key.
    pub key_provider: SecretReference,
}
impl AuthConfig {
    /// Loads the minimum service configuration from the environment.
    ///
    /// # Errors
    ///
    /// Returns an error when a required setting is absent or malformed.
    pub fn from_environment() -> Result<Self, ConfigurationError> {
        let required = |name| env::var(name).map_err(|_| ConfigurationError::Missing(name));
        let database_url = required("AUTH_DATABASE_URL")?;
        Ok(Self {
            public_base_url: PublicUrl::parse(&required("AUTH_PUBLIC_BASE_URL")?)?,
            public_listener: socket_addr(
                "AUTH_PUBLIC_LISTENER",
                &required("AUTH_PUBLIC_LISTENER")?,
            )?,
            internal_listener: socket_addr(
                "AUTH_INTERNAL_LISTENER",
                &required("AUTH_INTERNAL_LISTENER")?,
            )?,
            database: DatabaseConfig::new(database_url, 10, Duration::from_secs(5)).map_err(
                |_| ConfigurationError::Invalid {
                    name: "AUTH_DATABASE_URL",
                },
            )?,
            key_provider: SecretReference::parse(&required("AUTH_KEY_PROVIDER")?)?,
        })
    }
}

#[derive(Clone)]
struct AppState {
    database: Option<Database>,
    key_provider_configured: bool,
}

/// Builds the public health-only router. Liveness has no dependencies; readiness fails closed.
pub fn router(database: Option<Database>, key_provider_configured: bool) -> Router {
    Router::new()
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .route("/health/ready", get(ready))
        .with_state(AppState {
            database,
            key_provider_configured,
        })
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let Some(database) = state.database else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    if !state.key_provider_configured {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    match database.health_check().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
