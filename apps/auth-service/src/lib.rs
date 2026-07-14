//! The deployable Piquel authentication authority.
// Future policy modules remain private to this application.

use async_trait::async_trait;
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use piquel_configuration::{ConfigurationError, PublicUrl, SecretReference, socket_addr};
use piquel_repository::{Database, DatabaseConfig};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};

#[allow(dead_code)]
mod account;
#[allow(dead_code)]
mod audit;
#[allow(dead_code)]
mod email;
#[allow(dead_code)]
mod event_log;
#[allow(dead_code)]
mod session;

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
        let development = env::var("AUTH_DEVELOPMENT_MODE").is_ok_and(|value| value == "true");
        let public_base_url = if development {
            PublicUrl::parse_development(&required("AUTH_PUBLIC_BASE_URL")?)?
        } else {
            PublicUrl::parse(&required("AUTH_PUBLIC_BASE_URL")?)?
        };
        let database = if development {
            DatabaseConfig::new_development(database_url, 10, Duration::from_secs(5))
        } else {
            DatabaseConfig::new(database_url, 10, Duration::from_secs(5))
        }
        .map_err(|_| ConfigurationError::Invalid {
            name: "AUTH_DATABASE_URL",
        })?;
        Ok(Self {
            public_base_url,
            public_listener: socket_addr(
                "AUTH_PUBLIC_LISTENER",
                &required("AUTH_PUBLIC_LISTENER")?,
            )?,
            internal_listener: socket_addr(
                "AUTH_INTERNAL_LISTENER",
                &required("AUTH_INTERNAL_LISTENER")?,
            )?,
            database,
            key_provider: SecretReference::parse(&required("AUTH_KEY_PROVIDER")?)?,
        })
    }
}

/// Dependency check used by readiness without minting credentials.
#[async_trait]
pub trait Readiness: Send + Sync {
    /// Returns only when every required dependency is usable.
    async fn check(&self) -> Result<(), ()>;
}

/// Production readiness checks `PostgreSQL` and resolves the configured key.
pub struct ProductionReadiness {
    database: Database,
    key_provider: SecretReference,
}
impl ProductionReadiness {
    /// Builds the production readiness dependency set.
    #[must_use]
    pub const fn new(database: Database, key_provider: SecretReference) -> Self {
        Self {
            database,
            key_provider,
        }
    }
}
#[async_trait]
impl Readiness for ProductionReadiness {
    async fn check(&self) -> Result<(), ()> {
        self.database.health_check().await.map_err(|_| ())?;
        tokio::time::timeout(Duration::from_secs(2), async {
            self.key_provider.resolve().map(|_| ()).map_err(|_| ())
        })
        .await
        .map_err(|_| ())?
    }
}

#[derive(Clone)]
struct AppState {
    readiness: Arc<dyn Readiness>,
}

/// Builds the public health-only router. Liveness has no dependencies; readiness fails closed.
pub fn router(readiness: Arc<dyn Readiness>) -> Router {
    Router::new()
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .route("/health/ready", get(ready))
        .with_state(AppState { readiness })
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match state.readiness.check().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(()) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    struct FixedReadiness(bool);
    #[async_trait]
    impl Readiness for FixedReadiness {
        async fn check(&self) -> Result<(), ()> {
            if self.0 { Ok(()) } else { Err(()) }
        }
    }

    #[tokio::test]
    async fn liveness_has_no_dependencies_and_readiness_fails_closed() {
        let app = router(Arc::new(FixedReadiness(false)));
        let live = app
            .clone()
            .oneshot(
                axum::http::Request::get("/health/live")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let ready = app
            .oneshot(
                axum::http::Request::get("/health/ready")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(live.status(), StatusCode::NO_CONTENT);
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readiness_succeeds_with_test_substitutes() {
        let response = router(Arc::new(FixedReadiness(true)))
            .oneshot(
                axum::http::Request::get("/health/ready")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
