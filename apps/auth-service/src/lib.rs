//! The deployable Piquel authentication authority.
// Future policy modules remain private to this application.

use async_trait::async_trait;
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use ipnet::IpNet;
use piquel_configuration::{ConfigurationError, PublicUrl, SecretReference, socket_addr};
use piquel_repository::{Database, DatabaseConfig};
use std::{env, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

#[allow(dead_code)]
mod account;
#[allow(dead_code)]
mod audit;
#[allow(dead_code)]
mod email;
#[allow(dead_code)]
mod event_log;
#[allow(dead_code)]
mod federation;
pub use federation::{FederationApplication, ProviderConfiguration};
#[allow(dead_code)]
mod oidc;
pub use oidc::{Es256KeyProvider, KeyProvider, OidcApplication};
#[allow(dead_code)]
mod passkey;
pub use passkey::PasskeyApplication;
mod hardening;
mod service_rpc;
#[allow(dead_code)]
mod session;
pub use service_rpc::ServiceRpcApplication;

/// Typed auth-service configuration.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Public issuer/base URL.
    pub public_base_url: PublicUrl,
    /// Public HTTP listener address.
    pub public_listener: SocketAddr,
    /// Internal-only HTTP health listener, never routed by Traefik.
    pub health_listener: SocketAddr,
    /// Reserved private RPC listener address; no RPC is exposed yet.
    pub internal_listener: SocketAddr,
    /// Database connection settings.
    pub database: DatabaseConfig,
    /// Key-provider locator, never a literal key.
    pub key_provider: SecretReference,
    /// `WebAuthn` relying-party identifier.
    pub webauthn_rp_id: String,
    /// Enables loopback-only development relaxations.
    pub development_mode: bool,
    /// Stable identifier published with the active signing key.
    pub signing_key_id: String,
    /// GitHub OAuth client configuration.
    pub github: ProviderConfiguration,
    /// Google OIDC client configuration.
    pub google: ProviderConfiguration,
    /// Server certificate for the mTLS private RPC listener.
    pub rpc_tls_certificate: SecretReference,
    /// Server private key for the mTLS private RPC listener.
    pub rpc_tls_private_key: SecretReference,
    /// Client CA used to require private-RPC client certificates.
    pub rpc_client_ca: SecretReference,
    /// Docker networks from which Traefik forwarding headers are accepted.
    pub trusted_proxy_cidrs: Arc<[IpNet]>,
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
            DatabaseConfig::new_development(&database_url, 10, Duration::from_secs(5))
        } else {
            DatabaseConfig::new(&database_url, 10, Duration::from_secs(5))
        }
        .map_err(|_| ConfigurationError::Invalid {
            name: "AUTH_DATABASE_URL",
        })?;
        let trusted_proxy_cidrs: Arc<[IpNet]> = if development {
            Arc::default()
        } else {
            let values = required("AUTH_TRUSTED_PROXY_CIDRS")?;
            let parsed: Vec<_> = values
                .split(',')
                .map(str::trim)
                .map(IpNet::from_str)
                .collect::<Result<_, _>>()
                .map_err(|_| ConfigurationError::Invalid {
                    name: "AUTH_TRUSTED_PROXY_CIDRS",
                })?;
            if parsed.is_empty() {
                return Err(ConfigurationError::Invalid {
                    name: "AUTH_TRUSTED_PROXY_CIDRS",
                });
            }
            parsed.into()
        };
        Ok(Self {
            public_base_url,
            public_listener: socket_addr(
                "AUTH_PUBLIC_LISTENER",
                &required("AUTH_PUBLIC_LISTENER")?,
            )?,
            health_listener: socket_addr(
                "AUTH_HEALTH_LISTENER",
                &required("AUTH_HEALTH_LISTENER")?,
            )?,
            internal_listener: socket_addr(
                "AUTH_INTERNAL_LISTENER",
                &required("AUTH_INTERNAL_LISTENER")?,
            )?,
            database,
            key_provider: SecretReference::parse(&required("AUTH_KEY_PROVIDER")?)?,
            webauthn_rp_id: required("AUTH_WEBAUTHN_RP_ID")?,
            development_mode: development,
            signing_key_id: required("AUTH_SIGNING_KEY_ID")?,
            github: ProviderConfiguration {
                client_id: required("AUTH_GITHUB_CLIENT_ID")?,
                client_secret: SecretReference::parse(&required("AUTH_GITHUB_CLIENT_SECRET")?)?,
            },
            google: ProviderConfiguration {
                client_id: required("AUTH_GOOGLE_CLIENT_ID")?,
                client_secret: SecretReference::parse(&required("AUTH_GOOGLE_CLIENT_SECRET")?)?,
            },
            rpc_tls_certificate: SecretReference::parse(&required("AUTH_RPC_TLS_CERTIFICATE")?)?,
            rpc_tls_private_key: SecretReference::parse(&required("AUTH_RPC_TLS_PRIVATE_KEY")?)?,
            rpc_client_ca: SecretReference::parse(&required("AUTH_RPC_CLIENT_CA")?)?,
            trusted_proxy_cidrs,
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
    secret_providers: Vec<SecretReference>,
    secret_check: Arc<tokio::sync::Semaphore>,
}
impl ProductionReadiness {
    /// Builds the production readiness dependency set.
    #[must_use]
    pub fn new(database: Database, secret_providers: Vec<SecretReference>) -> Self {
        Self {
            database,
            secret_providers,
            secret_check: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}
#[async_trait]
impl Readiness for ProductionReadiness {
    async fn check(&self) -> Result<(), ()> {
        self.database.health_check().await.map_err(|_| ())?;
        for provider in &self.secret_providers {
            let provider = provider.clone();
            let permit = tokio::time::timeout(
                Duration::from_secs(2),
                self.secret_check.clone().acquire_owned(),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
            tokio::time::timeout(
                Duration::from_secs(2),
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    provider.resolve().map(|_| ()).map_err(|_| ())
                }),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())??;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    readiness: Arc<dyn Readiness>,
}

/// Builds the public protocol/API router behind the trusted ingress boundary.
pub fn router(
    passkeys: Option<PasskeyApplication>,
    oidc: Option<OidcApplication>,
    federation: Option<FederationApplication>,
    trusted_proxy_cidrs: Option<Arc<[IpNet]>>,
) -> Router {
    let router = passkeys.map_or_else(Router::new, passkey::routes);
    let router = oidc.map_or(router.clone(), |oidc| router.merge(oidc::routes(oidc)));
    let router = federation.map_or(router.clone(), |federation| {
        router.merge(federation::routes(federation))
    });
    let ingress = trusted_proxy_cidrs.map_or(hardening::IngressPolicy::Direct, |cidrs| {
        hardening::IngressPolicy::TrustedProxies(cidrs)
    });
    hardening::apply(router, ingress)
}

/// Builds the internal, unthrottled health router.
pub fn health_router(readiness: Arc<dyn Readiness>) -> Router {
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
        let app = health_router(Arc::new(FixedReadiness(false)));
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
        let response = health_router(Arc::new(FixedReadiness(true)))
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
