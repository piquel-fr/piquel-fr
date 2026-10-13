//! One authentication authority: browser flows, settings API, and OIDC.
/// Embedded auth frontend pages and static resources.
mod assets;
/// Validated service and application configuration.
mod config;
/// Shared normalized email validation.
mod email;
/// External identity provider applications and linking.
mod federation;
/// OAuth and `OpenID` Connect protocol application.
mod oidc;
/// `WebAuthn` ceremonies and account/session management.
mod passkey;
/// Every HTTP path the service serves.
mod routes;
/// Shared browser-session extraction and HTTP trust policy.
mod security;
/// Built-in public configuration, liveness and readiness.
mod service;

pub use config::{AuthConfig, PUBLIC_BASE_URL};
use federation::FederationApplication;
use oidc::OidcApplication;
use passkey::PasskeyApplication;
use service::ServiceApplication;

use assets::EmbeddedAssets;
use axum::{Router, extract::DefaultBodyLimit, http::Uri, middleware};
use piquel_repository::{Database, DatabaseError};
use thiserror::Error;

/// Bound on browser ceremony and API JSON bodies.
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Failures encountered before the service can accept requests.
#[derive(Debug, Error)]
pub enum StartupError {
    /// Passkey library initialization failed.
    #[error("could not initialize passkey application")]
    Passkey(#[from] passkey::PasskeyConfigError),
    /// Provider credentials or HTTP client initialization failed.
    #[error("could not initialize federation application")]
    Federation(#[from] federation::FederationConfigError),
    /// Static OIDC client provisioning failed.
    #[error("could not provision OIDC clients")]
    Database(#[from] DatabaseError),
    /// The executable lacks the required browser assets.
    #[error(
        "build the auth frontend with pnpm --filter @piquel/auth-web build before compiling auth-service"
    )]
    MissingAssets,
}

impl AuthConfig {
    /// Builds uniformly constructed applications under shared browser-origin protection.
    ///
    /// # Errors
    /// Fails when the frontend is not embedded, an application cannot initialize, or
    /// client provisioning fails.
    pub async fn router(&self, database: Database) -> Result<Router, StartupError> {
        // Finish fallible application initialization before changing client registrations.
        let assets = EmbeddedAssets::new()?;
        let application = Router::new()
            .merge(ServiceApplication::new(database.clone(), self).routes())
            .merge(PasskeyApplication::new(database.clone(), &self.passkey)?.routes())
            .merge(FederationApplication::new(database.clone(), &self.federation)?.routes())
            .merge(OidcApplication::new(database.clone(), &self.oidc).routes());
        let mut tx = database.begin().await?;
        tx.oidc().disable_all_clients().await?;
        for client in &self.oidc.clients {
            tx.oidc().bootstrap_client(client).await?;
        }
        tx.commit().await?;
        let policy = security::HttpSecurity::new(self, database);
        Ok(application
            .fallback(move |uri: Uri| async move { assets.serve(uri.path()) })
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .layer(middleware::from_fn_with_state(
                policy,
                security::HttpSecurity::protect,
            )))
    }
}
