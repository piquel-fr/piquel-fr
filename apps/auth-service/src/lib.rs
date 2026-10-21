//! One authentication authority: browser flows, settings API, OIDC and the admin API.
/// The private admin API and the operations it shares with the CLI.
mod admin;
/// Embedded auth frontend pages and static resources.
mod assets;
/// Creating, changing and rotating the secrets of OIDC clients.
mod clients;
/// Validated service and application configuration.
mod config;
/// Sending the outbound delivery queue.
// No channel sends deliveries yet: back-channel logout (#65) adds the first. Until
// then only tests use this module, and `expect` fails the build once it is used.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "No channel sends deliveries until #65.")
)]
mod deliveries;
/// Shared normalized email validation.
mod email;
/// External identity provider applications and linking.
mod federation;
/// The signed-in user's security history and its reports.
mod history;
/// Periodic background work, coordinated across replicas.
mod jobs;
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
/// Fixtures shared by the applications' tests.
#[cfg(test)]
mod tests;

pub use admin::{AdminError, AdminOperations, GracePeriod, InviteExpiry, Operator};
pub use clients::{ClientRegistry, ClientRegistryError};
pub use config::{AuthConfig, PUBLIC_BASE_URL};
use federation::FederationApplication;
use history::HistoryApplication;
pub use jobs::Jobs;
use oidc::OidcApplication;
use passkey::PasskeyApplication;
use service::ServiceApplication;

use assets::EmbeddedAssets;
use axum::{Router, extract::DefaultBodyLimit, http::Uri, middleware};
use piquel_repository::Database;
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
    /// The OIDC metadata or signing keys could not be serialized.
    #[error("could not initialize OIDC application")]
    Oidc(#[from] oidc::OidcConfigError),
    /// The executable lacks the required browser assets.
    #[error(
        "build the auth frontend with pnpm --filter @piquel/auth-web build before compiling auth-service"
    )]
    MissingAssets,
}

impl AuthConfig {
    /// Builds uniformly constructed applications under shared browser-origin protection.
    /// It changes nothing in the database, so tests build several to act as replicas.
    ///
    /// # Errors
    /// Fails when the frontend is not embedded or an application cannot initialize.
    pub fn router(&self, database: Database) -> Result<Router, StartupError> {
        let assets = EmbeddedAssets::new()?;
        let application = Router::new()
            .merge(ServiceApplication::new(database.clone(), self).routes())
            .merge(PasskeyApplication::new(database.clone(), &self.passkey)?.routes())
            .merge(FederationApplication::new(database.clone(), &self.federation)?.routes())
            .merge(HistoryApplication::new(database.clone()).routes())
            .merge(OidcApplication::new(database.clone(), &self.oidc)?.routes());
        let policy = security::HttpSecurity::new(self, database);
        Ok(application
            .fallback(move |uri: Uri| async move { assets.serve(uri.path()) })
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .layer(middleware::from_fn_with_state(
                policy,
                security::HttpSecurity::protect,
            )))
    }

    /// Builds the admin API, for the private admin listener only. It has no browser
    /// origin, CSRF or rate policy: no browser reaches it, and every request
    /// carries an administrator's access token. It shares the public listener's
    /// body limit and deadline, so no request can hold up shutdown.
    pub fn admin_router(&self, database: Database) -> Router {
        admin::AdminApplication::new(database, self)
            .routes()
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .layer(middleware::from_fn(security::HttpSecurity::deadline))
    }
}
