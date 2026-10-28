//! One authentication authority: browser flows, settings API, OIDC and the admin API.
/// Settings any administrator may also change, as operations both the owner's
/// routes and the CLI run.
mod account;
/// The private admin API and the operations it shares with the CLI.
mod admin;
/// The stylesheet and passkey script of auth's pages, embedded at compile time.
mod assets;
/// The command line: serving, migrations and break-glass administration.
mod cli;
/// Creating, changing, rotating the secrets of and deleting OIDC clients, and the
/// owner's operations on the clients an account manages.
mod clients;
/// Validated service and application configuration.
mod config;
/// Sending the outbound delivery queue.
mod deliveries;
/// The account's email addresses and their verification.
mod emails;
/// External identity provider applications and linking.
mod federation;
/// The apps that keep access to an account, and removing it.
mod grants;
/// The signed-in user's security history and its reports.
mod history;
/// Periodic background work, coordinated across replicas.
mod jobs;
/// Signing keys: sealed storage, rotation and the key set every replica reloads.
mod keys;
/// OAuth and `OpenID` Connect protocol application.
mod oidc;
/// Lists of operations every surface serving them must cover.
mod operations;
/// `WebAuthn` ceremonies and passkey management.
mod passkey;
/// Account recovery for owners who lost every passkey.
mod recovery;
/// Every HTTP path the service serves.
mod routes;
/// Shared browser-session extraction and HTTP trust policy.
mod security;
/// Built-in liveness and readiness.
mod service;
/// The account's sessions, and signing them out.
mod sessions;
/// Fixtures shared by the applications' tests.
#[cfg(test)]
mod tests;
/// auth.piquel.fr's server-rendered pages.
mod web;

pub use admin::{
    AdminError, AdminService, GracePeriod, HandleIssue, HandleProblem, InviteExpiry, Operator,
    Reason, UserRef,
};
pub use cli::Cli;
pub use clients::{
    Applied, ClientDetails, ClientRegistry, ClientRegistryError, DEFAULT_CLIENT_SCOPES,
    MAX_DAILY_REGISTRATIONS, MAX_OWNED_CLIENTS,
};
pub use config::{AuthConfig, PUBLIC_BASE_URL, TokenDigestKeys};
use emails::EmailApplication;
use federation::FederationApplication;
use history::HistoryApplication;
pub use jobs::Jobs;
pub use keys::{KeyError, KeyStore, SigningKeys};
use oidc::OidcApplication;
use passkey::PasskeyApplication;
use service::ServiceApplication;
use web::WebApplication;

use account::AccountApplication;
use assets::EmbeddedAssets;
use axum::{Router, extract::DefaultBodyLimit, http::Uri, middleware, routing::get};
use piquel_repository::Database;
use piquel_telemetry::HttpTelemetry;
use thiserror::Error;

/// The default `service.name` of exported telemetry.
pub const SERVICE_NAME: &str = "auth-service";
/// What is traced, and logged unless `RUST_LOG` says otherwise: auth's own
/// operations, and its database queries and committed events.
pub const TELEMETRY_FILTER: &str = "auth_service=info,piquel_repository=info";

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
    /// The HTTP client that sends deliveries could not initialize.
    #[error("could not initialize the outbound HTTP client")]
    Outbound(#[source] reqwest::Error),
}

impl AuthConfig {
    /// Builds uniformly constructed applications under shared browser-origin
    /// protection, signing and verifying with `keys`. It changes nothing in the
    /// database, so tests build several to act as replicas.
    ///
    /// # Errors
    /// Fails when an application cannot initialize.
    pub fn router(&self, database: Database, keys: &SigningKeys) -> Result<Router, StartupError> {
        let oidc = OidcApplication::new(database.clone(), &self.oidc, keys.clone())?;
        let federation = FederationApplication::new(database.clone(), &self.federation)?;
        let application = Router::new()
            .merge(ServiceApplication::new(database.clone()).routes())
            .merge(PasskeyApplication::new(database.clone(), &self.passkey)?.routes())
            .merge(federation.clone().routes())
            .merge(HistoryApplication::new(database.clone()).routes())
            .merge(AccountApplication::new(database.clone()).routes())
            .merge(EmailApplication::new(database.clone(), &self.email).routes())
            .merge(WebApplication::new(database.clone(), self, oidc.clone(), federation).routes())
            .merge(oidc.routes());
        let policy = security::HttpSecurity::new(self, database);
        let protected = application
            .fallback(get(
                |uri: Uri| async move { EmbeddedAssets::serve(uri.path()) },
            ))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .layer(middleware::from_fn_with_state(
                policy,
                security::HttpSecurity::protect,
            ));
        // Outside the security layer, so throttled and rejected requests are traced too.
        Ok(HttpTelemetry::default()
            .quiet(&[routes::service::LIVE, routes::service::READY])
            .wrap(protected))
    }

    /// Builds the admin API, for the private admin listener only. It has no browser
    /// origin, CSRF or rate policy: no browser reaches it, and every request
    /// carries an administrator's access token. It shares the public listener's
    /// body limit and deadline, so no request can hold up shutdown. Its telemetry
    /// is labelled `piquel.listener = "admin"`.
    pub fn admin_router(&self, database: Database, keys: &SigningKeys) -> Router {
        HttpTelemetry::default().listener("admin").wrap(
            admin::AdminApplication::new(database, self, keys.clone())
                .routes()
                .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
                .layer(middleware::from_fn(security::HttpSecurity::deadline)),
        )
    }
}
