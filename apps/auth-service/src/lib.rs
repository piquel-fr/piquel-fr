//! One authentication authority: browser flows, settings API, and OIDC.
/// Embedded auth frontend pages and static resources.
mod assets;
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

pub use config::{AuthConfig, PUBLIC_BASE_URL};
use federation::FederationApplication;
pub use jobs::Jobs;
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
    /// The OIDC metadata or signing keys could not be serialized.
    #[error("could not initialize OIDC application")]
    Oidc(#[from] oidc::OidcConfigError),
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

    /// Replaces every client registration with the clients file, atomically. Every
    /// replica runs this at startup, after [`Self::router`] has initialized.
    ///
    /// # Errors
    /// Fails when the database rejects the registrations.
    pub async fn provision_clients(&self, database: &Database) -> Result<(), StartupError> {
        let mut tx = database.begin().await?;
        tx.oidc().disable_all_clients().await?;
        for client in &self.oidc.clients {
            tx.oidc().bootstrap_client(client).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
