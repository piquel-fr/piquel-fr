//! The admin dashboard at admin.piquel.fr: server-rendered pages over auth's private
//! admin API, for administrators signed in with a passkey.
//!
//! The dashboard is an axum service. Its sign-in routes and session layer come from
//! the Rust SDK, and every other request goes to the Topcoat pages in [`pages`].

use piquel_admin_api::ApiError;
use piquel_common::{ErrorChain, config::ConfigurationError};
use piquel_telemetry::Telemetry;
use std::process::ExitCode;
use thiserror::Error;
use tokio::net::TcpListener;

/// The signed-in administrator of a request.
mod admin;
/// Startup configuration.
mod config;
/// The pages and their layout.
mod pages;
/// The HTTP service around the pages.
mod server;

use config::AdminConfig;
use server::Dashboard;

/// Failures that stop the dashboard.
#[derive(Debug, Error)]
pub enum StartupError {
    /// A setting is missing or invalid.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// The admin API client could not be built.
    #[error("could not build the admin API client")]
    Api(#[from] ApiError),
    /// The HTTP client for auth's public endpoints could not be built.
    #[error("could not build the auth HTTP client")]
    AuthClient(#[source] reqwest::Error),
    /// The auth origin cannot be sent in the security headers.
    #[error("ADMIN_AUTH_ORIGIN cannot be sent in a header")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
    /// The listener could not be bound or served.
    #[error("the admin dashboard listener failed")]
    Listener(#[from] std::io::Error),
}

/// Installs telemetry, serves, then flushes telemetry. A failed flush is only reported.
#[tokio::main]
async fn main() -> ExitCode {
    let telemetry = match Telemetry::init("admin-web", "info") {
        Ok(telemetry) => telemetry,
        Err(error) => {
            eprintln!("error: {}", ErrorChain(&error));
            return ExitCode::FAILURE;
        }
    };
    let served = run().await;
    if let Err(error) = &served {
        tracing::error!(error = %ErrorChain(error), "admin dashboard failed");
    }
    // An unreachable collector must not fail the dashboard's exit.
    if let Err(error) = telemetry.shutdown().await {
        eprintln!("warning: {}", ErrorChain(&error));
    }
    if served.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Serves the dashboard until a shutdown signal.
async fn run() -> Result<(), StartupError> {
    let config = AdminConfig::from_environment()?;
    let listener = TcpListener::bind(config.listener).await?;
    let dashboard = Dashboard::new(config)?;
    tracing::info!(address = %listener.local_addr()?, "admin dashboard listening");
    axum::serve(listener, dashboard.router())
        .with_graceful_shutdown(Dashboard::shutdown_signal())
        .await?;
    Ok(())
}
