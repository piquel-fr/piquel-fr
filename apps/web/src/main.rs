//! piquel.fr's web server: Piquel's homepage and policies. It is its own product,
//! relying on auth.piquel.fr only to sign people in: it links auth's pages, and
//! redirects every path it doesn't serve there.

/// piquel.fr's pages.
mod pages;
/// The router.
mod site;

use piquel_common::config::{ConfigurationError, Origin};
use piquel_telemetry::{Export, Telemetry, TelemetryError};
use site::Site;
use std::{net::SocketAddr, process::ExitCode};
use tokio::{net::TcpListener, signal::unix::SignalKind};

piquel_common::variables! {
    /// Every variable piquel-web reads, in the configuration reference's order.
    #[cfg(test)]
    const VARIABLES;

    /// Auth's origin, such as `https://auth.piquel.fr`. piquel.fr links its pages
    /// and redirects every other path there. Required.
    const AUTH_ORIGIN = "WEB_AUTH_ORIGIN";
    /// The address piquel-web listens on, behind piqueld's gateway.
    const LISTENER = "WEB_LISTENER", default DEFAULT_LISTENER;
}
/// [`LISTENER`] when none is configured.
const DEFAULT_LISTENER: &str = "127.0.0.1:8080";

/// The default `service.name` of exported telemetry.
const SERVICE_NAME: &str = "piquel-web";
/// What is traced, and logged unless `RUST_LOG` says otherwise.
const TELEMETRY_FILTER: &str = "piquel_web=info";

/// Why the server stopped.
#[derive(Debug, thiserror::Error)]
enum WebError {
    /// A variable is missing or invalid.
    #[error("invalid configuration")]
    Configuration(#[from] ConfigurationError),
    /// Telemetry could not start or flush.
    #[error("telemetry failed")]
    Telemetry(#[from] TelemetryError),
    /// The listener could not bind or serve.
    #[error("could not serve HTTP")]
    Serve(#[from] std::io::Error),
}

/// The configured server.
struct Web {
    /// Where it listens.
    listener: SocketAddr,
    /// What it serves.
    site: Site,
}

impl Web {
    /// Reads `WEB_LISTENER` and `WEB_AUTH_ORIGIN`.
    fn from_environment() -> Result<Self, ConfigurationError> {
        let auth: Origin = AUTH_ORIGIN.parse()?;
        Ok(Self {
            listener: LISTENER.parse_or(DEFAULT_LISTENER)?,
            site: Site::new(auth),
        })
    }

    /// Serves until Ctrl+C or SIGTERM, then lets in-flight requests finish.
    async fn serve(self) -> Result<(), WebError> {
        let listener = TcpListener::bind(self.listener).await?;
        tracing::info!(address = %listener.local_addr()?, "piquel.fr listening");
        let mut terminate = tokio::signal::unix::signal(SignalKind::terminate())?;
        axum::serve(listener, self.site.router())
            .with_graceful_shutdown(async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
                tracing::info!("shutting down");
            })
            .await?;
        Ok(())
    }

    /// Installs telemetry, serves, then flushes telemetry. A failed flush is only
    /// reported.
    async fn run() -> Result<(), WebError> {
        let telemetry = Telemetry::init(SERVICE_NAME, TELEMETRY_FILTER, Export::Required)?;
        let result = async { Self::from_environment()?.serve().await }.await;
        if let Err(error) = telemetry.shutdown().await {
            eprintln!("warning: {}", Self::chain(&error));
        }
        result
    }

    /// `error` and its causes, on one line.
    fn chain(error: &dyn std::error::Error) -> String {
        let mut text = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        text
    }
}

/// Runs the server, printing a failure with its causes.
#[tokio::main]
async fn main() -> ExitCode {
    match Web::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", Web::chain(&error));
            ExitCode::FAILURE
        }
    }
}

/// The configuration reference's piquel-web section says what this file declares.
/// `just docs reference` rewrites it.
#[cfg(test)]
#[test]
fn configuration_reference_is_current() {
    use piquel_common::config::{GeneratedFile, Section};
    GeneratedFile {
        path: concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/dev/operations/variables/piquel-web.md"
        )
        .into(),
        text: Section::render(
            &[Section {
                title: "Service",
                variables: VARIABLES,
            }],
            3,
            "the variables in `apps/web/src/main.rs`",
        ),
    }
    .write_or_compare()
    .expect("current reference");
}
