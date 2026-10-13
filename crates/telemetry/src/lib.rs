//! Structured tracing setup for service executables.

use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

/// Installs compact stderr tracing, filtered by `RUST_LOG` or else `default_filter`.
pub fn init(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::NONE)
        .with_target(false)
        .compact()
        .init();
}
