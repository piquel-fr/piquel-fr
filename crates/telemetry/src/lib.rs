//! Sanitized tracing setup and values for security-sensitive services.

use std::fmt;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

/// A value deliberately rendered as `[REDACTED]` in all tracing output.
pub struct Redacted<T>(T);
impl<T> Redacted<T> {
    /// Wraps a sensitive value before it reaches telemetry.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}
impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Initializes structured stderr tracing with a conservative default filter.
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
