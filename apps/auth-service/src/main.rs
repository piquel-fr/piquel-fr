//! Authentication service and its administrative CLI.
use auth_service::Cli;
use clap::Parser;
use std::process::ExitCode;

/// Runs the selected command; see [`Cli`].
#[tokio::main]
async fn main() -> ExitCode {
    Cli::parse().run().await
}
