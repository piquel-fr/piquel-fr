//! Authentication service and its administrative CLI.
use auth_service::Cli;
use clap::Parser;
use std::process::ExitCode;

/// Runs the selected command; see [`Cli`]. Once it ends, the process exits
/// without waiting for blocking work still running, such as a DNS lookup: a
/// command bounds its own shutdown, and dropping the runtime would wait for that
/// work forever.
fn main() -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: could not start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(Cli::parse().run());
    runtime.shutdown_background();
    code
}
