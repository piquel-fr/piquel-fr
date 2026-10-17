//! Authentication service and its small administrative CLI.
use auth_service::{AuthConfig, PUBLIC_BASE_URL};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use piquel_common::{ConfigurationError, ErrorChain, Origin};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{Database, DatabaseConnectionError, DatabaseError};
use thiserror::Error;
use tokio::sync::oneshot;

use std::{net::SocketAddr, process::ExitCode, str::FromStr, time::Duration as StdDuration};

/// How often the service starts an expired-state cleanup pass.
const CLEANUP_INTERVAL: StdDuration = StdDuration::from_mins(5);
/// Maximum time spent draining one cleanup pass.
const CLEANUP_BUDGET: StdDuration = StdDuration::from_mins(1);
/// Pause between full batches, allowing live requests to use the pool.
const CLEANUP_PAUSE: StdDuration = StdDuration::from_millis(100);
/// Per-table cleanup batch bound.
const CLEANUP_BATCH_SIZE: u32 = 1_000;
/// Largest accepted invitation lifetime number; the suffix chooses hours or days.
const MAX_INVITE_EXPIRY: i64 = 365;
/// Shared command-line explanation for invalid invitation lifetimes.
const INVITE_EXPIRY_HELP: &str = "expiry must be 1 to 365 followed by h or d, e.g. 24h or 7d";
/// Registration page used by generated signup links.
const REGISTRATION_PATH: &str = "/register";
/// Invitation proof sent to the registration page.
const INVITATION_PARAMETER: &str = "invitation";

/// Failures of startup and administrative commands, preserving their original causes.
#[derive(Debug, Error)]
enum CliError {
    /// A required operator setting is missing or invalid.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// The authentication database could not be connected.
    #[error("could not connect to authentication database")]
    Connection(#[from] DatabaseConnectionError),
    /// An administrative database operation failed.
    #[error("authentication database command failed")]
    Database(#[from] DatabaseError),
    /// Random invitation or client-secret generation failed.
    #[error("could not generate secure command material")]
    Crypto(#[from] CryptoError),
    /// HTTP applications or embedded assets could not be initialized.
    #[error(transparent)]
    Startup(#[from] auth_service::StartupError),
    /// The service listener could not be bound or served.
    #[error("authentication HTTP listener failed")]
    Listener(#[from] std::io::Error),
    /// Expired-state cleanup panicked.
    #[error("expired authentication state cleanup panicked")]
    Cleanup(#[from] tokio::task::JoinError),
}

/// Piquel authentication service. Runs `serve` when no command is given.
#[derive(Parser)]
#[command(after_help = "Database commands use AUTH_DATABASE_URL. See README.md for configuration.")]
struct Cli {
    /// Defaults to serving when no administrative command is supplied.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Top-level commands, separating offline secret generation from database work.
#[derive(Subcommand)]
enum Command {
    /// Commands that need a validated database connection.
    #[command(flatten)]
    Database(DatabaseCommand),
    /// Print a random secret for a confidential OIDC client.
    Secret,
}

impl Command {
    /// Executes this command and returns the original startup or operation failure.
    async fn run(self) -> Result<(), CliError> {
        match self {
            Self::Secret => {
                println!("{}", Secret::generate()?.encoded());
                Ok(())
            }
            Self::Database(command) => command.run().await,
        }
    }
}

/// Commands that connect to `AUTH_DATABASE_URL` first.
#[derive(Subcommand)]
enum DatabaseCommand {
    /// Serve the authentication service.
    Serve,
    /// Apply database migrations.
    Migrate,
    /// Print a single-use signup link.
    Invite {
        /// How long the link stays valid, in hours or days (e.g. 24h, 7d).
        #[arg(long, default_value = "7d")]
        expires_in: InviteExpiry,
    },
}

impl DatabaseCommand {
    /// Executes this command and returns the original startup or operation failure.
    async fn run(self) -> Result<(), CliError> {
        let database = Database::connect(AuthConfig::database_from_environment()?).await?;
        match self {
            Self::Serve => Self::serve(database).await,
            Self::Migrate => Ok(database.run_migrations().await?),
            Self::Invite { expires_in } => Self::invite(&database, expires_in).await,
        }
    }

    /// Prints a single-use signup link; only the secret's digest is stored.
    async fn invite(database: &Database, expires_in: InviteExpiry) -> Result<(), CliError> {
        let secret = Secret::generate()?;
        database
            .security()
            .create_invitation(secret.digest().as_bytes(), Utc::now() + expires_in.0)
            .await?;
        let mut url = PUBLIC_BASE_URL.parse::<Origin>()?.as_url().clone();
        url.set_path(REGISTRATION_PATH);
        url.query_pairs_mut()
            .append_pair(INVITATION_PARAMETER, &secret.encoded());
        println!("{url}");
        Ok(())
    }

    /// Resolves on Ctrl+C or SIGTERM, the signal container runtimes send on stop.
    async fn shutdown_signal() {
        use tokio::signal::unix::{SignalKind, signal};
        let ctrl_c = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(?error, "Ctrl+C handler unavailable");
                std::future::pending::<()>().await;
            }
        };
        let terminate = async {
            match signal(SignalKind::terminate()) {
                Ok(mut terminate) => {
                    terminate.recv().await;
                }
                Err(error) => {
                    tracing::error!(?error, "SIGTERM handler unavailable");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = ctrl_c => {}
            () = terminate => {}
        }
        tracing::info!("shutting down");
    }

    /// Every five minutes, drains expired auth state in bounded batches until a
    /// pass finds nothing or a one-minute budget runs out. Short pauses between
    /// batches keep cleanup from monopolizing the database under heavy churn.
    /// Returns once `stop` resolves, which its sender's drop triggers, after
    /// finishing the batch in progress.
    async fn purge_expired_state(database: Database, mut stop: oneshot::Receiver<()>) {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                biased;
                _ = &mut stop => return,
                _ = interval.tick() => {}
            }
            let deadline = tokio::time::Instant::now() + CLEANUP_BUDGET;
            loop {
                match database.purge_expired_auth_state(CLEANUP_BATCH_SIZE).await {
                    Ok(0) => break,
                    Ok(_) if tokio::time::Instant::now() >= deadline => {
                        tracing::warn!("expired authentication state cleanup is falling behind");
                        break;
                    }
                    Ok(_) => tokio::select! {
                        biased;
                        _ = &mut stop => return,
                        () = tokio::time::sleep(CLEANUP_PAUSE) => {}
                    },
                    Err(error) => {
                        tracing::error!(?error, "expired authentication state cleanup failed");
                        break;
                    }
                }
            }
        }
    }

    /// Builds the configured service, provisions clients, starts cleanup and serves
    /// until a shutdown signal. Cleanup then finishes its current batch while
    /// in-flight requests drain.
    async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let listener = tokio::net::TcpListener::bind(config.public_listener).await?;
        let router = config.router(database.clone())?;
        config.provision_clients(&database).await?;
        let (stop, stopped) = oneshot::channel();
        let cleanup = tokio::spawn(Self::purge_expired_state(database, stopped));
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            Self::shutdown_signal().await;
            drop(stop);
        })
        .await;
        // A listener failure drops `stop` with the shutdown future, so cleanup ends too.
        let cleanup = cleanup.await;
        result?;
        Ok(cleanup?)
    }
}

/// An invitation lifetime of 1 to 365 hours or days.
#[derive(Clone, Copy)]
struct InviteExpiry(Duration);

/// Why an invitation lifetime was rejected by the command-line parser.
#[derive(Debug, Error)]
enum InvalidInviteExpiry {
    /// The unit, value or bounds violate the supported hours/days syntax.
    #[error("{INVITE_EXPIRY_HELP}")]
    Format,
    /// The numeric portion could not be parsed.
    #[error("{INVITE_EXPIRY_HELP}")]
    Number(#[from] std::num::ParseIntError),
}

impl FromStr for InviteExpiry {
    type Err = InvalidInviteExpiry;
    /// Parses a bounded hours/days lifetime while retaining numeric syntax errors.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (number, unit) = value
            .char_indices()
            .last()
            .map(|(index, _)| value.split_at(index))
            .ok_or(InvalidInviteExpiry::Format)?;
        let number = number.parse::<i64>()?;
        if !(1..=MAX_INVITE_EXPIRY).contains(&number) {
            return Err(InvalidInviteExpiry::Format);
        }
        match unit {
            "h" => Ok(Self(Duration::hours(number))),
            "d" => Ok(Self(Duration::days(number))),
            _ => Err(InvalidInviteExpiry::Format),
        }
    }
}

/// Initializes tracing, runs the selected command and prints any failure with its causes.
#[tokio::main]
async fn main() -> ExitCode {
    piquel_telemetry::init("auth_service=info");
    let command = Cli::parse()
        .command
        .unwrap_or(Command::Database(DatabaseCommand::Serve));
    match command.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", ErrorChain(&error));
            ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    //! Invitation lifetime parsing and bounds.
    use super::*;
    /// Invitation lifetimes accept bounded hours and days and reject malformed input.
    #[test]
    fn invite_expiry_accepts_bounded_hours_and_days() {
        assert_eq!(
            "24h".parse::<InviteExpiry>().map(|expiry| expiry.0).ok(),
            Some(Duration::hours(24))
        );
        assert_eq!(
            "365d".parse::<InviteExpiry>().map(|expiry| expiry.0).ok(),
            Some(Duration::days(365))
        );
        for invalid in ["", "d", "0d", "366d", "-1h", "7w", "7 d", "é"] {
            assert!(invalid.parse::<InviteExpiry>().is_err(), "{invalid}");
        }
    }
}
