//! Authentication service and its small administrative CLI.
use auth_service::{AuthConfig, Jobs, PUBLIC_BASE_URL};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use piquel_common::{ConfigurationError, ErrorChain, Origin, Variable};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{
    Actor, Database, DatabaseConnectionError, DatabaseError, DomainEvent, EventContext,
    RequestOrigin,
};
use thiserror::Error;

use std::{net::SocketAddr, process::ExitCode, str::FromStr};

/// Largest accepted invitation lifetime number; the suffix chooses hours or days.
const MAX_INVITE_EXPIRY: i64 = 365;
/// Shared command-line explanation for invalid invitation lifetimes.
const INVITE_EXPIRY_HELP: &str = "expiry must be 1 to 365 followed by h or d, e.g. 24h or 7d";
/// Registration page used by generated signup links.
const REGISTRATION_PATH: &str = "/register";
/// Invitation proof sent to the registration page.
const INVITATION_PARAMETER: &str = "invitation";
/// The operating system user running a command, recorded on the events it causes.
const OS_USER: Variable = Variable::new("USER");
/// The machine's host name, for systems without `/proc`.
const HOST_NAME: Variable = Variable::new("HOSTNAME");
/// Where Linux exposes the host name.
const HOST_NAME_FILE: &str = "/proc/sys/kernel/hostname";
/// Recorded when the operator's user or host name cannot be read.
const UNKNOWN_OPERATOR: &str = "unknown";

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
    /// A background job panicked.
    #[error("a background job panicked")]
    Job(#[from] tokio::task::JoinError),
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
        let expires_at = Utc::now() + expires_in.0;
        let mut tx = database.begin().await?;
        tx.security()
            .create_invitation(secret.digest().as_bytes(), expires_at)
            .await?;
        tx.record(
            &Self::operator()?,
            None,
            DomainEvent::InvitationCreated { expires_at },
        )
        .await?;
        tx.commit().await?;
        let mut url = PUBLIC_BASE_URL.parse::<Origin>()?.as_url().clone();
        url.set_path(REGISTRATION_PATH);
        url.query_pairs_mut()
            .append_pair(INVITATION_PARAMETER, &secret.encoded());
        println!("{url}");
        Ok(())
    }

    /// Attributes events of a command to the operator running it: `$USER` and the
    /// host name, or `unknown` where they cannot be read, as in some containers.
    fn operator() -> Result<EventContext, CliError> {
        let host = std::fs::read_to_string(HOST_NAME_FILE)
            .ok()
            .map(|host| host.trim().to_owned())
            .or(HOST_NAME.optional()?)
            .filter(|host| !host.is_empty());
        Ok(EventContext {
            actor: Actor::Cli {
                os_user: OS_USER
                    .optional()?
                    .unwrap_or_else(|| UNKNOWN_OPERATOR.to_owned()),
                host: host.unwrap_or_else(|| UNKNOWN_OPERATOR.to_owned()),
            },
            origin: RequestOrigin::default(),
        })
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

    /// Builds the configured service, provisions clients, starts background jobs and
    /// serves until a shutdown signal. Once in-flight requests drain, running jobs
    /// get a grace period to finish.
    async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let listener = tokio::net::TcpListener::bind(config.public_listener).await?;
        let router = config.router(database.clone())?;
        config.provision_clients(&database).await?;
        let jobs = Jobs::start(&database);
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(Self::shutdown_signal())
        .await;
        let jobs = jobs.shutdown().await;
        result?;
        Ok(jobs?)
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
