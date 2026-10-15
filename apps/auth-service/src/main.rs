//! Authentication service and its small administrative CLI.
use auth_service::{AdminError, AdminOperations, AuthConfig, InviteExpiry, PUBLIC_BASE_URL};
use clap::{Parser, Subcommand};
use piquel_common::{ConfigurationError, ErrorChain, Origin, Variable};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{Actor, Database, DatabaseConnectionError, DatabaseError};
use thiserror::Error;

use std::{net::SocketAddr, process::ExitCode, time::Duration as StdDuration};

/// How often the service starts an expired-state cleanup pass.
const CLEANUP_INTERVAL: StdDuration = StdDuration::from_mins(5);
/// Maximum time spent draining one cleanup pass.
const CLEANUP_BUDGET: StdDuration = StdDuration::from_mins(1);
/// Pause between full batches, allowing live requests to use the pool.
const CLEANUP_PAUSE: StdDuration = StdDuration::from_millis(100);
/// Per-table cleanup batch bound.
const CLEANUP_BATCH_SIZE: u32 = 1_000;
/// Login name of the operator running a command.
const OPERATOR_USER: Variable = Variable::new("USER");
/// Fallback login name, set where `USER` is not.
const OPERATOR_LOGNAME: Variable = Variable::new("LOGNAME");
/// Kernel's name for this host, recorded with the operator.
const HOSTNAME_PATH: &str = "/proc/sys/kernel/hostname";
/// Recorded when the operator's name or host cannot be determined.
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
    /// Random client-secret generation failed.
    #[error("could not generate secure command material")]
    Crypto(#[from] CryptoError),
    /// An administrative operation was refused or failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
    /// HTTP applications or embedded assets could not be initialized.
    #[error(transparent)]
    Startup(#[from] auth_service::StartupError),
    /// The service listener could not be bound or served.
    #[error("authentication HTTP listener failed")]
    Listener(#[from] std::io::Error),
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
    /// Grant, revoke or list administrator rights. No HTTP route can change them.
    Admin {
        /// The administrator operation.
        #[command(subcommand)]
        command: AdminCommand,
    },
}

/// Administrator rights, managed only from the CLI.
#[derive(Subcommand)]
enum AdminCommand {
    /// Make an active account an administrator.
    Grant {
        /// The account's username.
        username: String,
    },
    /// Remove an account's administrator rights.
    Revoke {
        /// The account's username.
        username: String,
    },
    /// List administrators: username, account ID, grant time and granting operator.
    List,
}

impl DatabaseCommand {
    /// Executes this command and returns the original startup or operation failure.
    async fn run(self) -> Result<(), CliError> {
        let database = Database::connect(AuthConfig::database_from_environment()?).await?;
        match self {
            Self::Serve => Self::serve(database).await,
            Self::Migrate => Ok(database.run_migrations().await?),
            Self::Invite { expires_in } => {
                let invitation = Self::operations(database)?
                    .create_invitation(&Self::operator(), expires_in)
                    .await?;
                println!("{}", invitation.url);
                Ok(())
            }
            Self::Admin { command } => {
                let operations = Self::operations(database)?;
                match command {
                    AdminCommand::Grant { username } => {
                        operations
                            .grant_administrator(&Self::operator(), &username)
                            .await?;
                    }
                    AdminCommand::Revoke { username } => {
                        operations
                            .revoke_administrator(&Self::operator(), &username)
                            .await?;
                    }
                    AdminCommand::List => {
                        for admin in operations.list_administrators().await? {
                            println!(
                                "{}\t{}\t{}\t{}",
                                admin.username,
                                admin.user_id,
                                admin.granted_at.to_rfc3339(),
                                admin.granted_by,
                            );
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Admin operations on `database`, linking invitations to `AUTH_PUBLIC_BASE_URL`.
    fn operations(database: Database) -> Result<AdminOperations, CliError> {
        Ok(AdminOperations::new(
            database,
            PUBLIC_BASE_URL.parse::<Origin>()?,
        ))
    }

    /// The operator running this command, recorded with every change it makes.
    /// Attribution is best effort: break-glass commands must work in a bare
    /// container, so an unknown user or host is recorded as such, not refused.
    fn operator() -> Actor {
        let os_user = OPERATOR_USER
            .optional()
            .ok()
            .flatten()
            .or_else(|| OPERATOR_LOGNAME.optional().ok().flatten())
            .unwrap_or_else(|| UNKNOWN_OPERATOR.into());
        let host = std::fs::read_to_string(HOSTNAME_PATH)
            .map_or_else(|_| UNKNOWN_OPERATOR.into(), |host| host.trim().to_owned());
        Actor::Cli { os_user, host }
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
    async fn purge_expired_state(database: Database) {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            let deadline = tokio::time::Instant::now() + CLEANUP_BUDGET;
            loop {
                match database.purge_expired_auth_state(CLEANUP_BATCH_SIZE).await {
                    Ok(0) => break,
                    Ok(_) if tokio::time::Instant::now() >= deadline => {
                        tracing::warn!("expired authentication state cleanup is falling behind");
                        break;
                    }
                    Ok(_) => tokio::time::sleep(CLEANUP_PAUSE).await,
                    Err(error) => {
                        tracing::error!(?error, "expired authentication state cleanup failed");
                        break;
                    }
                }
            }
        }
    }

    /// Builds the configured service, starts cleanup and serves until a shutdown signal.
    async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let listener = tokio::net::TcpListener::bind(config.public_listener).await?;
        let router = config.router(database.clone()).await?;
        let cleanup = tokio::spawn(Self::purge_expired_state(database));
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(Self::shutdown_signal())
        .await;
        cleanup.abort();
        Ok(result?)
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
