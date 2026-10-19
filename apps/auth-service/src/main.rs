//! Authentication service and its administrative CLI.
use auth_service::{
    AdminError, AdminOperations, AuthConfig, InviteExpiry, Jobs, Operator, PUBLIC_BASE_URL,
};
use clap::{Parser, Subcommand};
use piquel_common::{
    DeliveryId, ErrorChain,
    config::{ConfigurationError, Variable},
};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{Database, DatabaseConnectionError, DatabaseError, DeliveryStatus};
use thiserror::Error;

use axum::Router;
use std::{net::SocketAddr, process::ExitCode};
use tokio::{net::TcpListener, sync::watch};

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
    /// No delivery with this ID is in a state the command applies to.
    #[error("no {states} delivery has ID {id}")]
    NoSuchDelivery {
        /// The requested delivery.
        id: DeliveryId,
        /// The states the command applies to.
        states: &'static str,
    },
    /// An administrative operation was refused or failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
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
    /// Inspect, retry and cancel outbound deliveries.
    #[command(subcommand)]
    Deliveries(DeliveriesCommand),
    /// Grant, revoke or list administrators.
    #[command(subcommand)]
    Admin(AdminCommand),
}

/// Changes to the administrator list. The CLI may act on any account, and is how
/// the first administrator is granted.
#[derive(Subcommand)]
enum AdminCommand {
    /// Make an active account an administrator.
    Grant {
        /// The account's username.
        username: String,
    },
    /// Remove an account's administrator rights. The last administrator keeps theirs.
    Revoke {
        /// The account's username.
        username: String,
    },
    /// List administrators, oldest grant first.
    List,
}

impl AdminCommand {
    /// Runs the change as the operator at this terminal.
    async fn run(self, admin: &AdminOperations) -> Result<(), CliError> {
        let operator = DatabaseCommand::operator()?;
        match self {
            Self::Grant { username } => {
                let user = admin.user_named(&username).await?;
                admin.grant_administrator(&operator, user).await?;
            }
            Self::Revoke { username } => {
                let user = admin.user_named(&username).await?;
                admin.revoke_administrator(&operator, user).await?;
            }
            Self::List => {
                for administrator in admin.list_administrators().await? {
                    println!(
                        "{}\t{}\t{}",
                        administrator.username,
                        administrator.user_id,
                        administrator.granted_at.to_rfc3339()
                    );
                }
            }
        }
        Ok(())
    }
}

impl DatabaseCommand {
    /// Executes this command and returns the original startup or operation failure.
    async fn run(self) -> Result<(), CliError> {
        let database = Database::connect(AuthConfig::database_from_environment()?).await?;
        match self {
            Self::Serve => Self::serve(database).await,
            Self::Migrate => Ok(database.run_migrations().await?),
            Self::Invite { expires_in } => {
                // Only the secret's digest is stored, so the link is printed once.
                let invitation = AdminOperations::new(database)
                    .create_invitation(&Self::operator()?, &PUBLIC_BASE_URL.parse()?, expires_in)
                    .await?;
                println!("{}", invitation.url);
                Ok(())
            }
            Self::Deliveries(command) => command.run(&database).await,
            // Grant, revoke and list need only the database, for a bare recovery shell.
            Self::Admin(command) => command.run(&AdminOperations::new(database)).await,
        }
    }

    /// The operator running a command: `$USER` and the host name, or `unknown` where
    /// they cannot be read, as in some containers.
    fn operator() -> Result<Operator, CliError> {
        let host = std::fs::read_to_string(HOST_NAME_FILE)
            .ok()
            .map(|host| host.trim().to_owned())
            .or(HOST_NAME.optional()?)
            .filter(|host| !host.is_empty());
        Ok(Operator::Cli {
            os_user: OS_USER
                .optional()?
                .unwrap_or_else(|| UNKNOWN_OPERATOR.to_owned()),
            host: host.unwrap_or_else(|| UNKNOWN_OPERATOR.to_owned()),
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
    /// serves the public listener, and the admin listener when one is configured,
    /// until a shutdown signal. Once in-flight requests drain, running jobs get a
    /// grace period to finish.
    async fn serve(database: Database) -> Result<(), CliError> {
        let config = AuthConfig::from_environment()?;
        let public = TcpListener::bind(config.public_listener).await?;
        let admin = match config.admin_listener {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let router = config.router(database.clone())?;
        let admin_router = config.admin_router(database.clone());
        config.provision_clients(&database).await?;
        let jobs = Jobs::start(&database);
        tracing::info!(address=%config.public_listener,"authentication service listening");
        let (stop, _) = watch::channel(false);
        let admin = async {
            let Some(listener) = admin else {
                return Ok(());
            };
            tracing::info!(address=%listener.local_addr()?, "admin API listening");
            Self::listen(listener, admin_router, &stop).await
        };
        let signal = async {
            let mut stopped = stop.subscribe();
            tokio::select! {
                () = Self::shutdown_signal() => {
                    stop.send_replace(true);
                }
                _ = stopped.wait_for(|stopped| *stopped) => {}
            }
        };
        let (public, admin, ()) = tokio::join!(Self::listen(public, router, &stop), admin, signal);
        let jobs = jobs.shutdown().await;
        public?;
        admin?;
        Ok(jobs?)
    }

    /// Serves `router` on `listener` until `stop` is set. Once this listener ends,
    /// whatever the reason, it sets `stop`, so the other listener ends too.
    async fn listen(
        listener: TcpListener,
        router: Router,
        stop: &watch::Sender<bool>,
    ) -> std::io::Result<()> {
        let mut stopped = stop.subscribe();
        let result = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            // Fails only once `stop` is dropped, which also means stopping.
            let _ = stopped.wait_for(|stopped| *stopped).await;
        })
        .await;
        stop.send_replace(true);
        result
    }
}

/// The break-glass view of the outbound delivery queue.
#[derive(Subcommand)]
enum DeliveriesCommand {
    /// List deliveries, newest first.
    List {
        /// Only deliveries with this status: pending, succeeded, failed or cancelled.
        #[arg(long)]
        status: Option<DeliveryStatus>,
        /// Only deliveries on this channel.
        #[arg(long)]
        channel: Option<String>,
        /// The most deliveries to list.
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Attempt a failed delivery, or a cancelled unordered one, again now.
    Retry {
        /// The delivery's ID.
        id: DeliveryId,
    },
    /// Cancel a pending or failed delivery, which unblocks the deliveries ordered after it.
    Cancel {
        /// The delivery's ID.
        id: DeliveryId,
    },
}

impl DeliveriesCommand {
    /// Runs this command on `database`.
    async fn run(self, database: &Database) -> Result<(), CliError> {
        let (id, states, result) = match self {
            Self::List {
                status,
                channel,
                limit,
            } => {
                let deliveries = database
                    .deliveries()
                    .list(status, channel.as_deref(), limit)
                    .await?;
                println!(
                    "ID\tCHANNEL\tSTATUS\tATTEMPTS\tORDER\tDUE OR FINISHED\tLAST ERROR\tDESTINATION"
                );
                for delivery in deliveries {
                    let order = delivery.ordering.map_or_else(
                        || "-".to_owned(),
                        |(key, ordinal)| format!("{key}#{ordinal}"),
                    );
                    println!(
                        "{}\t{}\t{}\t{}\t{order}\t{}\t{}\t{}",
                        delivery.id,
                        delivery.channel,
                        delivery.status,
                        delivery.attempts,
                        delivery.finished_at.unwrap_or(delivery.next_attempt_at),
                        delivery.last_error.as_deref().unwrap_or("-"),
                        delivery.destination,
                    );
                }
                return Ok(());
            }
            Self::Retry { id } => (
                id,
                "failed or cancelled unordered",
                database.deliveries().retry(id).await,
            ),
            Self::Cancel { id } => (
                id,
                "pending or failed",
                database.deliveries().cancel(id).await,
            ),
        };
        match result {
            Err(DatabaseError::NotFound) => Err(CliError::NoSuchDelivery { id, states }),
            result => Ok(result?),
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
