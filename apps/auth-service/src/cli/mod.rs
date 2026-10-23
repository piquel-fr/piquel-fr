//! The `auth-service` command line: serving, migrations and break-glass
//! administration. Administrative commands need only the database, so they work
//! while the service is down, and run through [`AdminService`] like the admin API.

/// Granting, revoking and listing administrators.
mod admin;
/// Registering, inspecting and changing OIDC clients.
mod client;
/// The outbound delivery queue.
mod deliveries;
/// Command failures.
mod error;
/// Checking and changing handles.
mod handle;
/// Serving the public and admin listeners.
mod serve;

use crate::{
    AdminService, AuthConfig, InviteExpiry, Operator, PUBLIC_BASE_URL, SERVICE_NAME,
    TELEMETRY_FILTER,
};
use admin::AdminCommand;
use clap::{Parser, Subcommand, ValueEnum};
use client::ClientCommand;
use deliveries::DeliveriesCommand;
use error::CliError;
use handle::HandleCommand;
use piquel_common::ErrorChain;
use piquel_repository::Database;
use piquel_telemetry::Telemetry;
use std::process::ExitCode;

/// Piquel authentication service. Runs `serve` when no command is given.
#[derive(Parser)]
#[command(
    after_help = "Every command uses AUTH_DATABASE_URL, except migrate when AUTH_DATABASE_OWNER_URL is \
                  set. See README.md for configuration."
)]
pub struct Cli {
    /// Defaults to serving when no administrative command is supplied.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Commands, each of which connects to the database first.
#[derive(Subcommand)]
enum Command {
    /// Serve the authentication service.
    Serve,
    /// Apply database migrations. Connected as the schema owner, also create or
    /// reset the role other commands connect as.
    Migrate,
    /// Print a single-use signup link.
    Invite {
        /// How long the link stays valid, in hours or days (e.g. 24h, 7d).
        #[arg(long, default_value = "7d")]
        expires_in: InviteExpiry,
    },
    /// Register, inspect and change OIDC clients. Changes apply to the next request.
    #[command(subcommand)]
    Client(Box<ClientCommand>),
    /// Inspect, retry and cancel outbound deliveries.
    #[command(subcommand)]
    Deliveries(DeliveriesCommand),
    /// Grant, revoke or list administrators.
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Check accounts against the handle rules, and change their handles.
    #[command(subcommand)]
    Handle(HandleCommand),
}

/// How list commands print their results.
#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// One tab-separated line per item.
    Table,
    /// A JSON array.
    Json,
}

impl Command {
    /// Executes this command and returns the original startup or operation failure.
    async fn run(self) -> Result<(), CliError> {
        // `migrate` connects as the schema owner when one is configured, then
        // provisions the role every other command connects as.
        let (config, runtime_role) = match self {
            Self::Migrate => AuthConfig::migration_from_environment()?,
            _ => (AuthConfig::database_from_environment()?, None),
        };
        let database = Database::connect(config).await?;
        match self {
            Self::Serve => Self::serve(database).await,
            Self::Migrate => {
                database.run_migrations().await?;
                if let Some(role) = runtime_role {
                    database.provision(&role).await?;
                }
                Ok(())
            }
            Self::Invite { expires_in } => {
                // Only the secret's digest is stored, so the link is printed once.
                let invitation = AdminService::new(database)
                    .create_invitation(
                        &Operator::terminal()?,
                        &PUBLIC_BASE_URL.parse()?,
                        expires_in,
                    )
                    .await?;
                println!("{}", invitation.url);
                Ok(())
            }
            Self::Client(command) => command.run(database).await,
            // The rest need only the database, for a bare recovery shell.
            Self::Deliveries(command) => command.run(&AdminService::new(database)).await,
            Self::Admin(command) => command.run(&AdminService::new(database)).await,
            Self::Handle(command) => command.run(&AdminService::new(database)).await,
        }
    }
}

impl Cli {
    /// Installs telemetry, runs the selected command, then flushes telemetry, and
    /// prints any failure with its causes. A failed flush, such as an unreachable
    /// collector, is only reported: it must not fail a command, such as a deploy's
    /// migration job.
    pub async fn run(self) -> ExitCode {
        let result = async {
            let telemetry = Telemetry::init(SERVICE_NAME, TELEMETRY_FILTER)?;
            let result = self.command.unwrap_or(Command::Serve).run().await;
            if let Err(error) = telemetry.shutdown().await {
                eprintln!("warning: {}", ErrorChain(&error));
            }
            result
        };
        match result.await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {}", ErrorChain(&error));
                ExitCode::FAILURE
            }
        }
    }
}
