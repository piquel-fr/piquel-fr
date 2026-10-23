//! The `auth-service` command line: serving, migrations and break-glass
//! administration. Administrative commands need only the database, so they work
//! while the service is down, and run through [`AdminService`](crate::AdminService)
//! like the admin API: every `AdminOperation` has a command, which a test checks
//! exhaustively.

/// Granting, revoking and listing administrators.
mod admin;
/// The audit history.
mod audit;
/// Registering, inspecting and changing OIDC clients.
mod client;
/// The service and operator, output formats and confirmation.
mod console;
/// The outbound delivery queue.
mod deliveries;
/// Command failures.
mod error;
/// Checking and changing handles.
mod handle;
/// Signup invitations.
mod invite;
/// Serving the public and admin listeners.
mod serve;
/// Ending sessions.
mod session;
/// Finding, showing, disabling and reactivating accounts.
mod user;

use crate::{AuthConfig, SERVICE_NAME, TELEMETRY_FILTER};
use admin::AdminCommand;
use audit::AuditCommand;
use clap::{Parser, Subcommand};
use client::ClientCommand;
use console::{Confirm, Console, Output};
use deliveries::DeliveriesCommand;
use error::CliError;
use handle::HandleCommand;
use invite::InviteCommand;
use piquel_common::ErrorChain;
use piquel_repository::Database;
use piquel_telemetry::Telemetry;
use session::SessionCommand;
use std::process::ExitCode;
use user::UserCommand;

/// Piquel authentication service. Runs `serve` when no command is given.
#[derive(Parser)]
#[command(
    after_help = "Every command uses AUTH_DATABASE_URL, except migrate when AUTH_DATABASE_OWNER_URL is \
                  set. See README.md for configuration and administration."
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
    /// Administrative commands.
    #[command(flatten)]
    Administration(Administration),
}

/// Administrative commands. They record what they change as the operator at this
/// terminal: `$USER` and the host name.
#[derive(Subcommand)]
enum Administration {
    /// Search, show, disable and reactivate accounts.
    #[command(subcommand)]
    User(UserCommand),
    /// End an account's sessions.
    #[command(subcommand)]
    Session(SessionCommand),
    /// Create, list and revoke signup invitations.
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Register, inspect and change OIDC clients. Changes apply to the next request.
    #[command(subcommand)]
    Client(Box<ClientCommand>),
    /// Page through the audit history, newest first.
    Audit(AuditCommand),
    /// Grant, revoke or list administrators.
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Check accounts against the handle rules, and change their handles.
    #[command(subcommand)]
    Handle(HandleCommand),
    /// Inspect, retry and cancel outbound deliveries.
    #[command(subcommand)]
    Deliveries(DeliveriesCommand),
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
            Self::Administration(command) => command.run(&Console::new(database)?).await,
        }
    }
}

impl Administration {
    /// Runs this command through `console`.
    async fn run(self, console: &Console) -> Result<(), CliError> {
        match self {
            Self::User(command) => command.run(console).await,
            Self::Session(command) => command.run(console).await,
            Self::Invite(command) => command.run(console).await,
            Self::Client(command) => command.run(console).await,
            Self::Audit(command) => command.run(console).await,
            Self::Admin(command) => command.run(console).await,
            Self::Handle(command) => command.run(console).await,
            Self::Deliveries(command) => command.run(console).await,
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

#[cfg(test)]
mod tests;
