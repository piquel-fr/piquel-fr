//! The `auth-service` command line: serving, migrations and break-glass
//! administration. Administrative commands need only the database, so they work
//! while the service is down. They run through [`AdminService`](crate::AdminService)
//! like the admin API, and through [`AccountService`](crate::account::AccountService)
//! like the shared settings mounts. Every command names the [`Operation`] it runs,
//! and tests check that every operation has a command.

/// Changing one account's settings on its owner's behalf.
mod account;
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

use crate::{
    AuthConfig, SERVICE_NAME, TELEMETRY_FILTER, account::AccountOperation, admin::AdminOperation,
};
use account::AccountCommand;
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
use tracing::Instrument;
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
    /// Read or change one account's settings on its owner's behalf.
    Account(AccountCommand),
}

/// What an administrative command runs, recorded on its trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    /// An administrative operation.
    Admin(AdminOperation),
    /// A shared settings operation on one account.
    Account(AccountOperation),
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
    /// The operation this command runs. The match is exhaustive, so a new command
    /// does not compile until it names one.
    const fn operation(&self) -> Operation {
        type Op = AdminOperation;
        Operation::Admin(match self {
            Self::Account(command) => return Operation::Account(command.operation()),
            Self::User(command) => match command {
                UserCommand::Search { .. } => Op::SearchUsers,
                UserCommand::Show { .. } => Op::ViewUser,
                UserCommand::Disable { .. } => Op::DisableUser,
                UserCommand::Enable { .. } => Op::EnableUser,
            },
            Self::Session(command) => match command {
                SessionCommand::Revoke { .. } => Op::RevokeSession,
                SessionCommand::RevokeAll { .. } => Op::RevokeUserSessions,
            },
            Self::Invite(command) => match command {
                InviteCommand::Create { .. } => Op::CreateInvitation,
                InviteCommand::List { .. } => Op::ListInvitations,
                InviteCommand::Revoke { .. } => Op::RevokeInvitation,
            },
            Self::Client(command) => match **command {
                ClientCommand::Create(_) => Op::CreateClient,
                ClientCommand::Apply(_) => Op::ApplyClient,
                ClientCommand::List { .. } => Op::ListClients,
                ClientCommand::Show { .. } => Op::ViewClient,
                ClientCommand::Update(_) => Op::UpdateClient,
                ClientCommand::Disable { .. } => Op::DisableClient,
                ClientCommand::Delete { .. } => Op::DeleteClient,
                ClientCommand::Enable { .. } => Op::EnableClient,
                ClientCommand::Suspend { .. } => Op::SuspendClient,
                ClientCommand::Unsuspend { .. } => Op::UnsuspendClient,
                ClientCommand::RotateSecret { .. } => Op::RotateClientSecret,
            },
            Self::Audit(_) => Op::ListEvents,
            Self::Admin(command) => match command {
                AdminCommand::Grant { .. } => Op::GrantAdministrator,
                AdminCommand::Revoke { .. } => Op::RevokeAdministrator,
                AdminCommand::List { .. } => Op::ListAdministrators,
            },
            Self::Handle(command) => match command {
                HandleCommand::Check => Op::CheckHandles,
                HandleCommand::Rename { .. } => Op::RenameHandle,
            },
            Self::Deliveries(command) => match command {
                DeliveriesCommand::List { .. } => Op::ListDeliveries,
                DeliveriesCommand::Retry { .. } => Op::RetryDelivery,
                DeliveriesCommand::Cancel { .. } => Op::CancelDelivery,
            },
        })
    }

    /// Runs this command through `console`, in a span naming its operation, so
    /// its events and failures can be traced to it.
    async fn run(self, console: &Console) -> Result<(), CliError> {
        let span = tracing::info_span!("admin command", admin.operation = ?self.operation());
        self.dispatch(console).instrument(span).await
    }

    /// Runs this command's own code.
    async fn dispatch(self, console: &Console) -> Result<(), CliError> {
        match self {
            Self::User(command) => command.run(console).await,
            Self::Session(command) => command.run(console).await,
            Self::Invite(command) => command.run(console).await,
            Self::Client(command) => command.run(console).await,
            Self::Audit(command) => command.run(console).await,
            Self::Admin(command) => command.run(console).await,
            Self::Handle(command) => command.run(console).await,
            Self::Deliveries(command) => command.run(console).await,
            Self::Account(command) => command.run(console).await,
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
