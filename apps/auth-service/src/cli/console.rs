//! What administrative commands share: the service and its operator, output
//! formats, and confirmation before changes that cut off a whole account,
//! administrator or client.

use super::CliError;
use crate::{
    AdminService, AuthConfig, Operator, UserRef, account::AccountService, admin::OperatorName,
};
use clap::{Args, ValueEnum};
use sourceorigin_common::{UserId, admin::Paging, config::ConfigurationError};
use sourceorigin_repository::Database;
use serde::Serialize;
use std::io::{BufRead, IsTerminal};

/// Administrative commands' view of auth: every operation, run by the operator at
/// this terminal.
pub(super) struct Console {
    /// Every administrative operation.
    pub(super) service: AdminService,
    /// Every shared settings operation, run on an account as its owner would.
    pub(super) account: AccountService,
    /// Who runs them, recorded on their events.
    pub(super) operator: Operator,
}

impl Console {
    /// Runs operations on `database` as the operator at this terminal: `name`,
    /// given by `--operator`, or the one the environment names.
    pub(super) fn new(database: Database, name: Option<OperatorName>) -> Result<Self, CliError> {
        Ok(Self {
            service: AdminService::new(database.clone(), AuthConfig::mails_from_environment()?),
            account: AccountService::new(database),
            operator: Self::operator(name, OperatorName::from_environment)?,
        })
    }

    /// The operator at this terminal: `given` by `--operator`, else the one
    /// `environment` names. Refuses when neither names one, so nothing is
    /// recorded as an unknown operator's.
    pub(super) fn operator(
        given: Option<OperatorName>,
        environment: impl FnOnce() -> Result<Option<OperatorName>, ConfigurationError>,
    ) -> Result<Operator, CliError> {
        let name = match given {
            Some(name) => name,
            None => environment()?.ok_or(CliError::UnknownOperator)?,
        };
        Ok(Operator::terminal(name)?)
    }

    /// The account `user` names. A failure names the reference, as given.
    pub(super) async fn user(&self, user: &UserRef) -> Result<UserId, CliError> {
        self.service
            .find_user(&self.operator, user)
            .await
            .map_err(|source| CliError::User {
                user: user.clone(),
                source,
            })
    }
}

/// How a read command prints its results.
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum OutputFormat {
    /// Tab-separated lines for people.
    Table,
    /// The view the admin dashboard shows, as JSON, for scripts: its shape is
    /// `sourceorigin_common`'s, as its `admin` and `alerts` modules define it.
    Json,
}

/// The `--output` option of read commands.
#[derive(Args)]
pub(super) struct Output {
    /// A table for people, or JSON for scripts.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    output: OutputFormat,
}

impl Output {
    /// Prints `value` as pretty JSON, or as `table` writes it for people.
    pub(super) fn print<T: Serialize + ?Sized>(
        &self,
        value: &T,
        table: impl FnOnce(&T),
    ) -> Result<(), CliError> {
        match self.output {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
            OutputFormat::Table => table(value),
        }
        Ok(())
    }

    /// Says where a page of `what` stands, and how to go on, after a table.
    pub(super) fn paging(paging: Paging, what: &str) {
        eprintln!(
            "Page {} of {}: {} {what} in all.{}",
            paging.page,
            paging.pages,
            paging.total,
            paging
                .next()
                .map(|next| format!(" Next: --page {next}"))
                .unwrap_or_default()
        );
    }
}

/// The `--yes` option of commands that cut off a whole account, administrator or
/// client. Ending one session does not ask: the command names it exactly, and its
/// owner can sign in again.
#[derive(Args)]
pub(super) struct Confirm {
    /// Do not ask for confirmation. Required when standard input is not a terminal.
    #[arg(long)]
    pub(super) yes: bool,
}

impl Confirm {
    /// Describes `change` and asks to go ahead when standard input is a terminal.
    /// Without one, refuses unless `--yes` was given, so a script never runs a
    /// change it did not mean to.
    pub(super) fn ask(&self, change: &str) -> Result<(), CliError> {
        let input = std::io::stdin();
        self.ask_on(change, input.is_terminal(), input.lock())
    }

    /// [`Self::ask`], reading the answer from `input`, which is a terminal or not.
    pub(super) fn ask_on(
        &self,
        change: &str,
        terminal: bool,
        mut input: impl BufRead,
    ) -> Result<(), CliError> {
        if self.yes {
            return Ok(());
        }
        if !terminal {
            return Err(CliError::Unconfirmed);
        }
        eprint!("{change}. Continue? [y/N] ");
        let mut answer = String::new();
        input.read_line(&mut answer).map_err(CliError::Prompt)?;
        match answer.trim() {
            "y" | "Y" | "yes" => Ok(()),
            _ => Err(CliError::Declined),
        }
    }
}
