//! What administrative commands share: the service and its operator, where they
//! print, and confirmation before changes that cut off a whole account,
//! administrator or client.

use super::{CliError, output::Output};
use crate::{
    AdminService, AuthConfig, Operator, UserRef, account::AccountService, admin::OperatorName,
};
use clap::Args;
use sourceorigin_common::{UserId, config::ConfigurationError};
use sourceorigin_repository::Database;
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
    /// Where they print.
    pub(super) out: Output,
}

impl Console {
    /// Runs operations on `database` as the operator at this terminal: `name`,
    /// given by `--operator`, or the one the environment names. Prints to `out`.
    pub(super) fn new(
        database: Database,
        name: Option<OperatorName>,
        out: Output,
    ) -> Result<Self, CliError> {
        Ok(Self {
            service: AdminService::new(database.clone(), AuthConfig::mails_from_environment()?),
            account: AccountService::new(database),
            operator: Self::operator(name, OperatorName::from_environment)?,
            out,
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
    /// Describes `change` on `out` and asks to go ahead when standard input is a
    /// terminal. Without one, refuses unless `--yes` was given, so a script never
    /// runs a change it did not mean to.
    pub(super) fn ask(&self, out: &Output, change: &str) -> Result<(), CliError> {
        let input = std::io::stdin();
        self.ask_on(out, change, input.is_terminal(), input.lock())
    }

    /// [`Self::ask`], reading the answer from `input`, which is a terminal or not.
    pub(super) fn ask_on(
        &self,
        out: &Output,
        change: &str,
        terminal: bool,
        input: impl BufRead,
    ) -> Result<(), CliError> {
        if self.yes {
            return Ok(());
        }
        if !terminal {
            return Err(CliError::Unconfirmed);
        }
        if out.ask(change, input)? {
            Ok(())
        } else {
            Err(CliError::Declined)
        }
    }
}
