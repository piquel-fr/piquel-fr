//! Checking accounts against the handle rules, and changing their handles.

use super::{CliError, Console};
use crate::{AdminError, UserRef};
use clap::Subcommand;
use piquel_common::Handle;

/// Handle checks and changes. The CLI may act on any account.
#[derive(Subcommand)]
pub(super) enum HandleCommand {
    /// List accounts whose handle breaks the syntax, is reserved, or looks like
    /// another account's. Fails while any remain.
    Check,
    /// Give an account a new handle, and record the change.
    Rename {
        /// The account: its current handle, ID or verified email.
        user: UserRef,
        /// Its new handle.
        new: String,
        /// Allow a reserved name, or one that looks like it.
        #[arg(long)]
        allow_reserved: bool,
    },
}

impl HandleCommand {
    /// Runs the check, or the change as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::Check => {
                let problems = service.check_handles().await?;
                for problem in &problems {
                    println!(
                        "{}\t{}\t{}",
                        problem.username, problem.user_id, problem.issue
                    );
                }
                if !problems.is_empty() {
                    return Err(CliError::HandleProblems(problems.len()));
                }
            }
            Self::Rename {
                user,
                new,
                allow_reserved,
            } => {
                let user = console.user(&user).await?;
                let new = Handle::parse(&new).map_err(AdminError::from)?;
                service
                    .rename_handle(operator, user, new, allow_reserved)
                    .await?;
            }
        }
        Ok(())
    }
}
