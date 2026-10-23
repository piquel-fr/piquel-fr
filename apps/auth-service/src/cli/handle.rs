//! Checking accounts against the handle rules, and changing their handles.

use super::CliError;
use crate::{AdminError, AdminService, Operator};
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
        /// The account's current handle.
        handle: String,
        /// Its new handle.
        new: String,
        /// Allow a reserved name, or one that looks like it.
        #[arg(long)]
        allow_reserved: bool,
    },
}

impl HandleCommand {
    /// Runs the check, or the change as the operator at this terminal.
    pub(super) async fn run(self, admin: &AdminService) -> Result<(), CliError> {
        match self {
            Self::Check => {
                let problems = admin.check_handles().await?;
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
                handle,
                new,
                allow_reserved,
            } => {
                let user = admin.user_named(&handle).await?;
                let new = Handle::parse(&new).map_err(AdminError::from)?;
                admin
                    .rename_handle(&Operator::terminal()?, user, new, allow_reserved)
                    .await?;
            }
        }
        Ok(())
    }
}
