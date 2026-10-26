//! Granting, revoking and listing administrators.

use super::{CliError, Confirm, Console, Output};
use crate::UserRef;
use clap::Subcommand;

/// Changes to the administrator list. The CLI may act on any account, and is how
/// the first administrator is granted.
#[derive(Subcommand)]
pub(super) enum AdminCommand {
    /// Make an active account an administrator.
    ///
    /// Refuses while a recovery of the account can still be undone: granted
    /// during its probation, the rights would go live for whoever used its link
    /// once it settles.
    Grant {
        /// The account: its username, ID or verified email.
        user: UserRef,
    },
    /// Remove an account's administrator rights. The last administrator keeps theirs.
    Revoke {
        /// The account: its username, ID or verified email.
        user: UserRef,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// List administrators, oldest grant first.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
}

impl AdminCommand {
    /// Runs the change as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::Grant { user } => {
                let user = console.user(&user).await?;
                service.grant_administrator(operator, user).await?;
            }
            Self::Revoke { user, confirm } => {
                let id = console.user(&user).await?;
                confirm.ask(&format!("Remove the administrator rights of {user} ({id})"))?;
                service.revoke_administrator(operator, id).await?;
            }
            Self::List { output } => {
                output.print(
                    &service.list_administrators(operator).await?,
                    |administrators| {
                        println!("USERNAME\tID\tGRANTED");
                        for administrator in administrators {
                            println!(
                                "{}\t{}\t{}",
                                administrator.username,
                                administrator.user_id,
                                administrator.granted_at.to_rfc3339()
                            );
                        }
                    },
                )?;
            }
        }
        Ok(())
    }
}
