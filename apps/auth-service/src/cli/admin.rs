//! Granting, revoking and listing administrators.

use super::CliError;
use crate::{AdminService, Operator};
use clap::Subcommand;

/// Changes to the administrator list. The CLI may act on any account, and is how
/// the first administrator is granted.
#[derive(Subcommand)]
pub(super) enum AdminCommand {
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
    pub(super) async fn run(self, admin: &AdminService) -> Result<(), CliError> {
        let operator = Operator::terminal()?;
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
