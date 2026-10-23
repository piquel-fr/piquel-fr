//! Signup invitations.

use super::{CliError, Console, Output};
use crate::{InviteExpiry, PUBLIC_BASE_URL};
use clap::Subcommand;
use piquel_common::TokenId;

/// Creating, listing and revoking single-use signup links.
#[derive(Subcommand)]
pub(super) enum InviteCommand {
    /// Print a single-use signup link. Only its digest is stored, so it is shown
    /// only this once.
    Create {
        /// How long the link stays valid, e.g. 24h or 7d.
        #[arg(long, default_value = "7d")]
        expires_in: InviteExpiry,
    },
    /// List invitations, newest first, without their links.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Revoke an unredeemed invitation.
    Revoke {
        /// The invitation's ID, as `invite list` shows it.
        id: TokenId,
    },
}

impl InviteCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console { service, operator } = console;
        match self {
            Self::Create { expires_in } => {
                let invitation = service
                    .create_invitation(operator, &PUBLIC_BASE_URL.parse()?, expires_in)
                    .await?;
                println!("{}", invitation.url);
            }
            Self::List { output } => {
                output.print(&service.list_invitations().await?, |invitations| {
                    println!("ID\tCREATED\tEXPIRES\tREDEEMED\tREVOKED");
                    for invitation in invitations {
                        let time = |at: Option<chrono::DateTime<chrono::Utc>>| {
                            at.map_or_else(|| "-".to_owned(), |at| at.to_rfc3339())
                        };
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            invitation.id,
                            invitation.created_at.to_rfc3339(),
                            invitation.expires_at.to_rfc3339(),
                            time(invitation.redeemed_at),
                            time(invitation.revoked_at)
                        );
                    }
                })?;
            }
            Self::Revoke { id } => service.revoke_invitation(operator, id).await?,
        }
        Ok(())
    }
}
