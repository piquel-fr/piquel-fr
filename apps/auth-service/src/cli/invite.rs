//! Signup invitations.

use super::{
    CliError, Console,
    output::{Cell, Single, report},
};
use crate::{InviteExpiry, PUBLIC_BASE_URL, Reason};
use clap::Subcommand;
use sourceorigin_common::{TokenId, admin::Invitation};

/// Creating, listing and revoking single-use signup links.
#[derive(Subcommand)]
pub(super) enum InviteCommand {
    /// Print a single-use signup link. Only its digest is stored, so it is shown
    /// only this once.
    Create {
        /// How long the link stays valid, e.g. 24h or 7d.
        #[arg(long, default_value = "7d")]
        expires_in: InviteExpiry,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// List invitations, newest first, without their links.
    List,
    /// Revoke an unredeemed invitation.
    Revoke {
        /// The invitation's ID, as `invite list` shows it.
        id: TokenId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
}

impl InviteCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::Create { expires_in, reason } => {
                let invitation = service
                    .create_invitation(operator, &PUBLIC_BASE_URL.parse()?, expires_in, reason)
                    .await?;
                out.emit(&Single {
                    name: "link",
                    value: invitation.url,
                })?;
            }
            Self::List => out.emit(&service.list_invitations(operator).await?[..])?,
            Self::Revoke { id, reason } => {
                service.revoke_invitation(operator, id, reason).await?;
                out.info(format_args!("Revoked invitation {id}."))?;
            }
        }
        Ok(())
    }
}

// One invitation per line, newest first, without its link.
report!([Invitation], self, out, {
    out.table(
        ["ID", "CREATED", "EXPIRES", "REDEEMED", "REVOKED"],
        "No invitations.",
        self.iter().map(|invitation| {
            [
                Cell::new(invitation.id),
                invitation.created_at.into(),
                invitation.expires_at.into(),
                invitation.redeemed_at.into(),
                invitation.revoked_at.into(),
            ]
        }),
    )
});
