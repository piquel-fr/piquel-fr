//! Signup invitations.

use super::{
    CliError, Console,
    output::{Cell, Single, report},
};
use crate::{AuthConfig, InviteExpiry, Reason};
use clap::Subcommand;
use sourceorigin_common::{
    TokenId,
    admin::{Invitation, InvitationSent},
    email::NormalizedEmail,
};

/// Creating, listing, resending and revoking single-use signup links, whatever
/// the signup setting: while signup is open, an invitation is a tracked signup
/// link.
#[derive(Subcommand)]
pub(super) enum InviteCommand {
    /// Create a single-use signup link. With --email, Origin Auth mails it there
    /// and prints the invitation's ID. Without, it prints the link, only this
    /// once: only its digest is stored.
    Create {
        /// Mail the link to this address, which the account created with it
        /// starts with, verified. Needs email enabled (`AUTH_SMTP_URL`).
        #[arg(long, value_parser = NormalizedEmail::parse)]
        email: Option<NormalizedEmail>,
        /// How long the link stays valid, e.g. 24h or 7d.
        #[arg(long, default_value = "7d")]
        expires_in: InviteExpiry,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// List invitations, newest first, without their links.
    List,
    /// Mail an open invitation's link again, to the address it was mailed to. Its
    /// expiry stays the same.
    Resend {
        /// The invitation's ID, as `invite list` shows it.
        id: TokenId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
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
            Self::Create {
                email,
                expires_in,
                reason,
            } => {
                let links = AuthConfig::invitation_links_from_environment()?;
                let invitation = service
                    .create_invitation(operator, &links, expires_in, email, reason)
                    .await?;
                match invitation.sent {
                    InvitationSent::Link(link) => out.emit(&Single {
                        name: "link",
                        value: link,
                    })?,
                    InvitationSent::Mailed(email) => {
                        out.emit(&Single {
                            name: "id",
                            value: invitation.id,
                        })?;
                        out.info(format_args!("Mailed the invitation to {email}."))?;
                    }
                }
            }
            Self::List => out.emit(&service.list_invitations(operator).await?[..])?,
            Self::Resend { id, reason } => {
                service.resend_invitation(operator, id, reason).await?;
                out.info(format_args!("Mailed invitation {id} again."))?;
            }
            Self::Revoke { id, reason } => {
                service.revoke_invitation(operator, id, reason).await?;
                out.info(format_args!("Revoked invitation {id}."))?;
            }
        }
        Ok(())
    }
}

// One invitation per line, newest first, with the address it was mailed to, if
// any, and without its link.
report!([Invitation], self, out, {
    out.table(
        ["ID", "EMAIL", "CREATED", "EXPIRES", "REDEEMED", "REVOKED"],
        "No invitations.",
        self.iter().map(|invitation| {
            [
                Cell::new(invitation.id),
                invitation.email.as_deref().into(),
                invitation.created_at.into(),
                invitation.expires_at.into(),
                invitation.redeemed_at.into(),
                invitation.revoked_at.into(),
            ]
        }),
    )
});
