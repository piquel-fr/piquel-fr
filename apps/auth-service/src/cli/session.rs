//! Signing accounts out.

use super::{CliError, Confirm, Console};
use crate::{Reason, UserRef};
use clap::Subcommand;
use sourceorigin_common::SessionId;

/// Ending sessions, with the refresh tokens their applications hold.
#[derive(Subcommand)]
pub(super) enum SessionCommand {
    /// End one session of an account and its applications' refresh tokens.
    Revoke {
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// The session's ID, as `user show` lists it. Another account's session is
        /// not found.
        session: SessionId,
        /// Why, recorded with the change and shown to the owner in their history:
        /// 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// End every session of an account and its applications' refresh tokens.
    RevokeAll {
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// Why, recorded with the change and shown to the owner in their history:
        /// 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

impl SessionCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::Revoke {
                user,
                session,
                reason,
            } => {
                let id = console.user(&user).await?;
                service
                    .revoke_session(operator, id, session, reason)
                    .await?;
            }
            Self::RevokeAll {
                user,
                reason,
                confirm,
            } => {
                let id = console.user(&user).await?;
                confirm.ask(&format!("Sign {user} ({id}) out everywhere"))?;
                service.revoke_user_sessions(operator, id, reason).await?;
            }
        }
        Ok(())
    }
}
