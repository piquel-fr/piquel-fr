//! Checking accounts' handles against the handle rules, changing them, and the
//! handles kept from others: released ones and reserved ones.

use super::{CliError, Console};
use crate::{Reason, UserRef};
use clap::Subcommand;
use piquel_common::Handle;

/// Handle checks and changes. The CLI may act on any account.
#[derive(Subcommand)]
pub(super) enum HandleCommand {
    /// List accounts whose handle is reserved.
    Check,
    /// Give an account a new handle, without the settings cooldown, and record the
    /// change.
    Rename {
        /// The account: its current handle, ID or verified email.
        user: UserRef,
        /// Its new handle.
        #[arg(value_parser = Handle::parse)]
        new: Handle,
        /// Why, kept with the event as personal data: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Allow a reserved name, or one that looks like it.
        #[arg(long)]
        allow_reserved: bool,
    },
    /// Delete a released handle, or a purged account's last one, so anyone may
    /// claim it again, e.g. after a trademark dispute. An account's current handle is
    /// never released: rename the account first.
    Release {
        /// The released handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
    },
    /// List released handles and purged accounts' last ones, which `release` frees.
    Released,
    /// List the handles administrators reserved, then the built-in reserved names.
    Reserved,
    /// Reserve a handle: signup and the settings refuse it and its look-alikes until
    /// an administrator gives it with `rename --allow-reserved`, or `unreserve`s it.
    Reserve {
        /// The handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
        /// Who or what it is kept for: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// Remove a handle from the reserved list, so anyone may claim it again.
    Unreserve {
        /// The handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
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
                for problem in service.check_handles(operator).await? {
                    println!("{}\t{}\t{}", problem.handle, problem.user_id, problem.error);
                }
            }
            Self::Rename {
                user,
                new,
                reason,
                allow_reserved,
            } => {
                let user = console.user(&user).await?;
                service
                    .rename_handle(operator, user, new, reason, allow_reserved)
                    .await?;
            }
            Self::Release { handle } => service.release_handle(operator, handle).await?,
            Self::Released => {
                for released in service.list_released_handles(operator).await? {
                    let user = released
                        .user_id
                        .map_or_else(|| "purged".to_owned(), |user| user.to_string());
                    let at = released
                        .released_at
                        .map_or_else(|| "-".to_owned(), |at| at.to_rfc3339());
                    println!("{}\t{user}\t{at}", released.handle);
                }
            }
            Self::Reserved => {
                for reserved in service.list_reserved_handles(operator).await? {
                    println!(
                        "{}\t{}\t{}",
                        reserved.handle,
                        reserved.reserved_at.to_rfc3339(),
                        reserved.reason
                    );
                }
                for name in piquel_common::handle::RESERVED {
                    println!("{name}\tbuilt-in\t-");
                }
            }
            Self::Reserve { handle, reason } => {
                service.reserve_handle(operator, handle, reason).await?;
            }
            Self::Unreserve { handle } => service.unreserve_handle(operator, handle).await?,
        }
        Ok(())
    }
}
