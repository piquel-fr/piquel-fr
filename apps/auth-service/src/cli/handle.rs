//! Checking accounts' handles against the handle rules, changing them, and the
//! handles kept from others: released ones and reserved ones.

use super::{
    CliError, Confirm, Console,
    output::{Cell, Style, report},
};
use crate::{HandleProblem, Reason, UserRef};
use clap::Subcommand;
use serde::Serialize;
use sourceorigin_common::{
    Handle,
    admin::{ReleasedHandle, ReservedHandle},
    handle::RESERVED,
};

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
        /// Why, recorded with the change and shown to the owner in their history:
        /// 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Allow a reserved name, or one that looks like it.
        #[arg(long)]
        allow_reserved: bool,
    },
    /// Delete a released handle, or a purged account's last one, so anyone may
    /// claim it again, e.g. after a trademark dispute. An account's current handle is
    /// never released: rename the account first. Asks first.
    Release {
        /// The released handle.
        #[arg(value_parser = Handle::parse)]
        handle: Handle,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
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
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
}

impl HandleCommand {
    /// Runs the check, or the change as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::Check => out.emit(&service.check_handles(operator).await?[..])?,
            Self::Rename {
                user,
                new,
                reason,
                allow_reserved,
            } => {
                let id = console.user(&user).await?;
                service
                    .rename_handle(operator, id, new.clone(), reason, allow_reserved)
                    .await?;
                out.info(format_args!("Renamed {user} to @{new}."))?;
            }
            Self::Release {
                handle,
                reason,
                confirm,
            } => {
                confirm.ask(
                    out,
                    &format!(
                        "Release @{handle}: anyone may claim it, and it is no longer kept for the account that held it"
                    ),
                )?;
                service
                    .release_handle(operator, handle.clone(), reason)
                    .await?;
                out.info(format_args!("Released @{handle}: anyone may claim it."))?;
            }
            Self::Released => out.emit(&service.list_released_handles(operator).await?[..])?,
            Self::Reserved => out.emit(&Reserved {
                reserved: service.list_reserved_handles(operator).await?,
                built_in: RESERVED,
            })?,
            Self::Reserve { handle, reason } => {
                service
                    .reserve_handle(operator, handle.clone(), reason)
                    .await?;
                out.info(format_args!("Reserved @{handle}."))?;
            }
            Self::Unreserve { handle, reason } => {
                service
                    .unreserve_handle(operator, handle.clone(), reason)
                    .await?;
                out.info(format_args!("Unreserved @{handle}: anyone may claim it."))?;
            }
        }
        Ok(())
    }
}

/// The reserved handles: those administrators reserved, then the built-in names.
#[derive(Serialize)]
struct Reserved {
    /// Those administrators reserved.
    reserved: Vec<ReservedHandle>,
    /// The built-in names.
    built_in: &'static [&'static str],
}

// One account per line whose handle the rules refuse, with why.
report!([HandleProblem], self, out, {
    out.table(
        ["HANDLE", "ACCOUNT", "PROBLEM"],
        "Every handle follows the rules.",
        self.iter().map(|problem| {
            [
                Cell::new(&problem.handle),
                Cell::new(problem.user_id),
                Cell::new(&problem.error).style(Style::Bad),
            ]
        }),
    )
});

// One released handle per line, with the account that held it.
report!([ReleasedHandle], self, out, {
    out.table(
        ["HANDLE", "ACCOUNT", "RELEASED"],
        "No released handles.",
        self.iter().map(|released| {
            [
                Cell::new(&released.handle),
                released
                    .user_id
                    .map_or_else(|| Cell::new("purged").style(Style::Muted), Cell::new),
                released.released_at.into(),
            ]
        }),
    )
});

// One reserved handle per line, those administrators reserved first.
report!(Reserved, self, out, {
    let reserved = self.reserved.iter().map(|reserved| {
        [
            Cell::new(&reserved.handle),
            reserved.reserved_at.into(),
            Cell::new(&reserved.reason),
        ]
    });
    let built_in = self.built_in.iter().map(|name| {
        [
            Cell::new(name),
            Cell::new("built-in").style(Style::Muted),
            Cell::none(),
        ]
    });
    out.table(
        ["HANDLE", "RESERVED", "REASON"],
        "",
        reserved.chain(built_in),
    )
});
