//! Finding, showing, disabling, reactivating and recovering accounts.

use super::{CliError, Confirm, Console, Output};
use crate::{
    AdminError, AuthConfig, Reason, UserRef,
    recovery::{ReviewedRecovery, WhileUndoable},
};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use piquel_admin_api::{UserDetail, UserPage};
use piquel_common::UserId;
use piquel_repository::Rollback;

/// Accounts, in any status.
#[derive(Subcommand)]
pub(super) enum UserCommand {
    /// Search accounts by ID, or by part of a username, display name or email,
    /// ignoring case. Lists 50 at a time, by ID.
    Search {
        /// What to look for. Lists every account when empty.
        #[arg(default_value = "")]
        query: String,
        /// Continue after this account ID, the last one listed.
        #[arg(long)]
        cursor: Option<UserId>,
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Show an account's profile, status, emails, passkeys, linked identities,
    /// sessions and consents. Recorded, since it shows personal data.
    Show {
        /// The account: its username, ID or verified email.
        user: UserRef,
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Disable an account and end its sessions and refresh tokens.
    Disable {
        /// The account: its username, ID or verified email.
        user: UserRef,
        /// Why, kept with the event as personal data: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Let a disabled account sign in again.
    Enable {
        /// The account: its username, ID or verified email.
        user: UserRef,
    },
    /// Recover an account whose owner lost every passkey (not usable yet).
    ///
    /// The recovery page its link opens comes with the server-rendered pages.
    /// First lists the account's recoveries of the last 30 days, with what each
    /// one that can still be undone added. Refuses while one can, unless
    /// `--despite-undoable`: review it, and undo it with `user undo-recovery`
    /// first. Refuses an administrator's account: revoke its rights first.
    /// Ends the account's sessions and sends its primary address a link that
    /// enrolls one passkey, within a day. Prints the link too, for an owner
    /// without an address. The owner can undo it with an older passkey, which
    /// takes back everything added since. Needs `AUTH_PUBLIC_BASE_URL` and the
    /// token digest key, which derives the link.
    Recover {
        /// The account: its username, ID or verified email.
        user: UserRef,
        /// Why, recorded with the recovery and shown to the owner in their
        /// history: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Start even though another recovery can still be undone, as when its
        /// own owner asks again.
        #[arg(long)]
        despite_undoable: bool,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Undo an account's newest recovery for its owner, once they are confirmed.
    ///
    /// For an owner with no passkey left from before it, after whoever used it
    /// added their own ways in. Lists what it takes back, then removes the
    /// passkeys, identities, consents and addresses added since it started,
    /// restores its primary address, and ends every session.
    UndoRecovery {
        /// The account: its username, ID or verified email.
        user: UserRef,
        /// Why, recorded with each change and shown to the owner in their
        /// history: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

impl UserCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::Search {
                query,
                cursor,
                output,
            } => output.print(
                &service.search_users(operator, &query, cursor).await?,
                Self::print_page,
            )?,
            Self::Show { user, output } => {
                let id = console.user(&user).await?;
                output.print(&service.view_user(operator, id).await?, Self::print_detail)?;
            }
            Self::Disable {
                user,
                reason,
                confirm,
            } => {
                let id = console.user(&user).await?;
                confirm.ask(&format!("Disable {user} ({id}) and end its sessions"))?;
                service.disable_user(operator, id, reason).await?;
            }
            Self::Enable { user } => {
                let id = console.user(&user).await?;
                service.enable_user(operator, id).await?;
            }
            Self::Recover {
                user,
                reason,
                despite_undoable,
                confirm,
            } => {
                let id = console.user(&user).await?;
                let links = AuthConfig::recovery_links_from_environment()?;
                Self::print_recent(&service.recent_recoveries(operator, id).await?);
                let while_undoable = if despite_undoable {
                    WhileUndoable::Proceed
                } else {
                    WhileUndoable::Refuse
                };
                confirm.ask(&format!(
                    "Recover {user} ({id}): end its sessions and send it a recovery link"
                ))?;
                if let Some(link) = service
                    .recover_account(operator, id, reason, &links, while_undoable)
                    .await?
                {
                    println!("{link}");
                }
                eprintln!(
                    "The link opens a page that is not available yet; it works once, for a day."
                );
            }
            Self::UndoRecovery {
                user,
                reason,
                confirm,
            } => {
                let id = console.user(&user).await?;
                let recent = service.recent_recoveries(operator, id).await?;
                Self::print_recent(&recent);
                let newest = recent
                    .iter()
                    .find(|reviewed| reviewed.rollback.is_some())
                    .ok_or(AdminError::NoRecoveryToUndo)?;
                let recovery = newest.recovery.id;
                confirm.ask(&format!(
                    "Undo recovery {recovery} of {user} ({id}): take back what it lists, and end its sessions"
                ))?;
                service
                    .undo_recovery(operator, id, recovery, reason)
                    .await?;
            }
        }
        Ok(())
    }

    /// Prints the account's recent recoveries, newest first, each followed by
    /// what undoing it would take back while it can be, before another is
    /// started or one is undone. On standard error, which leaves standard output
    /// to the new link.
    fn print_recent(recent: &[ReviewedRecovery]) {
        if recent.is_empty() {
            return;
        }
        eprintln!("RECOVERY\tSTARTED\tSTATE\tPASSKEY\tNAME\tACTIVE");
        for ReviewedRecovery { recovery, rollback } in recent {
            let at = |at: Option<DateTime<Utc>>| at.map(|at| at.to_rfc3339());
            let state = at(recovery.undone_at)
                .map(|at| format!("undone {at}"))
                .or_else(|| at(recovery.cancelled_at).map(|at| format!("replaced {at}")))
                .or_else(|| at(recovery.completed_at).map(|at| format!("used {at}")))
                .unwrap_or_else(|| "link not used".to_owned());
            let (passkey, name, active) = match &recovery.passkey {
                Some(passkey) => (
                    passkey.id.to_string(),
                    passkey.friendly_name.as_deref().unwrap_or("-"),
                    if passkey.active { "yes" } else { "no" },
                ),
                None => ("-".to_owned(), "-", "-"),
            };
            eprintln!(
                "{}\t{}\t{state}\t{passkey}\t{name}\t{active}",
                recovery.id,
                recovery.started_at.to_rfc3339(),
            );
            if let Some(rollback) = rollback {
                Self::print_rollback(rollback);
            }
        }
    }

    /// Prints, indented, what undoing a recovery would take back.
    fn print_rollback(rollback: &Rollback) {
        for passkey in &rollback.passkeys {
            let at = passkey.enrolled_at.to_rfc3339();
            eprintln!(
                "  passkey {} \"{}\", enrolled {at}",
                passkey.id, passkey.friendly_name
            );
        }
        for identity in &rollback.identities {
            let at = identity.linked_at.to_rfc3339();
            eprintln!("  {} sign-in, linked {at}", identity.provider);
        }
        for email in &rollback.emails {
            let at = email.verified_at.unwrap_or(email.added_at).to_rfc3339();
            eprintln!("  address {}, since {at}", email.address);
        }
        for consent in &rollback.consents {
            let at = consent.granted_at.to_rfc3339();
            eprintln!(
                "  consent to {} ({}), given {at}",
                consent.client_name, consent.client_id
            );
        }
        if let Some(primary) = &rollback.primary {
            eprintln!("  primary address back to {}", primary.address);
        }
    }

    /// Prints one account per line, and how to continue if there may be more.
    fn print_page(page: &UserPage) {
        println!("ID\tUSERNAME\tSTATUS\tCREATED\tNAME");
        for user in &page.users {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                user.id,
                user.username,
                user.status,
                user.created_at.to_rfc3339(),
                user.display_name
            );
        }
        if let Some(next) = page.next {
            eprintln!("More may follow: --cursor {next}");
        }
    }

    /// Prints an account's facts, then one section per kind of record.
    fn print_detail(detail: &UserDetail) {
        let user = &detail.user;
        println!("{} ({})", user.username, user.id);
        println!("Name:\t{}", user.display_name);
        println!("Status:\t{}", user.status);
        println!("Created:\t{}", user.created_at.to_rfc3339());
        println!("Administrator:\t{}", detail.administrator);
        println!("\nEMAIL\tVERIFIED\tPRIMARY");
        for email in &detail.emails {
            println!(
                "{}\t{}\t{}",
                email.address,
                email
                    .verified_at
                    .map_or_else(|| "-".to_owned(), |at| at.to_rfc3339()),
                email.primary
            );
        }
        println!("\nPASSKEY\tNAME");
        for passkey in &detail.passkeys {
            println!("{}\t{}", passkey.id, passkey.friendly_name);
        }
        println!("\nPROVIDER\tEMAIL");
        for identity in &detail.identities {
            println!(
                "{}\t{}",
                identity.provider,
                identity.linked_email.as_deref().unwrap_or("-")
            );
        }
        println!("\nSESSION\tMETHODS\tSIGNED IN\tLAST SEEN\tEXPIRES");
        for session in &detail.sessions {
            let methods: Vec<_> = session.methods.iter().map(ToString::to_string).collect();
            println!(
                "{}\t{}\t{}\t{}\t{}",
                session.id,
                methods.join(","),
                session.authenticated_at.to_rfc3339(),
                session.last_seen_at.to_rfc3339(),
                session.expires_at.to_rfc3339()
            );
        }
        println!("\nCLIENT\tSCOPES");
        for consent in &detail.consents {
            println!("{}\t{}", consent.client_id, consent.scopes.join(" "));
        }
    }
}
