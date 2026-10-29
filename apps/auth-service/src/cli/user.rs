//! Finding, showing, disabling, reactivating, recovering, deleting and restoring
//! accounts.

use super::{CliError, Confirm, Console, Output};
use crate::{AdminError, AuthConfig, Reason, UserRef, recovery::Revoke};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use piquel_common::{
    PasskeyId, UserId,
    admin::{UserDetail, UserPage},
};
use piquel_repository::{RecentRecovery, RecoveryState};

/// Accounts, in any status.
#[derive(Subcommand)]
pub(super) enum UserCommand {
    /// Search accounts by ID, or by part of a handle, display name or email,
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
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Disable an account and end its sessions and refresh tokens.
    Disable {
        /// The account: its handle, ID or verified email.
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
        /// The account: its handle, ID or verified email.
        user: UserRef,
    },
    /// Recover an account whose owner lost every passkey.
    ///
    /// First lists the account's recoveries that started, ended or were used
    /// within a probation's length. Refuses while one is in probation: find out
    /// who used it, and undo it with `user undo-recovery` first. An unused link
    /// is replaced. Refuses an administrator's account: revoke its rights first.
    /// Ends the account's sessions, removes its unverified addresses, and sends
    /// its primary verified address a link that enrolls one passkey, within a
    /// day; prints the link too, for when there is none. Through the probation
    /// that follows, that passkey signs in but confirms no change, and any older
    /// passkey can undo the recovery. Needs `AUTH_PUBLIC_BASE_URL` and the token
    /// digest key, which derives the link.
    Recover {
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// Why, recorded with the recovery and shown to the owner, and to whoever
        /// uses the link, in the history: what was asked, never the evidence. 1
        /// to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// The account was in someone else's hands: also revoke every passkey
        /// not kept with `--keep`, the last included, unlink every social
        /// identity and withdraw every consent. The link is then only printed,
        /// and every verified address is told at once. Remove the addresses the
        /// owner does not recognize afterwards, before handing the link over.
        #[arg(long)]
        revoke: bool,
        /// With `--revoke`, a passkey the owner vouches for, which stays and can
        /// still undo the recovery. Repeatable.
        #[arg(long, requires = "revoke")]
        keep: Vec<PasskeyId>,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Schedule an active account's deletion: it can no longer sign in, its
    /// sessions end, and it is purged after 30 days unless restored first. Never
    /// the last active administrator's.
    Delete {
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// Why, kept with the event as personal data: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Purge the account now, in any status, without a grace period. This
        /// cannot be undone.
        #[arg(long)]
        immediately: bool,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Undo an account's recovery for its owner, once they are confirmed.
    ///
    /// For an owner with no passkey left from before it, or whose account is
    /// disabled. In probation, removes its passkey, even the last, withdraws
    /// every consent, and ends every session and refresh grant; its link unused,
    /// cancels the link.
    UndoRecovery {
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// Why, recorded with each change and shown to the owner in their
        /// history: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Restore an account scheduled for deletion, so it can sign in again.
    Restore {
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// Why, kept with the event as personal data: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
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
                revoke,
                keep,
                confirm,
            } => Self::recover(console, &user, reason, revoke, keep, &confirm).await?,
            Self::UndoRecovery {
                user,
                reason,
                confirm,
            } => {
                let id = console.user(&user).await?;
                let recent = service.recent_recoveries(operator, id).await?;
                Self::print_recent(&recent);
                let undoable = recent
                    .iter()
                    .find(|recovery| recovery.state.undoable())
                    .ok_or(AdminError::NoRecoveryToUndo)?;
                let action = if undoable.state == RecoveryState::Open {
                    "cancel its unused link"
                } else {
                    "remove its passkey, withdraw every consent and end every session"
                };
                confirm.ask(&format!(
                    "Undo recovery {} of {user} ({id}): {action}",
                    undoable.id
                ))?;
                service.undo_recovery(operator, id, reason).await?;
            }
            Self::Delete {
                user,
                reason,
                immediately,
                confirm,
            } => Self::delete(console, &user, reason, immediately, &confirm).await?,
            Self::Restore { user, reason } => {
                let id = console.user(&user).await?;
                service.restore_user(operator, id, reason).await?;
            }
        }
        Ok(())
    }

    /// Starts recovering `user`'s account for `reason`, once confirmed, after
    /// listing its recent recoveries; `revoke` with `keep` takes back every other
    /// way in first.
    async fn recover(
        console: &Console,
        user: &UserRef,
        reason: Reason,
        revoke: bool,
        keep: Vec<PasskeyId>,
        confirm: &Confirm,
    ) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        let id = console.user(user).await?;
        let links = AuthConfig::recovery_links_from_environment()?;
        let recent = service.recent_recoveries(operator, id).await?;
        Self::print_recent(&recent);
        // Refused before asking, rather than after the confirmation;
        // the service refuses too.
        let probation = recent
            .iter()
            .any(|recovery| matches!(recovery.state, RecoveryState::Probation { .. }));
        if probation {
            return Err(AdminError::RecoveryInProbation.into());
        }
        let revoke = revoke.then_some(Revoke { keep });
        let action = match &revoke {
            Some(revoke) => format!(
                "revoke every passkey but {} kept, unlink every identity, withdraw every consent, end its sessions and print a recovery link",
                revoke.keep.len()
            ),
            None => "end its sessions and send it a recovery link".to_owned(),
        };
        confirm.ask(&format!("Recover {user} ({id}): {action}"))?;
        if let Some(link) = service
            .recover_account(operator, id, reason, &links, revoke)
            .await?
        {
            println!("{link}");
        }
        Ok(())
    }

    /// Schedules the deletion of `user`'s account, or purges it at once when
    /// `immediately`, for `reason`, once confirmed.
    async fn delete(
        console: &Console,
        user: &UserRef,
        reason: Reason,
        immediately: bool,
        confirm: &Confirm,
    ) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        let id = console.user(user).await?;
        if immediately {
            confirm.ask(&format!(
                "Purge {user} ({id}) and everything that identifies its person now; this cannot be undone"
            ))?;
            service.purge_user(operator, id, reason).await?;
        } else {
            confirm.ask(&format!("Schedule the deletion of {user} ({id})"))?;
            service.schedule_deletion(operator, id, reason).await?;
        }
        Ok(())
    }

    /// Prints the account's recent recoveries, newest first, with where each
    /// stands and the passkey it enrolled, before another is started or one is
    /// undone. On standard error, which leaves standard output to the new link.
    fn print_recent(recent: &[RecentRecovery]) {
        if recent.is_empty() {
            return;
        }
        eprintln!("RECOVERY\tSTARTED\tSTATE\tPASSKEY\tNAME\tACTIVE");
        for recovery in recent {
            let at = |at: Option<DateTime<Utc>>| at.map(|at| at.to_rfc3339());
            let state = match recovery.state {
                RecoveryState::Open => "link not used".to_owned(),
                RecoveryState::Probation { settles_at } => {
                    format!("in probation until {}", settles_at.to_rfc3339())
                }
                RecoveryState::Settled => "settled".to_owned(),
                RecoveryState::Ended => at(recovery.undone_at)
                    .map(|at| format!("undone {at}"))
                    .or_else(|| at(recovery.cancelled_at).map(|at| format!("cancelled {at}")))
                    .unwrap_or_else(|| "link expired".to_owned()),
            };
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
        }
    }

    /// Prints one account per line, and how to continue if there may be more.
    fn print_page(page: &UserPage) {
        println!("ID\tHANDLE\tSTATUS\tCREATED\tNAME");
        for user in &page.users {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                user.id,
                user.handle,
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
        println!("{} ({})", user.handle, user.id);
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
