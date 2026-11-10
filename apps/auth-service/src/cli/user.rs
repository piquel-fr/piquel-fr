//! Finding, showing, disabling, reactivating, recovering, deleting and restoring
//! accounts.

use super::{
    CliError, Confirm, Console,
    output::{Cell, Joined, Single, Style, Time, report},
};
use crate::{AdminError, AuthConfig, Reason, UserRef, recovery::Revoke};
use clap::Subcommand;
use sourceorigin_common::{
    PasskeyId,
    admin::{UserDetail, UserPage},
};
use sourceorigin_repository::{RecentRecovery, RecoveryState};

/// Accounts, in any status.
#[derive(Subcommand)]
pub(super) enum UserCommand {
    /// Search accounts by ID, or by part of a handle, display name or email,
    /// ignoring case. Lists 50 at a time, by handle.
    Search {
        /// What to look for. Lists every account when empty.
        #[arg(default_value = "")]
        query: String,
        /// The page to list, counting from 1.
        #[arg(long)]
        page: Option<u32>,
    },
    /// Show an account's profile, status, emails, passkeys, linked identities,
    /// sessions, known browsers and consents. Recorded, since it shows personal
    /// data.
    Show {
        /// The account: its handle, ID or verified email.
        user: UserRef,
    },
    /// Disable an account and end its sessions and refresh tokens. Never the last
    /// active administrator's.
    Disable {
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
    /// Let a disabled account sign in again.
    Enable {
        /// The account: its handle, ID or verified email.
        user: UserRef,
        /// Why, recorded with the change and shown to the owner in their history:
        /// 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
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
        /// Why, recorded with the change and shown to the owner in their history:
        /// 1 to 500 characters.
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
        /// Why, recorded with the change and shown to the owner in their history:
        /// 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
}

impl UserCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::Search { query, page } => {
                out.emit(&service.search_users(operator, &query, page).await?)?;
            }
            Self::Show { user } => {
                let id = console.user(&user).await?;
                out.emit(&service.view_user(operator, id).await?)?;
            }
            Self::Disable {
                user,
                reason,
                confirm,
            } => {
                let id = console.user(&user).await?;
                confirm.ask(out, &format!("Disable {user} ({id}) and end its sessions"))?;
                service.disable_user(operator, id, reason).await?;
                out.info(format_args!("Disabled {user} and ended its sessions."))?;
            }
            Self::Enable { user, reason } => {
                let id = console.user(&user).await?;
                service.enable_user(operator, id, reason).await?;
                out.info(format_args!("Enabled {user}: it can sign in again."))?;
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
                out.context(&recent[..])?;
                let undoable = recent
                    .iter()
                    .find(|recovery| recovery.state.undoable())
                    .ok_or(AdminError::NoRecoveryToUndo)?;
                let action = if undoable.state == RecoveryState::Open {
                    "cancel its unused link"
                } else {
                    "remove its passkey, withdraw every consent and end every session"
                };
                confirm.ask(
                    out,
                    &format!("Undo recovery {} of {user} ({id}): {action}", undoable.id),
                )?;
                service.undo_recovery(operator, id, reason).await?;
                out.info(format_args!("Undid recovery {} of {user}.", undoable.id))?;
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
                out.info(format_args!("Restored {user}: it can sign in again."))?;
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
            service,
            operator,
            out,
            ..
        } = console;
        let id = console.user(user).await?;
        let links = AuthConfig::recovery_links_from_environment()?;
        let recent = service.recent_recoveries(operator, id).await?;
        out.context(&recent[..])?;
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
        confirm.ask(out, &format!("Recover {user} ({id}): {action}"))?;
        match service
            .recover_account(operator, id, reason, &links, revoke)
            .await?
        {
            Some(link) => out.emit(&Single {
                name: "link",
                value: link,
            }),
            None => out.info(format_args!(
                "Recovering {user}: its primary verified address was sent the link."
            )),
        }
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
            service,
            operator,
            out,
            ..
        } = console;
        let id = console.user(user).await?;
        if immediately {
            confirm.ask(
                out,
                &format!(
                    "Purge {user} ({id}) and everything that identifies its person now; this cannot be undone"
                ),
            )?;
            service.purge_user(operator, id, reason).await?;
            out.info(format_args!("Purged {user}."))
        } else {
            confirm.ask(out, &format!("Schedule the deletion of {user} ({id})"))?;
            service.schedule_deletion(operator, id, reason).await?;
            out.info(format_args!(
                "Scheduled the deletion of {user}: it is purged in 30 days unless restored."
            ))
        }
    }
}

// An account's recent recoveries, newest first, with where each stands and the
// passkey it enrolled, shown before another is started or one is undone.
report!([RecentRecovery], self, out, {
    if self.is_empty() {
        return Ok(());
    }
    out.table(
        ["RECOVERY", "STARTED", "STATE", "PASSKEY", "NAME", "ACTIVE"],
        "",
        self.iter().map(|recovery| {
            let state = match recovery.state {
                RecoveryState::Open => Cell::new("link not used").style(Style::Notice),
                RecoveryState::Probation { settles_at } => {
                    Cell::new(format_args!("in probation until {}", Time(settles_at)))
                        .style(Style::Notice)
                }
                RecoveryState::Settled => Cell::new("settled"),
                RecoveryState::Ended => {
                    let ended = |what: &str, at| Cell::new(format_args!("{what} {}", Time(at)));
                    match (recovery.undone_at, recovery.cancelled_at) {
                        (Some(at), _) => ended("undone", at),
                        (None, Some(at)) => ended("cancelled", at),
                        (None, None) => Cell::new("link expired"),
                    }
                    .style(Style::Muted)
                }
            };
            let passkey = recovery.passkey.as_ref();
            [
                Cell::new(recovery.id),
                recovery.started_at.into(),
                state,
                passkey.map(|passkey| Cell::new(passkey.id)).into(),
                passkey
                    .and_then(|passkey| passkey.friendly_name.as_deref())
                    .into(),
                passkey.map(|passkey| passkey.active).into(),
            ]
        }),
    )?;
    out.blank()
});

// One account per line, and how to list the next page.
report!(UserPage, self, out, {
    out.table(
        ["ID", "HANDLE", "STATUS", "CREATED", "NAME"],
        "No accounts.",
        self.users.iter().map(|user| {
            [
                Cell::new(user.id),
                Cell::new(&user.handle),
                user.status.into(),
                user.created_at.into(),
                Cell::new(&user.display_name),
            ]
        }),
    )?;
    out.paging(self.paging, "accounts")
});

// An account's facts, then one section per kind of record.
report!(UserDetail, self, out, {
    let user = &self.user;
    out.title(format_args!("{} ({})", user.handle, user.id))?;
    let mut fields = vec![
        ("Name", Cell::new(&user.display_name)),
        ("Status", user.status.into()),
        ("Created", user.created_at.into()),
        ("Administrator", self.administrator.into()),
    ];
    if let Some(deletion) = &self.deletion {
        fields.push(("Purged after", deletion.purge_after.into()));
        if let Some(failure) = &deletion.failure {
            fields.extend([
                ("Purge failures", failure.attempts.into()),
                ("Next attempt", failure.next_attempt_at.into()),
                (
                    "Last error",
                    Cell::new(&failure.last_error).style(Style::Bad),
                ),
            ]);
        }
    }
    out.fields(&fields)?;
    out.section("Emails")?;
    out.table(
        ["ADDRESS", "VERIFIED", "PRIMARY"],
        "No addresses.",
        self.emails.iter().map(|email| {
            [
                Cell::new(&email.address),
                email.verified_at.into(),
                email.primary.into(),
            ]
        }),
    )?;
    out.section("Passkeys")?;
    out.table(
        ["ID", "NAME"],
        "No passkeys.",
        self.passkeys
            .iter()
            .map(|passkey| [Cell::new(passkey.id), Cell::new(&passkey.friendly_name)]),
    )?;
    out.section("Linked identities")?;
    out.table(
        ["PROVIDER", "EMAIL"],
        "No linked identities.",
        self.identities.iter().map(|identity| {
            [
                Cell::new(identity.provider),
                identity.linked_email.as_deref().into(),
            ]
        }),
    )?;
    out.section("Sessions")?;
    out.table(
        ["ID", "METHODS", "SIGNED IN", "LAST SEEN", "EXPIRES"],
        "No sessions.",
        self.sessions.iter().map(|session| {
            [
                Cell::new(session.id),
                Cell::new(Joined(&session.methods, ", ")),
                session.authenticated_at.into(),
                session.last_seen_at.into(),
                session.expires_at.into(),
            ]
        }),
    )?;
    out.section("Known browsers")?;
    self.known_devices[..].human(out)?;
    out.section("Consents")?;
    out.table(
        ["CLIENT", "SCOPES"],
        "No consents.",
        self.consents.iter().map(|consent| {
            [
                Cell::new(&consent.client_id),
                Cell::new(consent.scopes.join(" ")),
            ]
        }),
    )
});
