//! Changing one account's settings on its owner's behalf, with the owner's own
//! operations.

use super::{
    CliError, Confirm, Console, Operation,
    announcement::LetterArgs,
    output::{Cell, Joined, Style, report},
};
use crate::{
    Reason, UserRef,
    account::{AccountOperation, Subject, Viewer},
    admin::AdminOperation,
    emails::EmailView,
    grants::ConnectedApp,
    history::HistoryPage,
    notifications::{NotificationItem, NotificationPage, NotificationView},
    pictures::PictureView,
    sessions::{Revoked, SessionItem},
};
use clap::{Args, Subcommand};
use sourceorigin_common::{
    ClientId, EmailId, EventId, NotificationId, PasskeyId, Provider, SessionId, UserId,
    admin::KnownDevice,
    notifications::NotificationPreference,
    protocol::api::{Identity, Passkey},
};

/// One account's settings, as its owner sees and changes them, and messages to
/// it. Every change needs a reason, recorded with it and shown to the owner in
/// their security history.
#[derive(Args)]
pub(super) struct AccountCommand {
    /// The account: its handle, ID or verified email.
    user: UserRef,
    /// The setting to read or change.
    #[command(subcommand)]
    setting: Setting,
}

/// The settings an operator may read or change: never one that adds a way to
/// sign in or to receive the account's email.
#[derive(Subcommand)]
enum Setting {
    /// Change the display name.
    #[command(subcommand)]
    Name(Name),
    /// List, rename or remove passkeys.
    #[command(subcommand)]
    Passkeys(Passkeys),
    /// List or unlink social sign-ins.
    #[command(subcommand)]
    Identities(Identities),
    /// List email addresses, choose the primary one, or remove one.
    #[command(subcommand)]
    Emails(Emails),
    /// List sessions, or sign them out.
    #[command(subcommand)]
    Sessions(Sessions),
    /// List the apps that keep access, or remove one's access.
    #[command(subcommand)]
    Apps(Apps),
    /// Show or remove the profile picture.
    #[command(subcommand)]
    Picture(Picture),
    /// Page through the security history as the owner sees it, newest first.
    History {
        /// Continue with entries older than this one, the last one listed.
        #[arg(long)]
        before: Option<EventId>,
    },
    /// Read the account's notifications, as its inbox shows them. Reading one
    /// never marks it read.
    #[command(subcommand)]
    Notifications(Notifications),
    /// Send the account a message, such as why it was disabled or what support
    /// needs from its owner. It lands in the account's inbox, and is emailed to
    /// its primary verified address whatever the owner's email preferences. The
    /// owner cannot reply, so say how to reach support. It cannot be taken back.
    Message {
        /// Its subject and text.
        #[command(flatten)]
        letter: LetterArgs,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// The account's inbox.
#[derive(Subcommand)]
enum Notifications {
    /// List the notifications, newest first.
    List {
        /// Continue with notifications older than this one, the last one listed.
        #[arg(long)]
        before: Option<NotificationId>,
    },
    /// Show one notification, with what it offers its owner to do and its
    /// security history entry while kept.
    Show {
        /// The notification, as `list` shows it.
        notification: NotificationId,
    },
    /// Show which categories of notifications the account receives by email.
    /// Only the owner changes them, since turning one off could hide a notice
    /// from them.
    Preferences,
}

/// The account's display name, which `user show` shows.
#[derive(Subcommand)]
enum Name {
    /// Change the display name, which applications receive as `name` once they
    /// refresh the profile.
    Set {
        /// The new name: at most 80 characters, not blank.
        name: String,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
}

/// The account's passkeys.
#[derive(Subcommand)]
enum Passkeys {
    /// List the active passkeys.
    List,
    /// Rename a passkey.
    Rename {
        /// The passkey's ID, as `list` shows it.
        passkey: PasskeyId,
        /// The new name.
        name: String,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
    /// Remove a passkey and sign the account out everywhere. One passkey always
    /// remains.
    Revoke {
        /// The passkey's ID, as `list` shows it.
        passkey: PasskeyId,
        /// Why.
        #[command(flatten)]
        change: Change,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// The account's linked social sign-ins.
#[derive(Subcommand)]
enum Identities {
    /// List the linked providers.
    List,
    /// Unlink a provider and sign the account out everywhere.
    Unlink {
        /// The provider: `github` or `google`.
        provider: Provider,
        /// Why.
        #[command(flatten)]
        change: Change,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// The account's email addresses.
#[derive(Subcommand)]
enum Emails {
    /// List the addresses, primary first.
    List,
    /// Make a verified address the primary one, which applications receive. The
    /// previous one is told.
    Primary {
        /// The address's ID, as `list` shows it.
        email: EmailId,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
    /// Remove an address, which is told if it was verified. The primary address
    /// goes last.
    Remove {
        /// The address's ID, as `list` shows it.
        email: EmailId,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
}

/// The account's sessions, one per signed-in browser.
#[derive(Subcommand)]
enum Sessions {
    /// List the active sessions, most recently active first.
    List,
    /// Sign one session out, with its applications' refresh tokens.
    Revoke {
        /// The session's ID, as `list` shows it.
        session: SessionId,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
    /// Sign every session out, with their applications' refresh tokens.
    RevokeAll {
        /// Why.
        #[command(flatten)]
        change: Change,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// List the browsers that signed in within the last 400 days, most recently
    /// seen first. A sign-in from any other browser sends the owner a security
    /// notification.
    Known,
}

/// The apps that keep access to the account: those it consented to, and those
/// whose refresh grant still works.
#[derive(Subcommand)]
enum Apps {
    /// List the apps, by name.
    List,
    /// Remove an app's access: its refresh grants end and it asks for consent
    /// again. The account's sessions stay signed in.
    Remove {
        /// The app's client ID, as `list` shows it.
        client: ClientId,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
}

/// The account's profile picture. Only the owner sets one.
#[derive(Subcommand)]
enum Picture {
    /// Show the picture's ID, path on auth and when it was uploaded.
    Show,
    /// Remove the picture, such as one that impersonates someone.
    Remove {
        /// Why.
        #[command(flatten)]
        change: Change,
    },
}

/// The `--reason` every change takes.
#[derive(Args)]
struct Change {
    /// Why: 1 to 500 characters, recorded with the change. The account's owner
    /// sees it in their security history.
    #[arg(long)]
    reason: Reason,
}

impl Change {
    /// The operator at this terminal changing `user`, for this reason.
    fn on(self, user: UserId, console: &Console) -> Subject {
        Subject::operator(user, console.operator.clone(), self.reason)
    }
}

impl AccountCommand {
    /// The operation this command runs: a shared settings operation, or sending
    /// a message, an administrative one. The match is exhaustive, so a new
    /// command does not compile until it names one.
    pub(super) const fn operation(&self) -> Operation {
        type Op = AccountOperation;
        Operation::Account(match &self.setting {
            Setting::Message { .. } => return Operation::Admin(AdminOperation::MessageUser),
            Setting::Name(Name::Set { .. }) => Op::ChangeDisplayName,
            Setting::Passkeys(command) => match command {
                Passkeys::List => Op::ListPasskeys,
                Passkeys::Rename { .. } => Op::RenamePasskey,
                Passkeys::Revoke { .. } => Op::RevokePasskey,
            },
            Setting::Identities(command) => match command {
                Identities::List => Op::ListIdentities,
                Identities::Unlink { .. } => Op::UnlinkIdentity,
            },
            Setting::Emails(command) => match command {
                Emails::List => Op::ListEmails,
                Emails::Primary { .. } => Op::MakeEmailPrimary,
                Emails::Remove { .. } => Op::RemoveEmail,
            },
            Setting::Sessions(command) => match command {
                Sessions::List => Op::ListSessions,
                Sessions::Revoke { .. } => Op::RevokeSession,
                Sessions::RevokeAll { .. } => Op::RevokeOtherSessions,
                Sessions::Known => Op::ListKnownDevices,
            },
            Setting::Apps(command) => match command {
                Apps::List => Op::ListApps,
                Apps::Remove { .. } => Op::RemoveApp,
            },
            Setting::Picture(command) => match command {
                Picture::Show => Op::ViewPicture,
                Picture::Remove { .. } => Op::RemovePicture,
            },
            Setting::History { .. } => Op::ViewHistory,
            Setting::Notifications(notifications) => match notifications {
                Notifications::List { .. } => Op::ListNotifications,
                Notifications::Show { .. } => Op::ViewNotification,
                Notifications::Preferences => Op::ViewNotificationPreferences,
            },
        })
    }

    /// Runs this command as the operator at this terminal. Reads are recorded as
    /// views of the account, as `user show` is.
    #[expect(
        clippy::too_many_lines,
        reason = "One arm per command, so a new command cannot skip running."
    )]
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Self { user, setting } = self;
        let id = console.user(&user).await?;
        let Console { account, out, .. } = console;
        let read = || Viewer::operator(id, console.operator.clone());
        match setting {
            Setting::Name(Name::Set { name, change }) => {
                account
                    .change_display_name(&change.on(id, console), name)
                    .await?;
                out.info(format_args!("Changed the display name of {user}."))?;
            }
            Setting::Passkeys(Passkeys::List) => out.emit(&account.passkeys(&read()).await?[..])?,
            Setting::Passkeys(Passkeys::Rename {
                passkey,
                name,
                change,
            }) => {
                account
                    .rename_passkey(&change.on(id, console), passkey, name)
                    .await?;
                out.info(format_args!("Renamed passkey {passkey} of {user}."))?;
            }
            Setting::Passkeys(Passkeys::Revoke {
                passkey,
                change,
                confirm,
            }) => {
                confirm.ask(
                    out,
                    &format!(
                        "Remove passkey {passkey} of {user} ({id}) and sign it out everywhere"
                    ),
                )?;
                let subject = change.on(id, console);
                account.revoke_passkey(&subject, passkey).await?;
                out.info(format_args!(
                    "Removed passkey {passkey} of {user} and signed it out everywhere."
                ))?;
            }
            Setting::Identities(Identities::List) => {
                out.emit(&account.identities(&read()).await?[..])?;
            }
            Setting::Identities(Identities::Unlink {
                provider,
                change,
                confirm,
            }) => {
                confirm.ask(
                    out,
                    &format!("Unlink {provider} from {user} ({id}) and sign it out everywhere"),
                )?;
                let subject = change.on(id, console);
                account.unlink_identity(&subject, provider).await?;
                out.info(format_args!(
                    "Unlinked {provider} from {user} and signed it out everywhere."
                ))?;
            }
            Setting::Emails(Emails::List) => out.emit(&account.emails(&read()).await?[..])?,
            Setting::Emails(Emails::Primary { email, change }) => {
                let subject = change.on(id, console);
                account.make_primary_email(&subject, email).await?;
                out.info(format_args!(
                    "Made address {email} the primary one of {user}."
                ))?;
            }
            Setting::Emails(Emails::Remove { email, change }) => {
                let subject = change.on(id, console);
                account.remove_email(&subject, email).await?;
                out.info(format_args!("Removed address {email} from {user}."))?;
            }
            Setting::Sessions(Sessions::List) => out.emit(&account.sessions(&read()).await?[..])?,
            Setting::Sessions(Sessions::Revoke { session, change }) => {
                account
                    .revoke_session(&change.on(id, console), session)
                    .await?;
                out.info(format_args!("Signed session {session} of {user} out."))?;
            }
            Setting::Sessions(Sessions::RevokeAll { change, confirm }) => {
                confirm.ask(out, &format!("Sign {user} ({id}) out everywhere"))?;
                let Revoked { revoked } = account
                    .revoke_other_sessions(&change.on(id, console))
                    .await?;
                out.info(format_args!("Signed {user} out of {revoked} sessions."))?;
            }
            Setting::Sessions(Sessions::Known) => {
                out.emit(&account.known_devices(&read()).await?[..])?;
            }
            Setting::Apps(Apps::List) => out.emit(&account.apps(&read()).await?[..])?,
            Setting::Apps(Apps::Remove { client, change }) => {
                account.remove_app(&change.on(id, console), &client).await?;
                out.info(format_args!("Removed the access of {client} to {user}."))?;
            }
            Setting::Picture(Picture::Show) => out.emit(&account.picture(&read()).await?)?,
            Setting::Picture(Picture::Remove { change }) => {
                account.remove_picture(&change.on(id, console)).await?;
                out.info(format_args!("Removed the profile picture of {user}."))?;
            }
            Setting::History { before } => {
                out.emit(&account.history(&read(), before).await?)?;
            }
            Setting::Notifications(notifications) => {
                notifications.run(console, &read()).await?;
            }
            Setting::Message { letter, confirm } => {
                let letter = letter.letter()?;
                confirm.ask(
                    out,
                    &format!(
                        "Send the message \"{}\" to {user} ({id}), emailing its primary verified address",
                        letter.subject
                    ),
                )?;
                console
                    .service
                    .message_user(&console.operator, id, letter)
                    .await?;
                out.info(format_args!("Sent the message to {user}."))?;
            }
        }
        Ok(())
    }
}

impl Notifications {
    /// Prints the inbox, one notification, or the email preferences, as `viewer`
    /// reads them, marking nothing read.
    async fn run(self, console: &Console, viewer: &Viewer) -> Result<(), CliError> {
        let Console { account, out, .. } = console;
        match self {
            Self::List { before } => out.emit(&account.notifications(viewer, before).await?),
            Self::Show { notification } => {
                out.emit(&account.notification(viewer, notification).await?)
            }
            Self::Preferences => out.emit(&account.notification_preferences(viewer).await?[..]),
        }
    }
}

// The profile picture, or that there is none.
report!(Option<PictureView>, self, out, {
    match self {
        Some(picture) => out.fields(&[
            ("ID", Cell::new(picture.id)),
            ("Path", Cell::new(&picture.url)),
            ("Uploaded", picture.created_at.into()),
        ]),
        None => out.line("No profile picture."),
    }
});

// One passkey per line.
report!([Passkey], self, out, {
    out.table(
        ["ID", "NAME"],
        "No passkeys.",
        self.iter()
            .map(|passkey| [Cell::new(passkey.id), Cell::new(&passkey.friendly_name)]),
    )
});

// One linked provider per line.
report!([Identity], self, out, {
    out.table(
        ["PROVIDER", "EMAIL"],
        "No linked identities.",
        self.iter().map(|identity| {
            [
                Cell::new(identity.provider),
                identity.linked_email.as_deref().into(),
            ]
        }),
    )
});

// One address per line.
report!([EmailView], self, out, {
    out.table(
        ["ID", "ADDRESS", "VERIFIED", "PRIMARY"],
        "No addresses.",
        self.iter().map(|email| {
            [
                Cell::new(email.id),
                Cell::new(&email.address),
                email.verified.into(),
                email.primary.into(),
            ]
        }),
    )
});

// One session per line, then one per dashboard session resting on it, indented,
// with when it signed in, was last used and ends.
report!([SessionItem], self, out, {
    out.table(
        [
            "ID",
            "METHODS",
            "DEVICE",
            "IP",
            "SIGNED IN",
            "LAST SEEN",
            "EXPIRES",
        ],
        "No sessions.",
        self.iter().flat_map(|session| {
            let row = [
                Cell::new(session.id),
                Cell::new(Joined(&session.methods, ", ")),
                session.device.map(Cell::new).into(),
                session.ip.map(Cell::new).into(),
                session.authenticated_at.into(),
                session.last_seen_at.into(),
                session.expires_at.into(),
            ];
            let dashboard = session.dashboard.iter().map(|dashboard| {
                [
                    Cell::new("  dashboard").style(Style::Muted),
                    Cell::none(),
                    Cell::none(),
                    Cell::none(),
                    dashboard.signed_in_at.into(),
                    dashboard.last_used_at.into(),
                    dashboard.expires_at.into(),
                ]
            });
            std::iter::once(row).chain(dashboard)
        }),
    )
});

// One known browser per line, as `user show` lists them too.
report!([KnownDevice], self, out, {
    out.table(
        ["DEVICE", "FIRST SEEN", "LAST SEEN"],
        "No known browsers.",
        self.iter().map(|device| {
            [
                device.device.map(Cell::new).into(),
                device.first_seen_at.into(),
                device.last_seen_at.into(),
            ]
        }),
    )
});

// One app per line. `OFFLINE` says whether it holds a refresh grant, to act
// while the owner is away.
report!([ConnectedApp], self, out, {
    out.table(
        ["CLIENT ID", "NAME", "FIRST PARTY", "OFFLINE", "SCOPES"],
        "No apps.",
        self.iter().map(|app| {
            [
                Cell::new(&app.client_id),
                Cell::new(&app.name),
                app.first_party.into(),
                app.offline.into(),
                Cell::new(app.scopes.join(" ")),
            ]
        }),
    )
});

// One entry per line, by its `kind`, and how to list what follows.
report!(HistoryPage, self, out, {
    out.table(
        ["ID", "TIME", "KIND", "BY", "REASON"],
        "No history.",
        self.entries.iter().map(|item| {
            // An entry holds no map, so it always serializes.
            let entry = serde_json::to_value(&item.entry).unwrap_or_default();
            [
                Cell::new(item.id),
                item.occurred_at.into(),
                entry["kind"].as_str().into(),
                Cell::new(item.actor),
                item.reason.as_deref().into(),
            ]
        }),
    )?;
    out.more(self.next)
});

// Each category and whether it is emailed. Everything about the account itself
// always is.
report!([NotificationPreference], self, out, {
    let category = |category, email| [Cell::new(category), Cell::new(email)];
    out.table(
        ["CATEGORY", "EMAIL"],
        "",
        std::iter::once(category("security".to_owned(), "always")).chain(self.iter().map(
            |preference| {
                let email = if preference.email { "on" } else { "off" };
                category(preference.category.to_string(), email)
            },
        )),
    )
});

// One notification per line, and how to list what follows.
report!(NotificationPage, self, out, {
    out.table(
        ["ID", "TIME", "READ", "SUBJECT"],
        "No notifications.",
        self.notifications.iter().map(|item| {
            [
                Cell::new(item.id),
                item.created_at.into(),
                item.read().into(),
                Cell::new(&item.subject),
            ]
        }),
    )?;
    out.more(self.next)
});

// A notification: its subject, when, whether it was read, what it offers its
// owner to do, what it says, and its history entry while the history keeps it.
report!(NotificationView, self, out, {
    let NotificationItem {
        subject,
        body,
        created_at,
        ..
    } = &self.item;
    out.title(subject)?;
    let mut fields = vec![
        ("Sent", Cell::from(*created_at)),
        ("Read", self.item.read().into()),
    ];
    if let Some(action) = self.item.action {
        fields.push(("Offers", Cell::new(action.label())));
    }
    if let Some(entry) = &self.history {
        fields.push((
            "History entry",
            Cell::new(format_args!("{} (by {})", entry.id, entry.actor)),
        ));
    }
    out.fields(&fields)?;
    out.blank()?;
    out.text(body)?;
    out.blank()
});
