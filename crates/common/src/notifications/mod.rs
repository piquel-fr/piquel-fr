//! What an account's owner is told about their account, and administrators
//! about the service: the notifications of their inbox, each derived from an
//! event by [`DomainEvent::notification`](crate::events::DomainEvent::notification).
//!
//! A notification holds no personal data and renders from itself alone, so it
//! reads the same once its event's personal data is erased, or the event pruned.
//! Its event's security history entry, while kept, tells the rest.

use crate::{
    AlertId, AnnouncementId, Provider,
    events::{Actor, DomainEvent, GrantRevocation, RevocationReason, SignInFailure},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How long the "sign me out everywhere" link of a security notification's
/// email works, once: its emails and pages say so.
pub const SIGN_OUT_LINK_LIFETIME: chrono::Duration = chrono::Duration::days(7);

/// What an account's owner is told, stored as it serializes, e.g.
/// `{"kind": "deletion_scheduled", "purge_after": …}`. Never rename a released
/// kind: a newer release's kinds are skipped by older ones, not misread.
///
/// A variant holds only IDs, enums, flags and timestamps, never a secret, an
/// address or a [`Personal`](crate::Personal) value, except an announcement or
/// a message, which hold the text administrators wrote, and a raised alert,
/// which holds the alert's text; it names no account. A targeted announcement's
/// text, which may name its recipients, goes with them: purging an account
/// deletes its notifications, its messages among them, and the announcement once
/// its last recipient is purged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Notification {
    /// Another verified address became the primary one.
    PrimaryEmailChanged,
    /// An address was removed from the account.
    EmailRemoved,
    /// Support revoked the account's ways in and started a recovery, as for an
    /// account in someone else's hands.
    AccountSecured {
        /// Whether a passkey the owner vouched for was kept, which can undo it.
        kept: bool,
    },
    /// A recovery's link enrolled a passkey.
    Recovered,
    /// A recovery was undone, or its unused link cancelled.
    RecoveryUndone,
    /// Support changed the account's handle.
    HandleChanged,
    /// Support changed the account's display name.
    DisplayNameChanged,
    /// Support renamed one of the account's passkeys.
    PasskeyRenamed,
    /// Support removed the account's profile picture.
    PictureRemoved,
    /// The account was disabled.
    AccountDisabled,
    /// The account was enabled again.
    AccountEnabled,
    /// The account was scheduled for deletion.
    DeletionScheduled {
        /// When it is purged, unless it is restored first.
        purge_after: DateTime<Utc>,
    },
    /// The account was restored before its deletion.
    AccountRestored,
    /// A browser that had never signed in to the account did.
    NewDeviceSignIn,
    /// A passkey was added to the account.
    PasskeyAdded,
    /// A passkey was removed from the account.
    PasskeyRemoved,
    /// A social sign-in was linked to the account.
    IdentityLinked {
        /// Its provider.
        provider: Provider,
    },
    /// A social sign-in was unlinked from the account.
    IdentityUnlinked {
        /// Its provider.
        provider: Provider,
    },
    /// An email address was added to the account.
    EmailAdded {
        /// The provider it was imported from, when linking one brought it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<Provider>,
    },
    /// An app's refresh token was used twice, so its access was revoked: one of
    /// the two may have been stolen.
    TokenReused,
    /// Support started a recovery of the account, whose link adds a passkey: it
    /// went to the primary address, or support handed it over.
    RecoveryStarted,
    /// Support signed the account out, of one device or every one.
    SignedOutBySupport,
    /// The owner reported an entry of their history as not theirs.
    CompromiseReported,
    /// A sign-in was refused because the passkey's signature counter went
    /// backwards, as a copied passkey's does.
    PasskeyCopied,
    /// Someone proved they hold a way into the account, but the sign-in was
    /// refused: the account is disabled, cannot sign in that way any more, or is
    /// scheduled for deletion and a recovery's passkey tried to restore it.
    SignInRefused,
    /// Administrators sent an announcement to every account, or to chosen ones
    /// among them this one. Sending writes it, as no event about the account
    /// does.
    Announcement {
        /// The announcement.
        announcement_id: AnnouncementId,
        /// Its subject, as they wrote it. Named apart from the `subject` every
        /// notification is shown with, which it becomes.
        title: String,
        /// Its text, as they wrote it, which becomes the notification's `body`.
        text: String,
    },
    /// Administrators sent this account a message, such as why it was disabled
    /// or what support needs from its owner. It and its queued email hold the
    /// message's only copies, which purging the account deletes:
    /// [`DomainEvent::MessageSent`] records who sent it, not what it says.
    Message {
        /// Its subject, as they wrote it, which becomes the notification's
        /// `subject`.
        title: String,
        /// Its text, as they wrote it, which becomes the notification's `body`.
        text: String,
    },
    /// An alert was raised, to every active administrator. It holds what the
    /// alert said when it was raised, not the alert itself: a newer release's
    /// alert would not decode in an older one's inbox.
    AlertRaised {
        /// The alert.
        alert_id: AlertId,
        /// The alert's subject, prefixed with "Alert: ". Named apart from the
        /// `subject` every notification is shown with, which it becomes.
        title: String,
        /// What it said, which becomes the notification's `body`.
        text: String,
    },
}

impl DomainEvent {
    /// The notification this event, caused by `actor`, gives its audience
    /// ([`Notification::audience`]), if any: its subject, or for a raised alert,
    /// every active administrator. Every variant is named, so a new event cannot
    /// be added without deciding whether anyone is told.
    ///
    /// A change the owner makes to their own name tells them nothing they don't
    /// know; one made by support does. Every change to the account's ways in,
    /// its addresses and recovery notifies whoever made it, so a stolen session
    /// cannot make one unseen, except the steps of an operation the owner takes
    /// without a session, signing up or through a recovery's link or undo page,
    /// which tells them as a whole, if at all. Support's own steps of a
    /// recovery are recorded without their notifications
    /// (`DatabaseTransaction::record_quietly`).
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    #[expect(
        clippy::too_many_lines,
        reason = "One arm per event kind, so a new kind cannot skip the decision."
    )]
    pub fn notification(&self, actor: &Actor) -> Option<Notification> {
        let by_support = matches!(actor, Actor::Admin { .. } | Actor::Cli { .. });
        let sessionless = matches!(
            actor,
            Actor::Anonymous
                | Actor::User {
                    session_id: None,
                    ..
                }
        );
        Some(match self {
            Self::PrimaryEmailChanged {
                previous_email_id: Some(_),
                ..
            } => Notification::PrimaryEmailChanged,
            Self::EmailRemoved { .. } => Notification::EmailRemoved,
            Self::RecoveryStarted {
                revoke: Some(revocation),
                ..
            } => Notification::AccountSecured {
                kept: !revocation.kept.is_empty(),
            },
            Self::RecoveryCompleted { .. } => Notification::Recovered,
            Self::RecoveryUndone { .. } => Notification::RecoveryUndone,
            Self::HandleChanged { .. } if by_support => Notification::HandleChanged,
            Self::DisplayNameChanged { .. } if by_support => Notification::DisplayNameChanged,
            Self::PasskeyRenamed { .. } if by_support => Notification::PasskeyRenamed,
            Self::PictureRemoved {} if by_support => Notification::PictureRemoved,
            Self::AccountDisabled { .. } => Notification::AccountDisabled,
            Self::AccountEnabled {} => Notification::AccountEnabled,
            Self::AccountDeletionScheduled { purge_after } => Notification::DeletionScheduled {
                purge_after: *purge_after,
            },
            Self::AccountRestored {} => Notification::AccountRestored,
            Self::SignedIn {
                new_device: true, ..
            } => Notification::NewDeviceSignIn,
            Self::PasskeyAdded { .. } if !sessionless => Notification::PasskeyAdded,
            Self::PasskeyRemoved { .. } if !sessionless => Notification::PasskeyRemoved,
            Self::IdentityLinked { provider, .. } if !sessionless => Notification::IdentityLinked {
                provider: *provider,
            },
            Self::IdentityUnlinked { provider } if !sessionless => {
                Notification::IdentityUnlinked {
                    provider: *provider,
                }
            }
            Self::EmailAdded { provider, .. } if !sessionless => Notification::EmailAdded {
                provider: *provider,
            },
            Self::GrantRevoked {
                reason: GrantRevocation::RefreshReplay,
                ..
            } => Notification::TokenReused,
            Self::RecoveryStarted { revoke: None, .. } => Notification::RecoveryStarted,
            Self::SessionRevoked {
                reason: RevocationReason::Admin,
                ..
            } => Notification::SignedOutBySupport,
            Self::CompromiseReported { .. } => Notification::CompromiseReported,
            Self::SignInFailed {
                reason: SignInFailure::CounterRegression,
                ..
            } => Notification::PasskeyCopied,
            Self::SignInFailed {
                reason: SignInFailure::AccountUnavailable,
                ..
            } => Notification::SignInRefused,
            Self::AlertRaised { alert_id, alert } => Notification::AlertRaised {
                alert_id: *alert_id,
                title: format!("Alert: {}", alert.subject()),
                text: alert.body(),
            },
            // The owner made it, so they know. Only the owner, or their social
            // signup, sets a picture, and only the owner changes their
            // notification preferences.
            Self::HandleChanged { .. }
            | Self::NotificationPreferenceChanged(_)
            | Self::DisplayNameChanged { .. }
            | Self::PasskeyRenamed { .. }
            | Self::PictureRemoved {}
            | Self::PictureChanged { .. }
            // The account's first verified address: nothing was replaced.
            | Self::PrimaryEmailChanged {
                previous_email_id: None,
                ..
            }
            // Signing up, or a recovery's link or undo page: the account's
            // creation needs no alert, and a recovery tells its owner as a whole.
            | Self::PasskeyAdded { .. }
            | Self::PasskeyRemoved { .. }
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::EmailAdded { .. }
            // A browser the account knows, or a sign-in that only shows the
            // account's existence, such as a wrong passkey's.
            | Self::AccountCreated { .. }
            | Self::SignedIn { .. }
            | Self::SignInFailed { .. }
            // The owner signed out, or another change that notifies ended them.
            | Self::SessionRevoked { .. }
            // Nothing that adds a way in: a confirmation, a name, a verified
            // address the owner already heard of, or an app's grants.
            | Self::PasskeyConfirmed { .. }
            | Self::EmailVerified { .. }
            | Self::ConsentGranted { .. }
            | Self::ConsentRevoked { .. }
            | Self::GrantIssued { .. }
            | Self::GrantRevoked { .. }
            // A replayed code's grants are revoked as `GrantRevoked`, which shows
            // its app's mistake rather than a stolen token: the history shows it.
            | Self::CodeReplayed { .. }
            | Self::CodeRedemptionFailed { .. }
            | Self::AccountExported {}
            // It signs the owner out, and the history shows its use, so a link
            // someone else used never goes unseen.
            | Self::SignedOutEverywhere { .. }
            // Administrator rights show in the dashboard, which its holder uses.
            | Self::AdministratorGranted {}
            | Self::AdministratorRevoked {}
            | Self::DashboardSignedIn { .. }
            | Self::DashboardSignedOut { .. }
            // A read changes nothing to tell.
            | Self::AccountViewed {}
            // Nobody reads the inbox of an account that no longer exists.
            | Self::AccountPurged {}
            // These concern no account's owner.
            | Self::InvitationCreated { .. }
            | Self::InvitationRevoked { .. }
            | Self::HandleReleased { .. }
            | Self::HandleReserved { .. }
            | Self::HandleUnreserved { .. }
            | Self::ClientRegistered { .. }
            | Self::ClientUpdated { .. }
            | Self::ClientEnabled { .. }
            | Self::ClientDisabled { .. }
            | Self::ClientSuspended { .. }
            | Self::ClientSuspensionLifted { .. }
            | Self::ClientDeleted { .. }
            | Self::ClientSecretRotated { .. }
            | Self::RelatedOriginApproved { .. }
            | Self::RelatedOriginRemoved { .. }
            | Self::DeliveryRetried { .. }
            | Self::DeliveryCancelled { .. }
            | Self::SigningKeyChanged { .. }
            | Self::AuditHistoryPruned { .. }
            | Self::AuditChainVerified(_)
            // It concerns no one account: sending writes each recipient's.
            | Self::AnnouncementSent { .. }
            // It leaves the message's text out, which
            // `DatabaseTransaction::record_message` gives the account instead.
            | Self::MessageSent {}
            // Administrators follow an alert on the dashboard's Alerts tab, or
            // with `auth-service alerts list`, once it is raised.
            | Self::AlertUpdated { .. }
            | Self::AlertCleared { .. }
            | Self::Imported(_) => return None,
        })
    }
}

crate::str_enum! {
    /// A category of notifications whose email the owner chooses to receive, on
    /// by default. Everything about the account itself, its security category, is
    /// not one: it is always emailed, so no switch can hide it.
    pub enum EmailCategory {
        /// Administrators' announcements. An essential one is emailed whatever
        /// the preference.
        Announcements = "announcements",
    }
}

impl EmailCategory {
    /// Its name, in settings and on the dashboard.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Announcements => "Announcements",
        }
    }

    /// What it holds, and what turning its email off does.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Announcements => {
                "News from SourceOrigin, such as a new feature. Announcements about a security incident, or a change to the privacy policy or terms, reach you by email either way."
            }
        }
    }
}

/// Whether the owner receives a category's email, e.g.
/// `{"category": "announcements", "email": false}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationPreference {
    /// The category.
    pub category: EmailCategory,
    /// Whether its notifications are emailed.
    pub email: bool,
}

impl NotificationPreference {
    /// What changing to it did, as the history says, e.g. "Announcements:
    /// emails turned off".
    #[must_use]
    pub fn change(self) -> String {
        let state = if self.email { "on" } else { "off" };
        format!("{}: emails turned {state}", self.category.label())
    }
}

/// Whose inbox a notification goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// The account its event is about.
    Subject,
    /// Every active administrator, for an event about the service rather than
    /// one account.
    Administrators,
}

/// Which of the account's verified addresses a notification's email goes to,
/// each once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addressees {
    /// Every verified address, so one compromised mailbox cannot hide it.
    Verified,
    /// The address its event replaced or removed, so whoever reads that mailbox
    /// hears of it.
    Affected,
    /// The primary verified address. An account without one gets no email.
    Primary,
}

impl Notification {
    /// Whose inbox it goes to.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn audience(&self) -> Audience {
        match self {
            Self::AlertRaised { .. } => Audience::Administrators,
            Self::PrimaryEmailChanged
            | Self::EmailRemoved
            | Self::AccountSecured { .. }
            | Self::Recovered
            | Self::RecoveryUndone
            | Self::HandleChanged
            | Self::DisplayNameChanged
            | Self::PasskeyRenamed
            | Self::PictureRemoved
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::DeletionScheduled { .. }
            | Self::AccountRestored
            | Self::NewDeviceSignIn
            | Self::PasskeyAdded
            | Self::PasskeyRemoved
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::EmailAdded { .. }
            | Self::TokenReused
            | Self::RecoveryStarted
            | Self::SignedOutBySupport
            | Self::CompromiseReported
            | Self::PasskeyCopied
            | Self::SignInRefused
            | Self::Announcement { .. }
            | Self::Message { .. } => Audience::Subject,
        }
    }

    /// Whether it is about the account's security, rather than what
    /// administrators announce or alert: then it is always emailed, and its email
    /// carries a link that signs the account out everywhere. Every kind is named,
    /// so a new one decides.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn security(&self) -> bool {
        match self {
            Self::Announcement { .. } | Self::AlertRaised { .. } => false,
            Self::PrimaryEmailChanged
            | Self::EmailRemoved
            | Self::AccountSecured { .. }
            | Self::Recovered
            | Self::RecoveryUndone
            | Self::HandleChanged
            | Self::DisplayNameChanged
            | Self::PasskeyRenamed
            | Self::PictureRemoved
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::DeletionScheduled { .. }
            | Self::AccountRestored
            | Self::NewDeviceSignIn
            | Self::PasskeyAdded
            | Self::PasskeyRemoved
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::EmailAdded { .. }
            | Self::TokenReused
            | Self::RecoveryStarted
            | Self::SignedOutBySupport
            | Self::CompromiseReported
            | Self::PasskeyCopied
            | Self::SignInRefused => true,
        }
    }

    /// Whether it only follows from another change, such as support signing the
    /// account out while recovering it: a transaction that already told the
    /// account something does not write it.
    #[must_use]
    pub const fn consequence(&self) -> bool {
        matches!(self, Self::SignedOutBySupport)
    }

    /// Whether its page and email link the admin dashboard's Alerts tab, while
    /// auth serves a dashboard.
    #[must_use]
    pub const fn links_alerts(&self) -> bool {
        matches!(self, Self::AlertRaised { .. })
    }

    /// Where its email goes. Every notification is emailed, except an
    /// announcement whose recipient turned [`EmailCategory::Announcements`] off.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn addressees(&self) -> Addressees {
        match self {
            Self::AccountSecured { .. } | Self::Recovered | Self::RecoveryStarted => {
                Addressees::Verified
            }
            Self::PrimaryEmailChanged | Self::EmailRemoved => Addressees::Affected,
            Self::RecoveryUndone
            | Self::HandleChanged
            | Self::DisplayNameChanged
            | Self::PasskeyRenamed
            | Self::PictureRemoved
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::DeletionScheduled { .. }
            | Self::AccountRestored
            | Self::NewDeviceSignIn
            | Self::PasskeyAdded
            | Self::PasskeyRemoved
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::EmailAdded { .. }
            | Self::TokenReused
            | Self::SignedOutBySupport
            | Self::CompromiseReported
            | Self::PasskeyCopied
            | Self::SignInRefused
            | Self::AlertRaised { .. }
            // About the account itself, so whatever the owner's preferences.
            | Self::Message { .. }
            // Through the `announcement` channel, which has workers of its own.
            | Self::Announcement { .. } => Addressees::Primary,
        }
    }

    /// Its subject: one line, in the inbox and as an email's subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        match self {
            Self::Announcement { title, .. }
            | Self::Message { title, .. }
            | Self::AlertRaised { title, .. } => title,
            Self::PrimaryEmailChanged => "Your primary email address changed",
            Self::EmailRemoved => "An email address was removed from your account",
            Self::AccountSecured { .. } => "SourceOrigin support secured your account",
            Self::Recovered => "A recovery added a passkey to your account",
            Self::RecoveryUndone => "A recovery of your account was undone",
            Self::HandleChanged => "SourceOrigin support changed your handle",
            Self::DisplayNameChanged => "SourceOrigin support changed your display name",
            Self::PasskeyRenamed => "SourceOrigin support renamed one of your passkeys",
            Self::PictureRemoved => "SourceOrigin support removed your profile picture",
            Self::AccountDisabled => "Your account was disabled",
            Self::AccountEnabled => "Your account was enabled again",
            Self::DeletionScheduled { .. } => "Your account is scheduled for deletion",
            Self::AccountRestored => "Your account was restored",
            Self::NewDeviceSignIn => "A new device signed in to your account",
            Self::PasskeyAdded => "A passkey was added to your account",
            Self::PasskeyRemoved => "A passkey was removed from your account",
            Self::IdentityLinked { .. } => "A social sign-in was linked to your account",
            Self::IdentityUnlinked { .. } => "A social sign-in was unlinked from your account",
            Self::EmailAdded { .. } => "An email address was added to your account",
            Self::TokenReused => "An app’s access to your account was revoked",
            Self::RecoveryStarted => "SourceOrigin support started recovering your account",
            Self::SignedOutBySupport => "SourceOrigin support signed your account out",
            Self::CompromiseReported => "You reported activity on your account",
            Self::PasskeyCopied => "A copy of one of your passkeys was refused",
            Self::SignInRefused => "A sign-in to your account was refused",
        }
    }

    /// What it says, below its subject.
    #[must_use]
    pub fn body(&self) -> String {
        match self {
            Self::Announcement { text, .. }
            | Self::Message { text, .. }
            | Self::AlertRaised { text, .. } => text.clone(),
            Self::PrimaryEmailChanged => "Another of your verified addresses is now the primary one. Origin Auth sends notices about your account there, and apps that read your email address see it the next time they refresh your profile. If you didn’t make this change, sign in and review your security history.".to_owned(),
            Self::EmailRemoved => "Origin Auth no longer sends anything to that address. If you didn’t remove it, sign in and review your security history.".to_owned(),
            Self::AccountSecured { kept } => {
                let undo = if *kept {
                    "If you didn’t ask for this, undo it with a passkey you kept, then contact SourceOrigin support."
                } else {
                    "If you didn’t ask for this, contact SourceOrigin support."
                };
                format!("Support signed your account out everywhere, removed your other passkeys, unlinked your social sign-ins and withdrew every app’s access, then sent a recovery link to whoever asked for help. {undo}")
            }
            Self::Recovered => "Someone used a recovery link from SourceOrigin support to add a passkey and sign in. Until the recovery settles, that passkey can sign in but can’t change your account’s security settings. If it wasn’t you, undo the recovery with a passkey from before it: that removes the new passkey, signs every device out and withdraws every app’s access. With no passkey from before it, contact SourceOrigin support, who can undo it for you.".to_owned(),
            Self::RecoveryUndone => "The recovery SourceOrigin support started no longer works: any passkey it added was removed, and every device and app was signed out.".to_owned(),
            Self::HandleChanged => "You now sign in with your new handle, and apps see it the next time they refresh your profile. Your security history says why it changed.".to_owned(),
            Self::DisplayNameChanged => "Apps see your new name the next time they refresh your profile. Your security history says why it changed.".to_owned(),
            Self::PasskeyRenamed => "It signs in as before: only its name in your settings changed. Your security history says which passkey, and why.".to_owned(),
            Self::PictureRemoved => "Apps stop showing it the next time they refresh your profile. You can choose another in your settings, and your security history says why it was removed.".to_owned(),
            Self::AccountDisabled => "Nobody can sign in to it, and every device was signed out. Contact SourceOrigin support to find out why.".to_owned(),
            Self::AccountEnabled => "You can sign in to it again.".to_owned(),
            Self::DeletionScheduled { purge_after } => format!(
                "It will be deleted for good on {}, with everything SourceOrigin knows about you. Until then, signing in lets you restore it.",
                purge_after.format("%-d %B %Y")
            ),
            Self::AccountRestored => "It is no longer scheduled for deletion.".to_owned(),
            Self::NewDeviceSignIn => "A browser that had never signed in to your account did. If it was you, there is nothing to do. If it wasn’t, open this notification and select “This wasn’t me”, or sign out everywhere from the link in its email.".to_owned(),
            Self::PasskeyAdded => "It can sign in to your account from now on. If you didn’t add it, remove it from your sign-in methods and report the change in your security history.".to_owned(),
            Self::PasskeyRemoved => "It can no longer sign in to your account, and your other devices were signed out. If you didn’t remove it, report the change in your security history.".to_owned(),
            Self::IdentityLinked { provider } => format!(
                "Your {} account can sign in to your Origin Account from now on. If you didn’t link it, unlink it from your sign-in methods and report the change in your security history.",
                provider.name()
            ),
            Self::IdentityUnlinked { provider } => format!(
                "Your {} account can no longer sign in to your Origin Account, and your other devices were signed out. If you didn’t unlink it, report the change in your security history.",
                provider.name()
            ),
            Self::EmailAdded { provider } => {
                let from = provider.map_or_else(String::new, |provider| {
                    format!(" It came from your {} account.", provider.name())
                });
                format!("Origin Auth may send notices about your account there once it is verified.{from} If you didn’t add it, remove it from your email addresses and report the change in your security history.")
            }
            Self::TokenReused => "An app used the same sign-in token twice, which happens when a token is stolen, so Origin Auth signed that app out of your account. The app asks you to sign in again. Your security history says which app it was.".to_owned(),
            Self::RecoveryStarted => "Someone asked SourceOrigin support for help signing in, and support started a recovery of your account: its link adds a new passkey. If you didn’t ask for it, cancel the recovery with a passkey you have, then contact SourceOrigin support.".to_owned(),
            Self::SignedOutBySupport => "Support ended one or more of your sessions. Sign in again to keep using your account, and see your security history for why.".to_owned(),
            Self::CompromiseReported => "You said an entry of your security history wasn’t yours, so Origin Auth signed out every other device and every app. Your security history shows what you can still undo.".to_owned(),
            Self::PasskeyCopied => "A sign-in used one of your passkeys, but its signature showed it may be a copy, so Origin Auth refused it. If your passkey’s provider doesn’t sync it between devices, remove that passkey from your sign-in methods and add a new one.".to_owned(),
            Self::SignInRefused => "Someone signed in with one of your passkeys or social sign-ins, but Origin Auth refused it: your account can’t be signed in to that way right now. If it wasn’t you, contact SourceOrigin support.".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests;
