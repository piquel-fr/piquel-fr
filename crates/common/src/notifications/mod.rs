//! What an account's owner is told about their account: the notifications of
//! their inbox, each derived from an event about the account by
//! [`DomainEvent::notification`](crate::events::DomainEvent::notification).
//!
//! A notification holds no personal data and renders from itself alone, so it
//! reads the same once its event's personal data is erased, or the event pruned.
//! Its event's security history entry, while kept, tells the rest.

use crate::{
    AnnouncementId,
    events::{Actor, DomainEvent},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What an account's owner is told, stored as it serializes, e.g.
/// `{"kind": "deletion_scheduled", "purge_after": …}`. Never rename a released
/// kind: a newer release's kinds are skipped by older ones, not misread.
///
/// A variant holds only IDs, enums, flags and timestamps, never a secret, an
/// address or a [`Personal`](crate::Personal) value, except an announcement,
/// which holds the text administrators wrote. A targeted announcement's text,
/// which may name its recipients, goes with them: purging an account deletes its
/// notifications, and the announcement once its last recipient is purged.
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
}

impl DomainEvent {
    /// The notification this event, caused by `actor`, gives its subject, if
    /// any. Every variant is named, so a new event cannot be added without
    /// deciding whether its subject is told.
    ///
    /// A change the owner makes to their own name tells them nothing they don't
    /// know; one made by support does. Notices that are emails today, about the
    /// account's addresses and recovery, notify whoever made the change, since
    /// the email they replace is sent either way.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub fn notification(&self, actor: &Actor) -> Option<Notification> {
        let by_support = matches!(actor, Actor::Admin { .. } | Actor::Cli { .. });
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
            Self::PictureRemoved {} if by_support => Notification::PictureRemoved,
            Self::AccountDisabled { .. } => Notification::AccountDisabled,
            Self::AccountEnabled {} => Notification::AccountEnabled,
            Self::AccountDeletionScheduled { purge_after } => Notification::DeletionScheduled {
                purge_after: *purge_after,
            },
            Self::AccountRestored {} => Notification::AccountRestored,
            // The owner made it, so they know. Only the owner, or their social
            // signup, sets a picture.
            Self::HandleChanged { .. }
            | Self::DisplayNameChanged { .. }
            | Self::PictureRemoved {}
            | Self::PictureChanged { .. }
            // Its link is the email; whoever lost every passkey reads no inbox.
            | Self::RecoveryStarted { revoke: None, .. }
            // The account's first verified address: nothing was replaced.
            | Self::PrimaryEmailChanged {
                previous_email_id: None,
                ..
            }
            // Sign-ins, sessions, credentials and consents: their security alerts
            // are #83's to decide.
            | Self::AccountCreated { .. }
            | Self::SignedIn { .. }
            | Self::SignInFailed { .. }
            | Self::SessionRevoked { .. }
            | Self::PasskeyConfirmed { .. }
            | Self::PasskeyAdded { .. }
            | Self::PasskeyRenamed { .. }
            | Self::PasskeyRemoved { .. }
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::EmailAdded { .. }
            | Self::EmailVerified { .. }
            | Self::ConsentGranted { .. }
            | Self::ConsentRevoked { .. }
            | Self::GrantIssued { .. }
            | Self::GrantRevoked { .. }
            | Self::CodeReplayed { .. }
            | Self::CodeRedemptionFailed { .. }
            | Self::CompromiseReported { .. }
            | Self::AccountExported {}
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
            | Self::AlertRaised { .. }
            | Self::AlertCleared { .. }
            | Self::Imported(_) => return None,
        })
    }
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
    /// Where its email goes. Every notification is emailed: each is about the
    /// account itself, so none can be turned off.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn addressees(&self) -> Addressees {
        match self {
            Self::AccountSecured { .. } | Self::Recovered => Addressees::Verified,
            Self::PrimaryEmailChanged | Self::EmailRemoved => Addressees::Affected,
            Self::RecoveryUndone
            | Self::HandleChanged
            | Self::DisplayNameChanged
            | Self::PictureRemoved
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::DeletionScheduled { .. }
            | Self::AccountRestored
            // Through the `announcement` channel, which has workers of its own.
            | Self::Announcement { .. } => Addressees::Primary,
        }
    }

    /// Its subject: one line, in the inbox and as an email's subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        match self {
            Self::Announcement { title, .. } => title,
            Self::PrimaryEmailChanged => "Your primary email address changed",
            Self::EmailRemoved => "An email address was removed from your account",
            Self::AccountSecured { .. } => "Piquel support secured your account",
            Self::Recovered => "A recovery added a passkey to your account",
            Self::RecoveryUndone => "A recovery of your account was undone",
            Self::HandleChanged => "Piquel support changed your handle",
            Self::DisplayNameChanged => "Piquel support changed your display name",
            Self::PictureRemoved => "Piquel support removed your profile picture",
            Self::AccountDisabled => "Your account was disabled",
            Self::AccountEnabled => "Your account was enabled again",
            Self::DeletionScheduled { .. } => "Your account is scheduled for deletion",
            Self::AccountRestored => "Your account was restored",
        }
    }

    /// What it says, below its subject.
    #[must_use]
    pub fn body(&self) -> String {
        match self {
            Self::Announcement { text, .. } => text.clone(),
            Self::PrimaryEmailChanged => "Another of your verified addresses is now the primary one. Piquel sends notices about your account there, and apps that read your email address see it the next time they refresh your profile. If you didn’t make this change, sign in and review your security history.".to_owned(),
            Self::EmailRemoved => "Piquel no longer sends anything to that address. If you didn’t remove it, sign in and review your security history.".to_owned(),
            Self::AccountSecured { kept } => {
                let undo = if *kept {
                    "If you didn’t ask for this, undo it with a passkey you kept, then contact Piquel support."
                } else {
                    "If you didn’t ask for this, contact Piquel support."
                };
                format!("Support signed your account out everywhere, removed your other passkeys, unlinked your social sign-ins and withdrew every app’s access, then sent a recovery link to whoever asked for help. {undo}")
            }
            Self::Recovered => "Someone used a recovery link from Piquel support to add a passkey and sign in. Until the recovery settles, that passkey can sign in but can’t change your account’s security settings. If it wasn’t you, undo the recovery with a passkey from before it: that removes the new passkey, signs every device out and withdraws every app’s access. With no passkey from before it, contact Piquel support, who can undo it for you.".to_owned(),
            Self::RecoveryUndone => "The recovery Piquel support started no longer works: any passkey it added was removed, and every device and app was signed out.".to_owned(),
            Self::HandleChanged => "You now sign in with your new handle, and apps see it the next time they refresh your profile. Your security history says why it changed.".to_owned(),
            Self::DisplayNameChanged => "Apps see your new name the next time they refresh your profile. Your security history says why it changed.".to_owned(),
            Self::PictureRemoved => "Apps stop showing it the next time they refresh your profile. You can choose another in your settings, and your security history says why it was removed.".to_owned(),
            Self::AccountDisabled => "Nobody can sign in to it, and every device was signed out. Contact Piquel support to find out why.".to_owned(),
            Self::AccountEnabled => "You can sign in to it again.".to_owned(),
            Self::DeletionScheduled { purge_after } => format!(
                "It will be deleted for good on {}, with everything Piquel knows about you. Until then, signing in lets you restore it.",
                purge_after.format("%-d %B %Y")
            ),
            Self::AccountRestored => "It is no longer scheduled for deletion.".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests;
