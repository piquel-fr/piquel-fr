//! An account's own security history: the entries its events show, who caused
//! them as the subject sees it, and what to do after reporting one.

use super::{Actor, DomainEvent, GrantRevocation, RevocationReason};
use crate::{
    AuthenticationMethod, EmailId, EventId, PasskeyId, Personal, Provider, clients::RelatedOrigin,
    email::NormalizedEmail,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

impl DomainEvent {
    /// The entry this event shows in its subject's own security history, or `None`
    /// for what only auth needs: ceremonies, rejected attempts, token bookkeeping
    /// and invitations. Every variant is named, so a new one cannot be added
    /// without deciding whether its subject sees it.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    #[expect(
        clippy::too_many_lines,
        reason = "One arm per event kind, so a new kind cannot skip the decision."
    )]
    pub fn history_entry(&self) -> Option<HistoryEntry> {
        Some(match self {
            Self::AccountCreated { method, .. } => HistoryEntry::AccountCreated { method: *method },
            Self::SignedIn { method, inline, .. } => HistoryEntry::SignedIn {
                method: *method,
                origin: inline
                    .as_ref()
                    .and_then(|inline| inline.origin.value().cloned()),
            },
            Self::SessionRevoked { reason, .. } => match reason {
                // Switching accounts signs this one out of the browser.
                RevocationReason::Logout
                | RevocationReason::AccountSwitched
                | RevocationReason::RelyingPartyLogout { .. } => HistoryEntry::SignedOut,
                RevocationReason::CredentialRemoved
                | RevocationReason::IdentityUnlinked
                | RevocationReason::Admin
                | RevocationReason::AccountDisabled
                | RevocationReason::AccountDeletion
                | RevocationReason::CompromiseReported
                | RevocationReason::UserRevoked => HistoryEntry::SessionRevoked {
                    reason: reason.clone(),
                },
                RevocationReason::Expired => return None,
            },
            Self::PasskeyAdded { passkey_id } => HistoryEntry::PasskeyAdded {
                passkey_id: *passkey_id,
            },
            Self::PasskeyRenamed { passkey_id } => HistoryEntry::PasskeyRenamed {
                passkey_id: *passkey_id,
            },
            Self::PasskeyRemoved { passkey_id } => HistoryEntry::PasskeyRemoved {
                passkey_id: *passkey_id,
            },
            Self::IdentityLinked { provider, .. } => HistoryEntry::IdentityLinked {
                provider: *provider,
            },
            Self::IdentityUnlinked { provider } => HistoryEntry::IdentityUnlinked {
                provider: *provider,
            },
            Self::EmailAdded {
                email_id,
                address,
                provider,
            } => HistoryEntry::EmailAdded {
                email_id: *email_id,
                provider: *provider,
                address: match address {
                    Personal::Value(address) => Some(address.clone()),
                    Personal::Erased => None,
                },
            },
            Self::EmailVerified { email_id } => HistoryEntry::EmailVerified {
                email_id: *email_id,
            },
            Self::PrimaryEmailChanged { email_id, .. } => HistoryEntry::PrimaryEmailChanged {
                email_id: *email_id,
            },
            Self::EmailRemoved { email_id } => HistoryEntry::EmailRemoved {
                email_id: *email_id,
            },
            Self::ConsentGranted { scopes, .. } => HistoryEntry::ConsentGranted {
                scopes: scopes.clone(),
            },
            Self::ConsentRevoked { .. } => HistoryEntry::ConsentRevoked,
            Self::GrantRevoked { reason, .. } => match reason {
                GrantRevocation::RefreshReplay => HistoryEntry::TokenReused,
                // A replayed code shows once, as its `CodeReplayed`.
                GrantRevocation::CodeReplay
                | GrantRevocation::ClientRevoked
                | GrantRevocation::PolicyRejected => return None,
            },
            Self::CodeReplayed { .. } => HistoryEntry::TokenReused,
            // The reason is written for administrators and may name other people.
            Self::AccountDisabled { .. } => HistoryEntry::AccountDisabled,
            Self::AccountEnabled {} => HistoryEntry::AccountEnabled,
            Self::AdministratorGranted {} => HistoryEntry::AdministratorGranted,
            Self::AdministratorRevoked {} => HistoryEntry::AdministratorRevoked,
            Self::DashboardSignedIn { .. } => HistoryEntry::DashboardSignedIn,
            Self::DashboardSignedOut { .. } => HistoryEntry::DashboardSignedOut,
            Self::HandleChanged { .. } => HistoryEntry::HandleChanged,
            Self::DisplayNameChanged { .. } => HistoryEntry::DisplayNameChanged,
            Self::PictureChanged { .. } => HistoryEntry::PictureChanged,
            Self::PictureRemoved {} => HistoryEntry::PictureRemoved,
            Self::RecoveryStarted { .. } => HistoryEntry::RecoveryStarted,
            Self::RecoveryCompleted { passkey_id, .. } => HistoryEntry::Recovered {
                passkey_id: *passkey_id,
            },
            Self::RecoveryUndone { .. } => HistoryEntry::RecoveryUndone,
            Self::CompromiseReported { event_id } => HistoryEntry::CompromiseReported {
                event_id: *event_id,
            },
            Self::AccountExported {} => HistoryEntry::AccountExported,
            Self::AccountDeletionScheduled { purge_after } => HistoryEntry::DeletionScheduled {
                purge_after: *purge_after,
            },
            Self::AccountRestored {} => HistoryEntry::AccountRestored,
            Self::Imported(audit) => HistoryEntry::Legacy {
                action: audit.action.clone(),
                outcome: audit.outcome.clone(),
            },
            Self::SignInFailed { .. }
            | Self::PasskeyConfirmed { .. }
            | Self::GrantIssued { .. }
            | Self::InvitationCreated { .. }
            | Self::InvitationRevoked { .. }
            // The app's own mistake, or a stolen code's failed use: either way, the
            // account's owner has nothing to do about it.
            | Self::CodeRedemptionFailed { .. }
            // The handle was the account's no more.
            | Self::HandleReleased { .. }
            // Reservations concern names, not an account.
            | Self::HandleReserved { .. }
            | Self::HandleUnreserved { .. }
            // Changes to an application concern no account.
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
            // The delivery queue is operations' business; the audit keeps it.
            | Self::DeliveryRetried { .. }
            | Self::DeliveryCancelled { .. }
            | Self::SigningKeyChanged { .. }
            | Self::AuditHistoryPruned { .. }
            | Self::AuditChainVerified(_)
            // Alerts are the administrators', about the service.
            | Self::AlertRaised { .. }
            | Self::AlertCleared { .. }
            // A read may be a misclick or a confidential inquiry; the owner sees
            // changes, each with its reason, not what an administrator looked at.
            | Self::AccountViewed {}
            // Recipients read announcements in their inbox.
            | Self::AnnouncementSent { .. }
            // Nobody can read the history of an account that no longer exists.
            | Self::AccountPurged {} => return None,
        })
    }
}

/// What an entry of an account's security history says happened, serialized as a
/// stable `kind` with its details beside it, e.g.
/// `{"kind": "passkey.added", "passkey_id": …}`. Built by
/// [`DomainEvent::history_entry`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub enum HistoryEntry {
    /// The account was created.
    #[serde(rename = "account.created")]
    AccountCreated {
        /// How the person proved who they are.
        method: AuthenticationMethod,
    },
    /// A browser signed in.
    #[serde(rename = "session.signed_in")]
    SignedIn {
        /// How it authenticated.
        method: AuthenticationMethod,
        /// The application page's origin, when it signed the user in itself and
        /// the origin was not erased since.
        #[serde(skip_serializing_if = "Option::is_none")]
        origin: Option<RelatedOrigin>,
    },
    /// A browser signed out, at the user's or an application's request, or by
    /// signing in to another account.
    #[serde(rename = "session.signed_out")]
    SignedOut,
    /// A session was ended for the user.
    #[serde(rename = "session.revoked")]
    SessionRevoked {
        /// Why.
        reason: RevocationReason,
    },
    /// A passkey was added.
    #[serde(rename = "passkey.added")]
    PasskeyAdded {
        /// The passkey.
        passkey_id: PasskeyId,
    },
    /// A passkey was renamed.
    #[serde(rename = "passkey.renamed")]
    PasskeyRenamed {
        /// The passkey.
        passkey_id: PasskeyId,
    },
    /// A passkey was removed.
    #[serde(rename = "passkey.removed")]
    PasskeyRemoved {
        /// The passkey.
        passkey_id: PasskeyId,
    },
    /// A provider identity was linked.
    #[serde(rename = "identity.linked")]
    IdentityLinked {
        /// Its provider.
        provider: Provider,
    },
    /// A provider identity was unlinked.
    #[serde(rename = "identity.unlinked")]
    IdentityUnlinked {
        /// Its provider.
        provider: Provider,
    },
    /// An email address was added.
    #[serde(rename = "email.added")]
    EmailAdded {
        /// The address's ID.
        email_id: EmailId,
        /// The address, until retention deletes it.
        address: Option<NormalizedEmail>,
        /// The provider it was imported from, if any.
        provider: Option<Provider>,
    },
    /// An email address was verified.
    #[serde(rename = "email.verified")]
    EmailVerified {
        /// The address's ID.
        email_id: EmailId,
    },
    /// Another address became the primary one.
    #[serde(rename = "email.primary_changed")]
    PrimaryEmailChanged {
        /// The new primary address's ID.
        email_id: EmailId,
    },
    /// An email address was removed.
    #[serde(rename = "email.removed")]
    EmailRemoved {
        /// The address's ID.
        email_id: EmailId,
    },
    /// The user approved an application's access.
    #[serde(rename = "consent.granted")]
    ConsentGranted {
        /// The approved scopes.
        scopes: Vec<String>,
    },
    /// An application's access was withdrawn.
    #[serde(rename = "consent.revoked")]
    ConsentRevoked,
    /// A refresh token or authorization code was used twice, so the access it
    /// granted was revoked.
    #[serde(rename = "token.reused")]
    TokenReused,
    /// The account was disabled.
    #[serde(rename = "account.disabled")]
    AccountDisabled,
    /// The account was reactivated.
    #[serde(rename = "account.enabled")]
    AccountEnabled,
    /// The account became an administrator.
    #[serde(rename = "administrator.granted")]
    AdministratorGranted,
    /// The account's administrator rights were removed.
    #[serde(rename = "administrator.revoked")]
    AdministratorRevoked,
    /// The account signed in to the admin dashboard.
    #[serde(rename = "administrator.dashboard_signed_in")]
    DashboardSignedIn,
    /// The account's dashboard session ended: it signed out, or lost its rights.
    #[serde(rename = "administrator.dashboard_signed_out")]
    DashboardSignedOut,
    /// The account's handle changed.
    #[serde(rename = "account.handle_changed")]
    HandleChanged,
    /// The account's display name changed.
    #[serde(rename = "account.display_name_changed")]
    DisplayNameChanged,
    /// The account got a new profile picture.
    #[serde(rename = "account.picture_changed")]
    PictureChanged,
    /// The account's profile picture was removed.
    #[serde(rename = "account.picture_removed")]
    PictureRemoved,
    /// An operator started recovering the account.
    #[serde(rename = "account.recovery_started")]
    RecoveryStarted,
    /// A recovery link enrolled a new passkey.
    #[serde(rename = "account.recovered")]
    Recovered {
        /// The passkey it enrolled.
        passkey_id: PasskeyId,
    },
    /// A recovery was undone or cancelled.
    #[serde(rename = "account.recovery_undone")]
    RecoveryUndone,
    /// The user reported an entry as not theirs.
    #[serde(rename = "compromise.reported")]
    CompromiseReported {
        /// The reported entry.
        event_id: EventId,
    },
    /// The user downloaded their data.
    #[serde(rename = "account.exported")]
    AccountExported,
    /// The account was scheduled for deletion.
    #[serde(rename = "account.deletion_scheduled")]
    DeletionScheduled {
        /// When it is purged, unless it is restored first.
        purge_after: DateTime<Utc>,
    },
    /// The account was restored before its deletion.
    #[serde(rename = "account.restored")]
    AccountRestored,
    /// A row of the audit log that preceded typed events.
    #[serde(rename = "legacy")]
    Legacy {
        /// The logged action, e.g. `passkey.login`.
        action: String,
        /// `success`, `failure` or `rejected`.
        outcome: String,
    },
}

impl HistoryEntry {
    /// Whether the account can report this entry, once its own session caused it,
    /// as not theirs. Not its creation, which made the account; nor a report, or a
    /// sign-out another change caused. Nor a recovery: the answer to a recovery the
    /// owner didn't ask for is undoing it, which takes back more than a report and
    /// needs no session. Nor what only takes access away: a withdrawn consent, or an
    /// undone recovery.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn reportable(&self) -> bool {
        match self {
            Self::AccountCreated { .. }
            | Self::SessionRevoked { .. }
            | Self::CompromiseReported { .. }
            | Self::ConsentRevoked
            | Self::RecoveryStarted
            | Self::Recovered { .. }
            | Self::RecoveryUndone => false,
            Self::SignedIn { .. }
            | Self::SignedOut
            | Self::PasskeyAdded { .. }
            | Self::PasskeyRenamed { .. }
            | Self::PasskeyRemoved { .. }
            | Self::IdentityLinked { .. }
            | Self::IdentityUnlinked { .. }
            | Self::EmailAdded { .. }
            | Self::EmailVerified { .. }
            | Self::PrimaryEmailChanged { .. }
            | Self::EmailRemoved { .. }
            | Self::ConsentGranted { .. }
            | Self::TokenReused
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::AdministratorGranted
            | Self::AdministratorRevoked
            | Self::DashboardSignedIn
            | Self::DashboardSignedOut
            | Self::HandleChanged
            | Self::DisplayNameChanged
            | Self::PictureChanged
            | Self::PictureRemoved
            | Self::AccountExported
            | Self::DeletionScheduled { .. }
            | Self::AccountRestored
            | Self::Legacy { .. } => true,
        }
    }

    /// What the user should still do after reporting this entry as not theirs:
    /// undo the credential or email address it added. Those actions need a passkey
    /// confirmation, so a stolen cookie that can report an entry still cannot
    /// change credentials.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn follow_up(&self) -> Option<FollowUp> {
        match self {
            Self::PasskeyAdded { passkey_id } => Some(FollowUp::RemovePasskey {
                passkey_id: *passkey_id,
            }),
            Self::IdentityLinked { provider } => Some(FollowUp::UnlinkIdentity {
                provider: *provider,
            }),
            Self::EmailAdded { email_id, .. } => Some(FollowUp::RemoveEmail {
                email_id: *email_id,
            }),
            Self::AccountCreated { .. }
            | Self::SignedIn { .. }
            | Self::SignedOut
            | Self::SessionRevoked { .. }
            | Self::PasskeyRenamed { .. }
            | Self::PasskeyRemoved { .. }
            | Self::IdentityUnlinked { .. }
            | Self::EmailVerified { .. }
            | Self::PrimaryEmailChanged { .. }
            | Self::EmailRemoved { .. }
            | Self::ConsentGranted { .. }
            | Self::ConsentRevoked
            | Self::TokenReused
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::AdministratorGranted
            | Self::AdministratorRevoked
            | Self::DashboardSignedIn
            | Self::DashboardSignedOut
            | Self::HandleChanged
            | Self::DisplayNameChanged
            | Self::PictureChanged
            | Self::PictureRemoved
            | Self::RecoveryStarted
            | Self::Recovered { .. }
            | Self::RecoveryUndone
            | Self::CompromiseReported { .. }
            | Self::AccountExported
            | Self::DeletionScheduled { .. }
            | Self::AccountRestored
            | Self::Legacy { .. } => None,
        }
    }
}

/// An action that undoes a reported entry, e.g.
/// `{"action": "remove_passkey", "passkey_id": …}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FollowUp {
    /// Remove the passkey the entry added.
    RemovePasskey {
        /// The passkey.
        passkey_id: PasskeyId,
    },
    /// Unlink the identity the entry linked.
    UnlinkIdentity {
        /// Its provider.
        provider: Provider,
    },
    /// Remove the email address the entry added.
    RemoveEmail {
        /// The address.
        email_id: EmailId,
    },
}

crate::str_enum! {
    /// Who caused a history entry, as its subject sees it. Operators and
    /// administrators are not named.
    pub enum HistoryActor {
        /// The account's own user.
        Account = "account",
        /// An administrator, through the admin dashboard.
        Admin = "admin",
        /// An operator, through the service's command line.
        Operator = "operator",
        /// An application.
        Client = "client",
        /// A background job.
        System = "system",
        /// An unauthenticated browser.
        Anonymous = "anonymous",
        /// Unknown: imported audit rows never recorded who acted.
        Unrecorded = "unrecorded",
    }
}

impl From<&Actor> for HistoryActor {
    /// Keeps only the kind of actor. Users act only on their own account.
    fn from(actor: &Actor) -> Self {
        match actor {
            Actor::User { .. } => Self::Account,
            Actor::Admin { .. } => Self::Admin,
            Actor::Cli { .. } => Self::Operator,
            Actor::Client { .. } => Self::Client,
            Actor::System { .. } => Self::System,
            Actor::Anonymous => Self::Anonymous,
            Actor::Unrecorded => Self::Unrecorded,
        }
    }
}
