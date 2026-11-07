//! Typed domain events: what changed in an account or its grants, who changed it,
//! and where the request came from.
//!
//! These are vocabulary only. The database crate records them in the transaction
//! that made the change, keeping every [`Personal`] value and the
//! [`RequestOrigin`](crate::events::RequestOrigin) apart from the event so both can be deleted on their own.

/// Who caused an event, where the request came from, and why.
mod context;
/// Projection of events into an account's own security history.
mod history;
/// The values event payloads carry beside IDs.
mod payload;
/// User agent classification on real browser headers.
#[cfg(test)]
mod tests;

pub use context::{
    Actor, Browser, EventContext, JobName, Platform, RequestOrigin, UserAgentFamily,
};
pub use history::{FollowUp, HistoryActor, HistoryEntry};
pub use payload::{
    CodeRedemptionFailure, GrantRevocation, ImportedAudit, InlineSignIn, RecordedOrigin,
    RecoveryRevocation, RevocationReason, SignInFailure, SigningKeyChange,
};

use crate::{
    AnnouncementId, AuthenticationMethod, ClientId, DeliveryId, EmailId, EventId, Handle,
    PasskeyId, Personal, PictureId, Provider, RecoveryId, SessionId, TokenId,
    admin::{AuditVerification, ChainBreak, ChainProblem, VerificationKeys},
    clients::{ClientField, ClientKind},
    email::NormalizedEmail,
    protocol::jwt::KeyId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Something that happened to an account or its grants, recorded in the
/// transaction that made the change. Adding a variant makes every `match` handle it.
///
/// Outside [`Personal`], a variant holds only typed auth IDs, enums, scopes,
/// timestamps and counts, so a secret, token or raw header cannot end up in one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum DomainEvent {
    /// An account was created. Its first session follows as [`Self::SignedIn`].
    AccountCreated {
        /// How the person proved who they are: a passkey, or a provider for social signup.
        method: AuthenticationMethod,
        /// Whether an invitation was redeemed.
        invited: bool,
    },
    /// A browser signed in: it got a new session, or re-authenticated its current one.
    SignedIn {
        /// The new or re-authenticated session.
        session_id: SessionId,
        /// How the browser authenticated.
        method: AuthenticationMethod,
        /// Set when an application's own page signed the user in, rather than
        /// auth's pages. The session then has no browser cookie.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inline: Option<InlineSignIn>,
    },
    /// A passkey or provider authentication was rejected, whether signing in or
    /// confirming a session. Only the rejected attempt is recorded; nothing changed.
    SignInFailed {
        /// The method that was attempted.
        method: AuthenticationMethod,
        /// Why it was rejected.
        reason: SignInFailure,
    },
    /// A session ended early. Revoking several sessions records one event each.
    SessionRevoked {
        /// The revoked session.
        session_id: SessionId,
        /// Why it was revoked; the actor says who revoked it.
        reason: RevocationReason,
    },
    /// A session proved possession of a passkey for protected actions.
    PasskeyConfirmed {
        /// The confirmed session.
        session_id: SessionId,
    },
    /// A passkey was added to the account.
    PasskeyAdded {
        /// The new passkey.
        passkey_id: PasskeyId,
    },
    /// A passkey's label changed.
    PasskeyRenamed {
        /// The renamed passkey.
        passkey_id: PasskeyId,
    },
    /// A passkey was removed from the account.
    PasskeyRemoved {
        /// The removed passkey.
        passkey_id: PasskeyId,
    },
    /// A provider identity was linked to the account.
    IdentityLinked {
        /// The identity's provider.
        provider: Provider,
        /// The provider's subject identifier, which identifies the person there.
        subject: Personal<String>,
    },
    /// A provider identity was unlinked from the account.
    IdentityUnlinked {
        /// The identity's provider.
        provider: Provider,
    },
    /// An unverified email address was added to the account. Its verification
    /// email is queued with it, unless a provider imported it verified, which
    /// [`Self::EmailVerified`] then records.
    EmailAdded {
        /// The new address.
        email_id: EmailId,
        /// The address itself.
        address: Personal<NormalizedEmail>,
        /// The provider it was imported from, when signing up or linking with one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<Provider>,
    },
    /// Someone holding the address's verification link confirmed it, or the
    /// provider it was imported from is authoritative for it.
    EmailVerified {
        /// The verified address.
        email_id: EmailId,
    },
    /// Another verified address became the account's primary one, which the
    /// OIDC `email` claim reports. The previous primary address is told.
    PrimaryEmailChanged {
        /// The new primary address.
        email_id: EmailId,
        /// The previous one; `None` when the account had no verified address.
        #[serde(default)]
        previous_email_id: Option<EmailId>,
    },
    /// An email address was removed from the account.
    EmailRemoved {
        /// The removed address.
        email_id: EmailId,
    },
    /// The user approved a client's access, adding to any earlier consent.
    ConsentGranted {
        /// The approved client.
        client_id: ClientId,
        /// The approved scopes, drawn from the client's registered allowlist.
        scopes: Vec<String>,
    },
    /// A client's access to the account was withdrawn: its consent, refresh grants
    /// and unused codes. An untrusted client asks for consent again at its next
    /// sign-in; a trusted one is let back in. Undoing a recovery withdraws every
    /// client's access.
    ConsentRevoked {
        /// The client.
        client_id: ClientId,
    },
    /// A client exchanged an authorization code for tokens.
    GrantIssued {
        /// The client the tokens were issued to.
        client_id: ClientId,
        /// The refresh family created, when the grant includes refresh tokens.
        family_id: Option<TokenId>,
        /// The granted scopes.
        scopes: Vec<String>,
    },
    /// A refresh family was revoked. Rotations are not events; they are counted as metrics.
    GrantRevoked {
        /// The client the family was issued to.
        client_id: ClientId,
        /// The revoked family.
        family_id: TokenId,
        /// Why it was revoked.
        reason: GrantRevocation,
    },
    /// A client redeemed an authorization code a second time. Every refresh family
    /// issued from the code is revoked, each with its own [`Self::GrantRevoked`].
    CodeReplayed {
        /// The client that redeemed the code.
        client_id: ClientId,
    },
    /// A client's redemption of an authorization code failed, which expired the
    /// code: it cannot be redeemed again.
    CodeRedemptionFailed {
        /// The client that redeemed the code.
        client_id: ClientId,
        /// Why it failed.
        reason: CodeRedemptionFailure,
    },
    /// A signup invitation was created.
    InvitationCreated {
        /// When the invitation stops being accepted.
        expires_at: DateTime<Utc>,
    },
    /// An unredeemed signup invitation was revoked.
    InvitationRevoked {
        /// The revoked invitation.
        invitation_id: TokenId,
    },
    /// The account was disabled. Its sessions follow as [`Self::SessionRevoked`].
    AccountDisabled {
        /// Why, as the administrator or operator wrote it. Free text may name people.
        reason: Personal<String>,
    },
    /// A disabled account was reactivated.
    AccountEnabled {},
    /// An administrator viewed the account's details, which hold personal data.
    /// Kept for the audit only: the owner's history shows changes, not reads.
    AccountViewed {},
    /// The account became an administrator.
    AdministratorGranted {},
    /// The account's administrator rights were removed.
    AdministratorRevoked {},
    /// The account's handle changed. Relying parties see it as a new
    /// `preferred_username` once they refresh the profile.
    HandleChanged {
        /// The previous handle. A username from before the handle rules may break
        /// them, so it stays text.
        old: Personal<String>,
        /// The new handle.
        new: Personal<Handle>,
    },
    /// The account's display name changed. Relying parties see it as a new
    /// `name` once they refresh the profile.
    DisplayNameChanged {
        /// The previous name.
        old: Personal<String>,
        /// The new name.
        new: Personal<String>,
    },
    /// The account got a new profile picture, replacing any other. Relying
    /// parties see its new URL as `picture` once they refresh the profile.
    PictureChanged {
        /// The new picture.
        picture_id: PictureId,
    },
    /// The account's profile picture was removed.
    PictureRemoved {},
    /// An operator deleted a released handle, so anyone may claim it again. Its
    /// former owner, if not purged, is the subject.
    HandleReleased {
        /// The released handle.
        handle: Personal<Handle>,
    },
    /// An administrator reserved a handle: nobody takes it, or a look-alike, until
    /// an administrator gives it to an account or removes it. The event's reason
    /// says who or what it is kept for.
    HandleReserved {
        /// The reserved handle.
        handle: Handle,
    },
    /// An administrator removed a handle from the reserved list.
    HandleUnreserved {
        /// The handle.
        handle: Handle,
    },
    /// An OIDC client was registered, enabled. A confidential client got its first secret.
    ClientRegistered {
        /// The new client.
        client_id: ClientId,
        /// Whether it is public or confidential.
        kind: ClientKind,
    },
    /// A client's name, redirect URIs, scopes, refresh or consent policy changed.
    ClientUpdated {
        /// The changed client.
        client_id: ClientId,
        /// The settings that changed; empty in events recorded before they were.
        #[serde(default)]
        changed: Vec<ClientField>,
    },
    /// A disabled client was enabled again.
    ClientEnabled {
        /// The enabled client.
        client_id: ClientId,
    },
    /// A client was disabled: it can no longer authorize, exchange or refresh.
    ClientDisabled {
        /// The disabled client.
        client_id: ClientId,
    },
    /// An operator suspended a client: it is disabled, and its owner cannot enable
    /// it until an operator lifts the suspension.
    ClientSuspended {
        /// The suspended client.
        client_id: ClientId,
    },
    /// An operator lifted a client's suspension. It stays disabled until enabled.
    ClientSuspensionLifted {
        /// The client.
        client_id: ClientId,
    },
    /// A client was deleted. Its ID stays reserved, it is disabled, its refresh
    /// families are revoked, and its secrets and consents are removed.
    ClientDeleted {
        /// The deleted client.
        client_id: ClientId,
    },
    /// A confidential client got a new secret. Its earlier secrets keep working until
    /// `previous_expire_at` at the latest, so the client can redeploy in between.
    ClientSecretRotated {
        /// The client.
        client_id: ClientId,
        /// When its earlier secrets stop working; now, for an immediate revocation.
        previous_expire_at: DateTime<Utc>,
    },
    /// An operator started recovering the account: its sessions and refresh
    /// grants end, its unverified addresses go, and a link that enrolls one new
    /// passkey is sent to its owner, or only printed when `revoke` is set. Its
    /// sessions follow as [`Self::SessionRevoked`].
    RecoveryStarted {
        /// The recovery.
        recovery_id: RecoveryId,
        /// When its link stops working.
        expires_at: DateTime<Utc>,
        /// Set when the account was in someone else's hands (`--revoke`): every
        /// passkey but the kept ones was revoked, every identity unlinked and
        /// every consent withdrawn, each recorded before this event.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoke: Option<RecoveryRevocation>,
    },
    /// A recovery's link enrolled a new passkey, which also signed its browser in.
    RecoveryCompleted {
        /// The recovery.
        recovery_id: RecoveryId,
        /// The passkey it enrolled.
        passkey_id: PasskeyId,
    },
    /// A recovery in probation was undone, by its owner with a passkey from
    /// before it or by support: its passkey, every consent and every refresh grant
    /// were taken back, recorded before it as [`Self::PasskeyRemoved`] and
    /// [`Self::ConsentRevoked`]. Every session ends after it
    /// ([`Self::SessionRevoked`]). An unused link is cancelled instead, which
    /// records only this event.
    RecoveryUndone {
        /// The recovery.
        recovery_id: RecoveryId,
    },
    /// An operator made a failed delivery, or a cancelled unordered one, due again.
    DeliveryRetried {
        /// The delivery.
        delivery_id: DeliveryId,
    },
    /// An operator cancelled a pending or failed delivery, such as a notice to a
    /// user, which unblocks the deliveries ordered after it.
    DeliveryCancelled {
        /// The delivery.
        delivery_id: DeliveryId,
    },
    /// An origin of a client's was approved for inline passkey sign-in, so
    /// `/.well-known/webauthn` lists it.
    RelatedOriginApproved {
        /// The client whose pages are on the origin.
        client_id: ClientId,
        /// The approved origin.
        origin: RecordedOrigin,
    },
    /// An approved origin was removed: its pages can no longer sign users in.
    RelatedOriginRemoved {
        /// The client whose pages were on the origin.
        client_id: ClientId,
        /// The removed origin.
        origin: RecordedOrigin,
    },
    /// The user reported an event of their history as not theirs. Their other
    /// sessions follow as [`Self::SessionRevoked`], and every refresh family of the
    /// account is revoked with them.
    CompromiseReported {
        /// The reported event.
        event_id: EventId,
    },
    /// A signing key moved through its lifecycle (see [`SigningKeyChange`]). It
    /// concerns no account.
    SigningKeyChanged {
        /// The key's `kid`.
        key_id: KeyId,
        /// What happened to it.
        change: SigningKeyChange,
    },
    /// The user downloaded a copy of their account's data.
    AccountExported {},
    /// The account was scheduled for deletion. Its sessions follow as
    /// [`Self::SessionRevoked`], and every refresh family is revoked with them.
    AccountDeletionScheduled {
        /// When the account is purged, unless it is restored first.
        purge_after: DateTime<Utc>,
    },
    /// An account scheduled for deletion was restored.
    AccountRestored {},
    /// The account was deleted with everything auth knew about the person: the
    /// personal data of every event it was the subject or actor of went with it.
    AccountPurged {},
    /// The audit history was pruned: every event through the checkpoint at
    /// `through` was deleted, and that checkpoint became the chain's anchor. It
    /// concerns no account.
    AuditHistoryPruned {
        /// The position of the checkpoint pruned through.
        through: u64,
        /// How many events were deleted.
        deleted: u64,
    },
    /// The audit chain was verified, by `auth-service audit verify` or from the
    /// dashboard, with what that found. It concerns no account.
    AuditChainVerified(AuditVerification),
    /// An administrator or operator sent an announcement, such as a security
    /// incident or a change to the privacy policy, to every account or to chosen
    /// ones. Each recipient with a primary verified address is emailed it, and
    /// every recipient gets it as a notification in their inbox. It concerns no
    /// one account.
    AnnouncementSent {
        /// The announcement.
        announcement_id: AnnouncementId,
        /// How many accounts it went to.
        recipients: u64,
    },
    /// A row of the security audit log that preceded typed events. Only
    /// migrations write these; its fields are private, so one is only ever read back.
    Imported(ImportedAudit),
}

impl DomainEvent {
    /// The payload version every kind starts at.
    pub const FIRST_VERSION: i16 = 1;

    /// The payload version stored with the event. A change an older release could
    /// not decode, such as a new variant of an enum inside a payload, gets the next
    /// version of that kind, written only by the events that use it, so older
    /// releases still read the others. See `docs/architecture/database-crate.md`.
    #[must_use]
    pub const fn version(&self) -> i16 {
        match self {
            Self::SessionRevoked {
                reason: RevocationReason::UserRevoked,
                ..
            } => 2,
            Self::RelatedOriginApproved { origin, .. }
            | Self::RelatedOriginRemoved { origin, .. }
            | Self::SignedIn {
                inline: Some(InlineSignIn { origin, .. }),
                ..
            } => origin.version(),
            Self::AuditChainVerified(verification) => verification.version(),
            _ => Self::FIRST_VERSION,
        }
    }

    /// The client the event concerns, stored in its own column for filtering.
    #[must_use]
    pub fn client_id(&self) -> Option<&ClientId> {
        match self {
            Self::ConsentGranted { client_id, .. }
            | Self::ConsentRevoked { client_id }
            | Self::GrantIssued { client_id, .. }
            | Self::GrantRevoked { client_id, .. }
            | Self::CodeReplayed { client_id }
            | Self::CodeRedemptionFailed { client_id, .. }
            | Self::ClientRegistered { client_id, .. }
            | Self::ClientUpdated { client_id, .. }
            | Self::ClientEnabled { client_id }
            | Self::ClientDisabled { client_id }
            | Self::ClientSuspended { client_id }
            | Self::ClientSuspensionLifted { client_id }
            | Self::ClientDeleted { client_id }
            | Self::ClientSecretRotated { client_id, .. }
            | Self::RelatedOriginApproved { client_id, .. }
            | Self::RelatedOriginRemoved { client_id, .. }
            | Self::SignedIn {
                inline: Some(InlineSignIn { client_id, .. }),
                ..
            }
            | Self::SessionRevoked {
                reason: RevocationReason::RelyingPartyLogout { client_id },
                ..
            } => Some(client_id),
            Self::AccountCreated { .. }
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
            | Self::PrimaryEmailChanged { .. }
            | Self::EmailRemoved { .. }
            | Self::InvitationCreated { .. }
            | Self::InvitationRevoked { .. }
            | Self::AccountDisabled { .. }
            | Self::AccountEnabled {}
            | Self::AccountViewed {}
            | Self::AdministratorGranted {}
            | Self::AdministratorRevoked {}
            | Self::HandleChanged { .. }
            | Self::DisplayNameChanged { .. }
            | Self::PictureChanged { .. }
            | Self::PictureRemoved {}
            | Self::RecoveryStarted { .. }
            | Self::RecoveryCompleted { .. }
            | Self::RecoveryUndone { .. }
            | Self::DeliveryRetried { .. }
            | Self::DeliveryCancelled { .. }
            | Self::HandleReleased { .. }
            | Self::HandleReserved { .. }
            | Self::HandleUnreserved { .. }
            | Self::CompromiseReported { .. }
            | Self::SigningKeyChanged { .. }
            | Self::AccountExported {}
            | Self::AccountDeletionScheduled { .. }
            | Self::AccountRestored {}
            | Self::AccountPurged {}
            | Self::AuditHistoryPruned { .. }
            | Self::AuditChainVerified(_)
            | Self::AnnouncementSent { .. }
            | Self::Imported(_) => None,
        }
    }

    /// The session the event concerns, stored in its own column for filtering.
    #[must_use]
    pub const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::SignedIn { session_id, .. }
            | Self::SessionRevoked { session_id, .. }
            | Self::PasskeyConfirmed { session_id } => Some(*session_id),
            Self::AccountCreated { .. }
            | Self::SignInFailed { .. }
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
            | Self::ConsentRevoked { .. }
            | Self::GrantIssued { .. }
            | Self::GrantRevoked { .. }
            | Self::CodeReplayed { .. }
            | Self::CodeRedemptionFailed { .. }
            | Self::InvitationCreated { .. }
            | Self::InvitationRevoked { .. }
            | Self::AccountDisabled { .. }
            | Self::AccountEnabled {}
            | Self::AccountViewed {}
            | Self::AdministratorGranted {}
            | Self::AdministratorRevoked {}
            | Self::HandleChanged { .. }
            | Self::DisplayNameChanged { .. }
            | Self::PictureChanged { .. }
            | Self::PictureRemoved {}
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
            | Self::RecoveryStarted { .. }
            | Self::RecoveryCompleted { .. }
            | Self::RecoveryUndone { .. }
            | Self::DeliveryRetried { .. }
            | Self::DeliveryCancelled { .. }
            | Self::RelatedOriginApproved { .. }
            | Self::RelatedOriginRemoved { .. }
            | Self::CompromiseReported { .. }
            | Self::SigningKeyChanged { .. }
            | Self::AccountExported {}
            | Self::AccountDeletionScheduled { .. }
            | Self::AccountRestored {}
            | Self::AccountPurged {}
            | Self::AuditHistoryPruned { .. }
            | Self::AuditChainVerified(_)
            | Self::AnnouncementSent { .. }
            | Self::Imported(_) => None,
        }
    }

    /// The variant's serde tag, e.g. `signed_in`: the `kind` it is stored under.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::AccountCreated { .. } => "account_created",
            Self::SignedIn { .. } => "signed_in",
            Self::SignInFailed { .. } => "sign_in_failed",
            Self::SessionRevoked { .. } => "session_revoked",
            Self::PasskeyConfirmed { .. } => "passkey_confirmed",
            Self::PasskeyAdded { .. } => "passkey_added",
            Self::PasskeyRenamed { .. } => "passkey_renamed",
            Self::PasskeyRemoved { .. } => "passkey_removed",
            Self::IdentityLinked { .. } => "identity_linked",
            Self::IdentityUnlinked { .. } => "identity_unlinked",
            Self::EmailAdded { .. } => "email_added",
            Self::EmailVerified { .. } => "email_verified",
            Self::PrimaryEmailChanged { .. } => "primary_email_changed",
            Self::EmailRemoved { .. } => "email_removed",
            Self::ConsentGranted { .. } => "consent_granted",
            Self::ConsentRevoked { .. } => "consent_revoked",
            Self::GrantIssued { .. } => "grant_issued",
            Self::GrantRevoked { .. } => "grant_revoked",
            Self::CodeReplayed { .. } => "code_replayed",
            Self::CodeRedemptionFailed { .. } => "code_redemption_failed",
            Self::InvitationCreated { .. } => "invitation_created",
            Self::InvitationRevoked { .. } => "invitation_revoked",
            Self::AccountDisabled { .. } => "account_disabled",
            Self::AccountEnabled {} => "account_enabled",
            Self::AccountViewed {} => "account_viewed",
            Self::AdministratorGranted {} => "administrator_granted",
            Self::AdministratorRevoked {} => "administrator_revoked",
            Self::HandleChanged { .. } => "handle_changed",
            Self::DisplayNameChanged { .. } => "display_name_changed",
            Self::PictureChanged { .. } => "picture_changed",
            Self::PictureRemoved {} => "picture_removed",
            Self::HandleReleased { .. } => "handle_released",
            Self::HandleReserved { .. } => "handle_reserved",
            Self::HandleUnreserved { .. } => "handle_unreserved",
            Self::ClientRegistered { .. } => "client_registered",
            Self::ClientUpdated { .. } => "client_updated",
            Self::ClientEnabled { .. } => "client_enabled",
            Self::ClientDisabled { .. } => "client_disabled",
            Self::ClientSuspended { .. } => "client_suspended",
            Self::ClientSuspensionLifted { .. } => "client_suspension_lifted",
            Self::ClientDeleted { .. } => "client_deleted",
            Self::ClientSecretRotated { .. } => "client_secret_rotated",
            Self::RecoveryStarted { .. } => "recovery_started",
            Self::RecoveryCompleted { .. } => "recovery_completed",
            Self::RecoveryUndone { .. } => "recovery_undone",
            Self::DeliveryRetried { .. } => "delivery_retried",
            Self::DeliveryCancelled { .. } => "delivery_cancelled",
            Self::RelatedOriginApproved { .. } => "related_origin_approved",
            Self::RelatedOriginRemoved { .. } => "related_origin_removed",
            Self::CompromiseReported { .. } => "compromise_reported",
            Self::SigningKeyChanged { .. } => "signing_key_changed",
            Self::AccountExported {} => "account_exported",
            Self::AccountDeletionScheduled { .. } => "account_deletion_scheduled",
            Self::AccountRestored {} => "account_restored",
            Self::AccountPurged {} => "account_purged",
            Self::AuditHistoryPruned { .. } => "audit_history_pruned",
            Self::AuditChainVerified(_) => "audit_chain_verified",
            Self::AnnouncementSent { .. } => "announcement_sent",
            Self::Imported(_) => "imported",
        }
    }
}

impl AuditVerification {
    /// Its payload version as a recorded event. A new [`ChainProblem`] or
    /// [`VerificationKeys`] is one older releases cannot decode, so it fails to
    /// compile here until it is given the next version.
    #[must_use]
    pub const fn version(&self) -> i16 {
        if let Some(ChainBreak { problem, .. }) = &self.broken {
            match problem {
                ChainProblem::MissingEvent
                | ChainProblem::EventBeforeAnchor
                | ChainProblem::EventChanged
                | ChainProblem::CheckpointMismatch
                | ChainProblem::CheckpointSignature
                | ChainProblem::CheckpointMalformed
                | ChainProblem::CheckpointBeyondChain => {}
                // Releases before it cannot decode it.
                ChainProblem::OutOfOrder => return 2,
            }
        }
        match self.keys {
            VerificationKeys::Committed
            | VerificationKeys::Given
            | VerificationKeys::Uncommitted => DomainEvent::FIRST_VERSION,
        }
    }
}
