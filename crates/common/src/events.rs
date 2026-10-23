//! Typed domain events: what changed in an account or its grants, who changed it,
//! and where the request came from.
//!
//! These are vocabulary only. The database crate records them in the transaction
//! that made the change, keeping every [`Personal`] value and the
//! [`RequestOrigin`](crate::events::RequestOrigin) apart from the event so both can be deleted on their own.

use crate::{
    AuthenticationMethod, ClientId, EmailId, EventId, Handle, PasskeyId, Personal, Provider,
    SessionId, TokenId, UserId,
    clients::{ClientField, ClientKind},
    email::NormalizedEmail,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

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
    /// email is queued with it.
    EmailAdded {
        /// The new address.
        email_id: EmailId,
        /// The address itself.
        address: Personal<NormalizedEmail>,
    },
    /// Someone holding the address's verification link confirmed it.
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
    /// The user reported an event of their history as not theirs. Their other
    /// sessions follow as [`Self::SessionRevoked`], and every refresh family of the
    /// account is revoked with them.
    CompromiseReported {
        /// The reported event.
        event_id: EventId,
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
            _ => Self::FIRST_VERSION,
        }
    }

    /// The client the event concerns, stored in its own column for filtering.
    #[must_use]
    pub fn client_id(&self) -> Option<&ClientId> {
        match self {
            Self::ConsentGranted { client_id, .. }
            | Self::GrantIssued { client_id, .. }
            | Self::GrantRevoked { client_id, .. }
            | Self::CodeReplayed { client_id }
            | Self::ClientRegistered { client_id, .. }
            | Self::ClientUpdated { client_id, .. }
            | Self::ClientEnabled { client_id }
            | Self::ClientDisabled { client_id }
            | Self::ClientSuspended { client_id }
            | Self::ClientSuspensionLifted { client_id }
            | Self::ClientDeleted { client_id }
            | Self::ClientSecretRotated { client_id, .. }
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
            | Self::CompromiseReported { .. }
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
            | Self::GrantIssued { .. }
            | Self::GrantRevoked { .. }
            | Self::CodeReplayed { .. }
            | Self::InvitationCreated { .. }
            | Self::InvitationRevoked { .. }
            | Self::AccountDisabled { .. }
            | Self::AccountEnabled {}
            | Self::AccountViewed {}
            | Self::AdministratorGranted {}
            | Self::AdministratorRevoked {}
            | Self::HandleChanged { .. }
            | Self::ClientRegistered { .. }
            | Self::ClientUpdated { .. }
            | Self::ClientEnabled { .. }
            | Self::ClientDisabled { .. }
            | Self::ClientSuspended { .. }
            | Self::ClientSuspensionLifted { .. }
            | Self::ClientDeleted { .. }
            | Self::ClientSecretRotated { .. }
            | Self::CompromiseReported { .. }
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
            Self::GrantIssued { .. } => "grant_issued",
            Self::GrantRevoked { .. } => "grant_revoked",
            Self::CodeReplayed { .. } => "code_replayed",
            Self::InvitationCreated { .. } => "invitation_created",
            Self::InvitationRevoked { .. } => "invitation_revoked",
            Self::AccountDisabled { .. } => "account_disabled",
            Self::AccountEnabled {} => "account_enabled",
            Self::AccountViewed {} => "account_viewed",
            Self::AdministratorGranted {} => "administrator_granted",
            Self::AdministratorRevoked {} => "administrator_revoked",
            Self::HandleChanged { .. } => "handle_changed",
            Self::ClientRegistered { .. } => "client_registered",
            Self::ClientUpdated { .. } => "client_updated",
            Self::ClientEnabled { .. } => "client_enabled",
            Self::ClientDisabled { .. } => "client_disabled",
            Self::ClientSuspended { .. } => "client_suspended",
            Self::ClientSuspensionLifted { .. } => "client_suspension_lifted",
            Self::ClientDeleted { .. } => "client_deleted",
            Self::ClientSecretRotated { .. } => "client_secret_rotated",
            Self::CompromiseReported { .. } => "compromise_reported",
            Self::Imported(_) => "imported",
        }
    }

    /// The entry this event shows in its subject's own security history, or `None`
    /// for what only auth needs: ceremonies, rejected attempts, token bookkeeping
    /// and invitations. Every variant is named, so a new one cannot be added
    /// without deciding whether its subject sees it.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub fn history_entry(&self) -> Option<HistoryEntry> {
        Some(match self {
            Self::AccountCreated { method, .. } => HistoryEntry::AccountCreated { method: *method },
            Self::SignedIn { method, .. } => HistoryEntry::SignedIn { method: *method },
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
            Self::EmailAdded { email_id, address } => HistoryEntry::EmailAdded {
                email_id: *email_id,
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
            Self::AccountViewed {} => HistoryEntry::AccountViewed,
            Self::AdministratorGranted {} => HistoryEntry::AdministratorGranted,
            Self::AdministratorRevoked {} => HistoryEntry::AdministratorRevoked,
            Self::HandleChanged { .. } => HistoryEntry::HandleChanged,
            Self::CompromiseReported { event_id } => HistoryEntry::CompromiseReported {
                event_id: *event_id,
            },
            Self::Imported(audit) => HistoryEntry::Legacy {
                action: audit.action.clone(),
                outcome: audit.outcome.clone(),
            },
            Self::SignInFailed { .. }
            | Self::PasskeyConfirmed { .. }
            | Self::GrantIssued { .. }
            | Self::InvitationCreated { .. }
            | Self::InvitationRevoked { .. }
            // Changes to an application concern no account.
            | Self::ClientRegistered { .. }
            | Self::ClientUpdated { .. }
            | Self::ClientEnabled { .. }
            | Self::ClientDisabled { .. }
            | Self::ClientSuspended { .. }
            | Self::ClientSuspensionLifted { .. }
            | Self::ClientDeleted { .. }
            | Self::ClientSecretRotated { .. } => return None,
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
    /// An email address was added, unverified.
    #[serde(rename = "email.added")]
    EmailAdded {
        /// The address's ID.
        email_id: EmailId,
        /// The address, until retention deletes it.
        address: Option<NormalizedEmail>,
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
    /// An administrator viewed the account's details.
    #[serde(rename = "account.viewed")]
    AccountViewed,
    /// The account became an administrator.
    #[serde(rename = "administrator.granted")]
    AdministratorGranted,
    /// The account's administrator rights were removed.
    #[serde(rename = "administrator.revoked")]
    AdministratorRevoked,
    /// The account's handle changed.
    #[serde(rename = "account.handle_changed")]
    HandleChanged,
    /// The user reported an entry as not theirs.
    #[serde(rename = "compromise.reported")]
    CompromiseReported {
        /// The reported entry.
        event_id: EventId,
    },
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
            | Self::TokenReused
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::AccountViewed
            | Self::AdministratorGranted
            | Self::AdministratorRevoked
            | Self::HandleChanged
            | Self::CompromiseReported { .. }
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
        /// An administrator, through the admin API.
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

crate::str_enum! {
    /// Why an authentication was rejected.
    pub enum SignInFailure {
        /// The assertion or provider evidence did not verify against the account.
        InvalidCredential = "invalid_credential",
        /// A passkey's signature counter did not increase, so it may have been copied.
        CounterRegression = "counter_regression",
        /// No active account holds the credential or username.
        UnknownAccount = "unknown_account",
        /// The account is disabled, or cannot sign in this way any more.
        AccountUnavailable = "account_unavailable",
    }
}

/// Why a session was revoked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RevocationReason {
    /// The user signed out.
    Logout,
    /// The browser signed in to another account, which ends its previous session.
    AccountSwitched,
    /// The user signed out at a client's request (RP-initiated logout).
    RelyingPartyLogout {
        /// The client that asked, as named by a verified `id_token_hint` or a
        /// registered `post_logout_redirect_uri`.
        client_id: ClientId,
    },
    /// A passkey was removed, which ends the account's other sessions.
    CredentialRemoved,
    /// A provider identity was unlinked, which ends the account's other sessions.
    IdentityUnlinked,
    /// An administrator revoked it.
    Admin,
    /// The account was disabled.
    AccountDisabled,
    /// The account is being deleted.
    AccountDeletion,
    /// It expired.
    Expired,
    /// The user reported an event of their history as not theirs, which ends the
    /// account's other sessions.
    CompromiseReported,
    /// The user signed it out from another session's settings. Added in version 2
    /// of `session_revoked`.
    UserRevoked,
}

crate::str_enum! {
    /// Why a refresh family was revoked.
    pub enum GrantRevocation {
        /// The client revoked it (RFC 7009).
        ClientRevoked = "client_revoked",
        /// One of its refresh tokens was used twice.
        RefreshReplay = "refresh_replay",
        /// The client's policy no longer allows it.
        PolicyRejected = "policy_rejected",
        /// The authorization code it came from was redeemed twice.
        CodeReplay = "code_replay",
    }
}

/// Who caused an event. Every feature attributes events with this one type.
///
/// Operator attribution (`os_user`, `host`, an administrator's user ID) is
/// accountability data, so it stays in the event rather than in personal data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    /// A signed-in user, or one signing in.
    User {
        /// The acting account.
        user_id: UserId,
        /// The session acting, once there is one.
        session_id: Option<SessionId>,
    },
    /// An administrator, through the admin API.
    Admin {
        /// The administrator's account.
        user_id: UserId,
        /// The administrator's session.
        session_id: SessionId,
    },
    /// An operator, through the service's command line.
    Cli {
        /// The operating system user, from `$USER`.
        os_user: String,
        /// The machine's host name.
        host: String,
    },
    /// A client calling a back-channel endpoint.
    Client {
        /// The authenticated client.
        client_id: ClientId,
    },
    /// A background job.
    System {
        /// The job.
        job: JobName,
    },
    /// An unauthenticated browser, e.g. one failing to sign in.
    Anonymous,
    /// Unknown: imported audit rows never recorded who acted.
    Unrecorded,
}

impl Actor {
    /// The client acting, if any.
    #[must_use]
    pub const fn client_id(&self) -> Option<&ClientId> {
        match self {
            Self::Client { client_id } => Some(client_id),
            Self::User { .. }
            | Self::Admin { .. }
            | Self::Cli { .. }
            | Self::System { .. }
            | Self::Anonymous
            | Self::Unrecorded => None,
        }
    }

    /// The session acting, if any.
    #[must_use]
    pub const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::User { session_id, .. } => *session_id,
            Self::Admin { session_id, .. } => Some(*session_id),
            Self::Cli { .. }
            | Self::Client { .. }
            | Self::System { .. }
            | Self::Anonymous
            | Self::Unrecorded => None,
        }
    }
}

/// Background jobs that act on their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobName {
    /// The periodic expired-state cleanup.
    Cleanup,
    /// The purge of accounts whose deletion grace period ended.
    AccountPurge,
}

/// A security audit log row, kept verbatim by the migrations to typed events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedAudit {
    /// The logged action, e.g. `passkey.login`.
    action: String,
    /// `success`, `failure` or `rejected`.
    outcome: String,
    /// The logged metadata, e.g. `{"provider": "github"}`.
    metadata: Value,
}

impl ImportedAudit {
    /// The logged action, e.g. `passkey.login`.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// `success`, `failure` or `rejected`.
    #[must_use]
    pub fn outcome(&self) -> &str {
        &self.outcome
    }

    /// The logged metadata, e.g. `{"provider": "github"}`.
    #[must_use]
    pub const fn metadata(&self) -> &Value {
        &self.metadata
    }
}

crate::str_enum! {
    /// Coarse browser derived from a `User-Agent` header, which is never stored.
    pub enum Browser {
        /// Google Chrome and other Chromium browsers that announce no other name.
        Chrome = "chrome",
        /// Microsoft Edge.
        Edge = "edge",
        /// Mozilla Firefox.
        Firefox = "firefox",
        /// Opera.
        Opera = "opera",
        /// Apple Safari.
        Safari = "safari",
        /// Anything else, including back-channel HTTP clients, and browsers a newer
        /// release recognizes.
        Other = "other",
    } else Other
}

crate::str_enum! {
    /// Coarse operating system derived from a `User-Agent` header.
    pub enum Platform {
        /// Android.
        Android = "android",
        /// `ChromeOS`.
        ChromeOs = "chrome_os",
        /// iOS and iPadOS. iPads that request desktop sites announce macOS.
        Ios = "ios",
        /// Linux on the desktop.
        Linux = "linux",
        /// macOS.
        MacOs = "macos",
        /// Windows.
        Windows = "windows",
        /// Anything else, including back-channel HTTP clients, and platforms a newer
        /// release recognizes.
        Other = "other",
    } else Other
}

/// Coarse browser and platform of a `User-Agent` header, the only part of it auth
/// keeps. Stored as text, `browser/platform` (`firefox/linux`); serialized as
/// `{"browser": …, "platform": …}`. A browser or platform this release doesn't
/// know reads as `other`, so a session or event a newer release tagged still loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAgentFamily {
    /// The browser.
    pub browser: Browser,
    /// The operating system it runs on.
    pub platform: Platform,
}

impl UserAgentFamily {
    /// Classifies a `User-Agent` header. Markers are checked in order: Edge and Opera
    /// also announce Chrome, Chrome announces Safari, Android and `ChromeOS` announce
    /// Linux, and iOS announces macOS.
    #[must_use]
    pub fn classify(user_agent: &str) -> Self {
        /// The value of the first marker `user_agent` contains, or `other`.
        fn first<T: Copy>(user_agent: &str, markers: &[(&str, T)], other: T) -> T {
            markers
                .iter()
                .find(|(marker, _)| user_agent.contains(marker))
                .map_or(other, |&(_, value)| value)
        }
        Self {
            browser: first(
                user_agent,
                &[
                    ("Edg/", Browser::Edge),
                    ("EdgA/", Browser::Edge),
                    ("EdgiOS/", Browser::Edge),
                    ("OPR/", Browser::Opera),
                    ("Firefox/", Browser::Firefox),
                    ("FxiOS/", Browser::Firefox),
                    ("Chrome/", Browser::Chrome),
                    ("CriOS/", Browser::Chrome),
                    ("Safari/", Browser::Safari),
                ],
                Browser::Other,
            ),
            platform: first(
                user_agent,
                &[
                    ("Android", Platform::Android),
                    ("CrOS", Platform::ChromeOs),
                    ("iPhone", Platform::Ios),
                    ("iPad", Platform::Ios),
                    ("iPod", Platform::Ios),
                    ("Mac OS X", Platform::MacOs),
                    ("Windows", Platform::Windows),
                    ("Linux", Platform::Linux),
                ],
                Platform::Other,
            ),
        }
    }
}

impl std::fmt::Display for UserAgentFamily {
    /// Formats the stored text, `browser/platform`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.browser, self.platform)
    }
}

impl std::str::FromStr for UserAgentFamily {
    type Err = crate::VocabularyError;
    /// Parses the stored text, `browser/platform`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (browser, platform) = value.split_once('/').ok_or(crate::VocabularyError {
            vocabulary: "UserAgentFamily",
        })?;
        Ok(Self {
            browser: browser.parse()?,
            platform: platform.parse()?,
        })
    }
}

crate::__str_enum_sqlx!(UserAgentFamily);

/// Where a request came from. Both fields are personal data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestOrigin {
    /// The client's IP address, when the event came from a request.
    pub client_ip: Option<IpAddr>,
    /// The client's browser and platform, when the event came from a request.
    pub user_agent_family: Option<UserAgentFamily>,
}

/// Who caused an event and where their request came from, recorded with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventContext {
    /// Who caused the event.
    pub actor: Actor,
    /// Where the request came from; empty outside requests.
    pub origin: RequestOrigin,
}

/// User agent classification on real browser headers.
#[cfg(test)]
mod tests;
