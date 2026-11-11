//! The values event payloads carry beside IDs: how a sign-in, revocation or
//! recovery went, the origins they name, and imported audit rows.

use super::DomainEvent;
use crate::{ClientId, PasskeyId, Personal, clients::RelatedOrigin};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a recovery started with `--revoke` revoked and kept: every passkey the
/// owner did not vouch for went, and the kept ones can still undo it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRevocation {
    /// The passkeys revoked.
    pub revoked: Vec<PasskeyId>,
    /// The passkeys kept.
    pub kept: Vec<PasskeyId>,
}

/// An application's page that signed a user in with a passkey, from an approved
/// related origin, without sending them to auth's pages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineSignIn {
    /// The client whose pushed authorization request the sign-in completed.
    pub client_id: ClientId,
    /// The page's origin.
    pub origin: RecordedOrigin,
}

/// A client's related origin, as an event names it. An origin may be a person's
/// own domain, so events keep it as personal data, which retention and purges
/// erase. Events recorded before it was kept that way hold it in their payload,
/// and so in the audit chain, which cannot change: those stay
/// [`Self::Sealed`], in payload version 1, until the history is pruned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecordedOrigin {
    /// Kept as personal data, in payload version 2.
    Personal(Personal<RelatedOrigin>),
    /// Kept in the event, in payload version 1. Nothing records one anymore.
    Sealed(RelatedOrigin),
}

impl RecordedOrigin {
    /// The origin, unless it was erased.
    #[must_use]
    pub const fn value(&self) -> Option<&RelatedOrigin> {
        match self {
            Self::Personal(Personal::Value(origin)) | Self::Sealed(origin) => Some(origin),
            Self::Personal(Personal::Erased) => None,
        }
    }

    /// The payload version of the event that holds it.
    pub(super) const fn version(&self) -> i16 {
        match self {
            Self::Personal(_) => 2,
            Self::Sealed(_) => DomainEvent::FIRST_VERSION,
        }
    }
}

impl From<RelatedOrigin> for RecordedOrigin {
    /// Records the origin as personal data.
    fn from(origin: RelatedOrigin) -> Self {
        Self::Personal(Personal::Value(origin))
    }
}

crate::str_enum! {
    /// Why an authentication was rejected.
    pub enum SignInFailure {
        /// The assertion or provider evidence did not verify against the account.
        InvalidCredential = "invalid_credential",
        /// A passkey's signature counter did not increase, so it may have been copied.
        CounterRegression = "counter_regression",
        /// No active account with a passkey held the handle, or the text was no
        /// handle. Only older events have it: handle sign-in now refuses these
        /// before any attempt.
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
    /// The browser signed in to another account, or with a recovery link, which
    /// ends its previous session.
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
    /// The user signed out everywhere with the link of a security
    /// notification's email, which works without signing in. Added in version 3
    /// of `session_revoked`.
    SignOutLink,
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

crate::str_enum! {
    /// Why a client's redemption of an authorization code failed, which uses the
    /// code up.
    pub enum CodeRedemptionFailure {
        /// The code was issued to another client.
        WrongClient = "wrong_client",
        /// The `redirect_uri` differs from the authorization request's.
        RedirectMismatch = "redirect_mismatch",
        /// The PKCE `code_verifier` does not match the request's challenge.
        InvalidVerifier = "invalid_verifier",
    }
}

crate::str_enum! {
    /// A step in a signing key's lifecycle: published as `next`, signing as
    /// `active`, still published as `retiring`, then kept for `id_token_hint`
    /// alone as `retired`, until it is deleted.
    pub enum SigningKeyChange {
        /// A key was generated: published as `next`, or signing at once when no
        /// key signed or the key it replaces was revoked.
        Generated = "generated",
        /// A key was imported from the deployment's PEM key, signing at once.
        /// Only earlier releases imported keys; this one reads their events.
        Imported = "imported",
        /// A `next` key started signing.
        Activated = "activated",
        /// A key stopped signing; it stays published for tokens it signed.
        Retiring = "retiring",
        /// A key left the key set; its private key was erased.
        Retired = "retired",
        /// A retired key was deleted, once no `id_token_hint` it signed could be valid.
        Deleted = "deleted",
        /// An operator removed a key at once, e.g. because it was compromised.
        Revoked = "revoked",
    }
}

/// A security audit log row, kept verbatim by the migrations to typed events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedAudit {
    /// The logged action, e.g. `passkey.login`.
    pub(super) action: String,
    /// `success`, `failure` or `rejected`.
    pub(super) outcome: String,
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
