//! Paths and JSON bodies of auth's admin API, shared by auth, which serves it, and
//! the admin dashboard, which calls it.
//!
//! The API listens only on auth's private admin listener (`AUTH_ADMIN_LISTENER`),
//! which no ingress route reaches. Every request carries an access token that auth
//! issued to the dashboard, for the [`AUDIENCE`] resource, on behalf of an
//! administrator who signed in with a passkey. Mutations also need a passkey
//! confirmation at most [`CONFIRMATION_MAX_AGE`] seconds old; without one the API
//! answers `401` with an RFC 9470 step-up challenge. Other errors are `{"error": …}`
//! ([`ErrorBody`]).
//!
//! Bodies the account settings API also returns come from `piquel-common`
//! and are re-exported here. The `client` feature adds [`AdminClient`], a typed
//! client of every route.

use chrono::{DateTime, Utc};
pub use piquel_common::protocol::{
    api::{ErrorBody, Identity, Passkey},
    step_up::CONFIRMATION_MAX_AGE,
};
use piquel_common::{
    AccountStatus, AuthenticationMethod, ClientId, EventId, SessionId, TokenId, UserId,
    protocol::oauth::ClientAuthMethod,
};
use serde::{Deserialize, Serialize};
use url::Url;

/// The typed client, behind the `client` feature.
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
pub use client::{AdminClient, ApiError};

/// The `aud` of the access tokens the admin API accepts. The dashboard is
/// registered as the OIDC client with this ID, whose tokens carry it.
pub const AUDIENCE: &str = "piquel-admin";

/// Every route of the admin API, as axum path templates.
pub mod paths {
    /// `GET`: searches accounts ([`UserSearch`](super::UserSearch) →
    /// [`UserPage`](super::UserPage)).
    pub const USERS: &str = "/users";
    /// `GET`: describes one account ([`UserDetail`](super::UserDetail)).
    pub const USER: &str = "/users/{user_id}";
    /// `POST`: disables an account and ends its sessions
    /// ([`DisableUser`](super::DisableUser)).
    pub const USER_DISABLE: &str = "/users/{user_id}/disable";
    /// `POST`: reactivates a disabled account.
    pub const USER_ENABLE: &str = "/users/{user_id}/enable";
    /// `DELETE`: ends every session and refresh grant of an account.
    pub const USER_SESSIONS: &str = "/users/{user_id}/sessions";
    /// `DELETE`: ends one session and its refresh grants.
    pub const SESSION: &str = "/sessions/{session_id}";
    /// `GET`: lists invitations ([`Invitation`](super::Invitation)). `POST`: creates
    /// one ([`CreateInvitation`](super::CreateInvitation) →
    /// [`CreatedInvitation`](super::CreatedInvitation)). Served only while signup
    /// requires an invitation.
    pub const INVITATIONS: &str = "/invitations";
    /// `DELETE`: revokes an unredeemed invitation.
    pub const INVITATION: &str = "/invitations/{invitation_id}";
    /// `GET`: lists OIDC clients ([`Client`](super::Client)).
    pub const CLIENTS: &str = "/clients";
    /// `GET`: describes one OIDC client ([`Client`](super::Client)).
    pub const CLIENT: &str = "/clients/{client_id}";
    /// `GET`: pages through domain events, newest first
    /// ([`EventSearch`](super::EventSearch) → [`EventPage`](super::EventPage)).
    pub const EVENTS: &str = "/events";
    /// `GET`: lists administrators ([`Administrator`](super::Administrator)).
    /// `POST`: makes an account an administrator
    /// ([`GrantAdministrator`](super::GrantAdministrator)).
    pub const ADMINISTRATORS: &str = "/administrators";
    /// `DELETE`: removes an administrator's rights. Administrators cannot remove
    /// their own, and the last administrator cannot be removed.
    pub const ADMINISTRATOR: &str = "/administrators/{user_id}";
    /// `GET`: verifies the audit chain and its checkpoints
    /// ([`AuditVerification`](super::AuditVerification)).
    pub const AUDIT_VERIFICATION: &str = "/audit/verification";
}

/// An account, as search results and its detail page show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Account ID.
    pub id: UserId,
    /// Login name.
    pub username: String,
    /// Name shown to the user and to applications.
    pub display_name: String,
    /// Whether the account can sign in.
    pub status: AccountStatus,
    /// When the account was created.
    pub created_at: DateTime<Utc>,
}

/// The query of [`paths::USERS`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSearch {
    /// An account ID, or part of a username, display name or email, ignoring case.
    /// Empty matches every account.
    #[serde(default)]
    pub q: String,
    /// The previous page's [`UserPage::next`], to continue after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<UserId>,
}

/// One page of accounts, by ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPage {
    /// The matching accounts.
    pub users: Vec<User>,
    /// The cursor of the next page, when there may be one.
    pub next: Option<UserId>,
}

/// Everything an administrator sees about one account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDetail {
    /// Profile and status.
    pub user: User,
    /// Whether the account is an administrator. The admin API changes only the
    /// accounts of non-administrators.
    pub administrator: bool,
    /// Email addresses, primary first.
    pub emails: Vec<Email>,
    /// Active passkeys, without their cryptographic contents.
    pub passkeys: Vec<Passkey>,
    /// Linked social identities.
    pub identities: Vec<Identity>,
    /// Active sessions, newest first.
    pub sessions: Vec<Session>,
    /// Remembered consents to applications.
    pub consents: Vec<Consent>,
}

/// An email address of an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Email {
    /// The normalized address.
    pub address: String,
    /// When it was verified, if it was.
    pub verified_at: Option<DateTime<Utc>>,
    /// Whether it is the account's primary address.
    pub primary: bool,
}

/// An active browser session of an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Session ID, the `sid` of the tokens issued from it.
    pub id: SessionId,
    /// How the session authenticated.
    pub methods: Vec<AuthenticationMethod>,
    /// When it signed in.
    pub authenticated_at: DateTime<Utc>,
    /// When it last proved possession of a passkey.
    pub passkey_confirmed_at: Option<DateTime<Utc>>,
    /// Last recorded activity.
    pub last_seen_at: DateTime<Utc>,
    /// When it expires.
    pub expires_at: DateTime<Utc>,
}

/// The scopes an account consented to for one application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consent {
    /// The application's client ID.
    pub client_id: String,
    /// The audience of the tokens it receives.
    pub audience: String,
    /// The consented scopes.
    pub scopes: Vec<String>,
}

/// The body of [`paths::USER_DISABLE`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisableUser {
    /// Why the account is disabled: 1 to 500 characters, without control
    /// characters. Kept with the event as personal data.
    pub reason: String,
}

/// A signup invitation, without its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    /// Invitation ID.
    pub id: TokenId,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When it stops being accepted.
    pub expires_at: DateTime<Utc>,
    /// When an account redeemed it.
    pub redeemed_at: Option<DateTime<Utc>>,
    /// When it was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// The optional body of `POST` [`paths::INVITATIONS`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInvitation {
    /// How long the link stays valid: 1 hour to 365 days, a number followed by `m`,
    /// `h` or `d`, e.g. `24h`.
    /// Seven days when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<String>,
}

/// A new invitation. Its link holds the secret and is shown only this once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedInvitation {
    /// Invitation ID, to revoke it.
    pub id: TokenId,
    /// The single-use signup link.
    pub url: Url,
    /// When the link stops working.
    pub expires_at: DateTime<Utc>,
}

/// An OIDC client: everything but its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// Client ID.
    pub id: ClientId,
    /// Name shown on consent screens.
    pub display_name: String,
    /// Allowed authorization redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed post-logout redirect URIs.
    pub post_logout_uris: Vec<String>,
    /// Scopes it may request.
    pub allowed_scopes: Vec<String>,
    /// Audiences it may request tokens for.
    pub allowed_audiences: Vec<String>,
    /// Whether it may receive refresh tokens.
    pub allow_refresh: bool,
    /// Whether it is usable.
    pub enabled: bool,
    /// Whether it skips the consent screen.
    pub trusted: bool,
    /// How it authenticates at the token endpoint.
    pub token_endpoint_auth_method: ClientAuthMethod,
}

/// The query of [`paths::EVENTS`]. Every filter is optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSearch {
    /// Only events concerning this account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserId>,
    /// Only events of this kind, e.g. `session_revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The previous page's [`EventPage::next`], to continue with older events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<EventId>,
}

/// One page of domain events, newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPage {
    /// The matching events.
    pub events: Vec<Event>,
    /// The cursor of the next, older page, when there may be one.
    pub next: Option<EventId>,
}

/// A recorded domain event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Event ID.
    pub id: EventId,
    /// When it was recorded.
    pub occurred_at: DateTime<Utc>,
    /// Who caused it, e.g. `{"type": "admin", "user_id": …, "session_id": …}`.
    pub actor: serde_json::Value,
    /// The account it concerns, if any.
    pub subject: Option<UserId>,
    /// What happened: `{"kind": …, "data": …}`, as auth stores it. Personal values
    /// read `{"$personal": value}`, or `"$erased"` once deleted. An event of a kind
    /// or payload version the serving release does not know, written by a newer
    /// one, also carries its `version`.
    pub event: serde_json::Value,
}

/// An administrator account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Administrator {
    /// The administrator's account.
    pub user_id: UserId,
    /// The account's login name.
    pub username: String,
    /// When the rights were granted.
    pub granted_at: DateTime<Utc>,
}

/// The body of `POST` [`paths::ADMINISTRATORS`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAdministrator {
    /// The active account to make an administrator.
    pub user_id: UserId,
}

/// The result of verifying the audit chain, as the admin API returns it and
/// `auth-service audit verify` prints it. Verification stops at the first problem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerification {
    /// The first position that does not match, or `None` if the chain is intact.
    pub broken: Option<ChainBreak>,
    /// Sealed events whose hash was recomputed.
    pub events_checked: u64,
    /// Checkpoints whose signature was checked.
    pub checkpoints_checked: u64,
    /// Events not sealed yet. They are sealed within seconds, once every older
    /// transaction has finished.
    pub unsealed: u64,
    /// The checkpoint the chain was last pruned through, which it extends.
    pub anchor: Option<ChainPoint>,
    /// The newest sealed event.
    pub newest: Option<ChainPoint>,
    /// The newest checkpoint.
    pub latest_checkpoint: Option<ChainPoint>,
    /// The keys checkpoint signatures were checked against.
    pub keys: VerificationKeys,
}

/// A position on the audit chain and the chain hash through it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPoint {
    /// The position, from 1.
    pub position: u64,
    /// The chain hash, in standard base64 as checkpoints write it.
    pub hash: String,
}

impl std::fmt::Display for ChainPoint {
    /// Writes the position and hash, e.g. `3037 b3Fx…=`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} {}", self.position, self.hash)
    }
}

/// Where the audit chain stops matching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBreak {
    /// The first position that does not match. The change may also be a removal
    /// or insertion just before it.
    pub position: u64,
    /// What does not match there.
    pub problem: ChainProblem,
}

/// What does not match at a [`ChainBreak`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainProblem {
    /// No sealed event has the position.
    MissingEvent,
    /// A sealed event remains at or before the anchor, which pruning would have
    /// deleted: the anchor was moved to hide it.
    EventBeforeAnchor,
    /// The event's content or position does not match its stored chain hash.
    EventChanged,
    /// The chain recomputed through the position does not match the checkpoint
    /// signed there: an event before it was changed and the stored hashes
    /// recomputed.
    CheckpointMismatch,
    /// The checkpoint's signature does not verify against the keys.
    CheckpointSignature,
    /// The checkpoint's note does not match its stored position and head.
    CheckpointMalformed,
    /// A checkpoint was signed at the position, but the chain ends before it:
    /// newer events were deleted.
    CheckpointBeyondChain,
}

impl std::fmt::Display for ChainProblem {
    /// Explains the problem in a sentence fragment, e.g. for the CLI.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingEvent => "no sealed event has this position",
            Self::EventBeforeAnchor => {
                "a sealed event remains here, at or before the anchor it was pruned through"
            }
            Self::EventChanged => "the event does not match its chain hash",
            Self::CheckpointMismatch => {
                "the recomputed chain does not match the checkpoint signed here"
            }
            Self::CheckpointSignature => "the checkpoint's signature does not verify",
            Self::CheckpointMalformed => {
                "the checkpoint's note does not match its stored position and head"
            }
            Self::CheckpointBeyondChain => {
                "a checkpoint was signed here, but the chain ends before it"
            }
        })
    }
}

/// The keys checkpoint signatures were checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationKeys {
    /// The keys committed to the repository (`docs/security/audit-key.pub`), which
    /// include the one signing new checkpoints.
    Committed,
    /// Keys the operator gave on the command line.
    Given,
    /// The committed keys and the server's own, which is not committed. A
    /// compromised server could have signed with it.
    Uncommitted,
}

impl std::fmt::Display for VerificationKeys {
    /// Describes the keys, e.g. for the CLI.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Committed => "committed",
            Self::Given => "given with --key",
            Self::Uncommitted => "committed, and the server's own key, which is not committed",
        })
    }
}
