//! The views of administration: what the admin dashboard shows and posts, and
//! what the CLI's `--output json` prints. Auth's service returns them, and its
//! database crate decodes some straight into them.
//!
//! Bodies the account settings also return come from [`crate::protocol::api`]
//! and are re-exported here.

pub use crate::protocol::api::{Identity, Passkey};
use crate::{
    AccountStatus, AuthenticationMethod, ClientId, EventId, Handle, SessionId, TokenId, TraceId,
    UserId, clients::RelatedOrigin, protocol::oauth::ClientAuthMethod,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

/// An account, as search results and its detail page show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Account ID.
    pub id: UserId,
    /// Public identifier and login name.
    pub handle: Handle,
    /// Name shown to the user and to applications.
    pub display_name: String,
    /// Whether the account can sign in.
    pub status: AccountStatus,
    /// When the account was created.
    pub created_at: DateTime<Utc>,
}

/// The account search's query.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSearch {
    /// An account ID, or part of a handle, display name or email, ignoring case.
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
    /// Whether the account is an administrator. The dashboard changes only the
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

/// The form disabling an account.
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

/// The form creating an invitation.
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "Each flag is an independent registration setting."
)]
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
    /// Whether it must push its authorization requests (RFC 9126). Absent from
    /// auth releases that predate them.
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /// How it authenticates at the token endpoint.
    pub token_endpoint_auth_method: ClientAuthMethod,
    /// Where logout tokens are posted when a session it holds tokens from ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    /// The account that manages it; absent for clients operators manage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<UserId>,
    /// When a token was last issued to it, to within an hour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When an operator suspended it: it stays disabled, and its owner cannot
    /// enable it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<DateTime<Utc>>,
    /// When it was deleted. It stays listed, disabled, so its ID is never reused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl Client {
    /// `deleted`, `suspended`, `enabled` or `disabled`: the first that applies.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        match (&self.deleted_at, &self.suspended_at, self.enabled) {
            (Some(_), _, _) => "deleted",
            (None, Some(_), _) => "suspended",
            (None, None, true) => "enabled",
            (None, None, false) => "disabled",
        }
    }
}

/// The event list's query. Every filter is optional.
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
    /// The trace of the request or job that recorded it, to look up in telemetry
    /// while the trace is kept. Absent for events recorded outside a trace, such as
    /// by the command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<TraceId>,
    /// What happened: `{"kind": …, "data": …}`, as auth stores it. Personal values
    /// read `{"$personal": value}`, or `"$erased"` once deleted. An event of a kind
    /// or payload version the serving release does not know, written by a newer
    /// one, also carries its `version`.
    pub event: serde_json::Value,
}

/// An origin approved for a client's pages to sign users in with passkeys, which
/// `/.well-known/webauthn` lists as a `WebAuthn` related origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedOrigin {
    /// The origin, as browsers send it.
    pub origin: RelatedOrigin,
    /// The client whose pages are on it.
    pub client_id: ClientId,
    /// When it was approved.
    pub approved_at: DateTime<Utc>,
}

/// The form approving an origin for a client's pages: the origin as typed, which
/// the dashboard checks, so a malformed one is explained beside the form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveOrigin {
    /// The origin, as browsers send it, e.g. `https://notes.example`.
    pub origin: String,
}

/// An administrator account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Administrator {
    /// The administrator's account.
    pub user_id: UserId,
    /// The account's handle.
    pub handle: Handle,
    /// When the rights were granted.
    pub granted_at: DateTime<Utc>,
}

/// The form granting administrator rights.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAdministrator {
    /// The active account to make an administrator.
    pub user_id: UserId,
}

/// The result of verifying the audit chain, as `auth-service audit verify` prints
/// it and the dashboard's audit page shows it. Verification stops at the first
/// problem.
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
    /// Explains the problem in a sentence fragment.
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
    /// The keys committed to the repository (`docs/security/audit-key.pub`).
    Committed,
    /// Keys the operator gave on the command line.
    Given,
    /// The server's own key, since none is committed for its environment, as on a
    /// preview. A compromised server could have signed with it.
    Uncommitted,
}

impl std::fmt::Display for VerificationKeys {
    /// Describes the keys.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Committed => "committed",
            Self::Given => "given with --key",
            Self::Uncommitted => "this server's own, which is not committed",
        })
    }
}

/// One page of the audit page's checkpoints, oldest first, after the anchor, with
/// the verification they are judged by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPage {
    /// The chain's state.
    pub verification: AuditVerification,
    /// The checkpoints.
    pub checkpoints: Vec<AuditCheckpoint>,
    /// The position to continue after, when there may be more.
    pub next: Option<u64>,
}

/// A signed checkpoint, and whether the chain may be pruned through it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    /// Its position and the head it signs.
    pub point: ChainPoint,
    /// When it was signed.
    pub signed_at: DateTime<Utc>,
    /// Whether `auth-service audit prune --through` its position would prune.
    pub pruning: Pruning,
}

/// Whether the chain may be pruned through a checkpoint, by the rules `audit
/// prune` applies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pruning {
    /// It may: the anchor precedes it and the chain verifies through it.
    Prunable,
    /// The chain was already pruned through it or a later checkpoint.
    Pruned {
        /// The anchor's position.
        anchor: u64,
    },
    /// The chain breaks at or before it.
    Broken(ChainBreak),
}
