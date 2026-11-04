//! The views of administration: what the admin dashboard shows and posts, and
//! what the CLI's `--output json` prints. Auth's service returns them, and its
//! database crate decodes some straight into them.
//!
//! Bodies the account settings also return come from [`crate::protocol::api`]
//! and are re-exported here.

pub use crate::protocol::api::{Identity, Passkey};
use crate::{
    AccountStatus, AuthenticationMethod, ClientId, DeliveryId, EventId, Handle, PictureId,
    SessionId, TokenId, TraceId, UserId,
    clients::RelatedOrigin,
    protocol::{jwt::KeyId, oauth::ClientAuthMethod},
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
    /// The account's profile picture, served at `/pictures/{id}` on auth, while the
    /// account is active: auth serves it only then.
    pub picture: Option<PictureId>,
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
    /// The page wanted, counting from 1; the first when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

/// One page of accounts, by ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPage {
    /// The matching accounts.
    pub users: Vec<User>,
    /// Where the page stands among every match.
    pub paging: Paging,
}

/// Where a page of a list stands: pages count from 1, and a list with no match
/// has one empty page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paging {
    /// The page shown.
    pub page: u32,
    /// How many pages there are.
    pub pages: u32,
    /// How many items match, over every page.
    pub total: u64,
    /// How many items a page holds at most.
    pub per_page: u32,
}

impl Paging {
    /// Page `page` of `total` items, `per_page` at a time. A page past the last
    /// reads as the last, so a stale link still shows something.
    #[must_use]
    pub fn new(page: Option<u32>, total: u64, per_page: u32) -> Self {
        let pages = total
            .div_ceil(u64::from(per_page))
            .clamp(1, u64::from(u32::MAX));
        let pages = u32::try_from(pages).unwrap_or(u32::MAX);
        Self {
            page: page.unwrap_or(1).clamp(1, pages),
            pages,
            total,
            per_page,
        }
    }

    /// How many items the pages before this one hold: the query's offset.
    #[must_use]
    pub fn offset(self) -> u64 {
        u64::from(self.page - 1) * u64::from(self.per_page)
    }

    /// The numbers of the first and last item of the page, counting from 1, or
    /// `None` when nothing matches.
    #[must_use]
    pub fn range(self) -> Option<(u64, u64)> {
        (self.total > 0).then(|| {
            let first = self.offset() + 1;
            (
                first,
                (first + u64::from(self.per_page) - 1).min(self.total),
            )
        })
    }

    /// The page before this one, if there is one.
    #[must_use]
    pub const fn previous(self) -> Option<u32> {
        if self.page > 1 {
            Some(self.page - 1)
        } else {
            None
        }
    }

    /// The page after this one, if there is one.
    #[must_use]
    pub const fn next(self) -> Option<u32> {
        if self.page < self.pages {
            Some(self.page + 1)
        } else {
            None
        }
    }
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
    /// The account's deletion, while it is scheduled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion: Option<ScheduledDeletion>,
}

/// An account's scheduled deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledDeletion {
    /// When it was scheduled.
    pub requested_at: DateTime<Utc>,
    /// When the purge job may delete the account.
    pub purge_after: DateTime<Utc>,
    /// Why its purge keeps failing, once it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<PurgeFailure>,
}

/// Why an account's purge keeps failing, and when it is tried again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeFailure {
    /// Failed attempts in a row.
    pub attempts: u64,
    /// The latest failure's message chain.
    pub last_error: String,
    /// When the purge job tries again.
    pub next_attempt_at: DateTime<Utc>,
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
    /// Whether administrators' views of accounts are listed too. They are left
    /// out unless asked for, here or as the `kind`, so the list shows changes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub views: bool,
    /// The page wanted, counting from 1 at the newest; the first when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

/// One page of domain events, newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPage {
    /// The matching events.
    pub events: Vec<Event>,
    /// Where the page stands among every match.
    pub paging: Paging,
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
    /// The account's profile picture, served at `/pictures/{id}` on auth, while the
    /// account is active: auth serves it only then.
    pub picture: Option<PictureId>,
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

crate::str_enum! {
    /// Where a delivery is in its life.
    pub enum DeliveryStatus {
        /// Waiting for its next attempt, or being attempted.
        Pending = "pending",
        /// The receiver accepted it.
        Succeeded = "succeeded",
        /// A permanent error, or retryable errors past the channel's maximum age.
        Failed = "failed",
        /// An operator cancelled it.
        Cancelled = "cancelled",
    }
}

/// A delivery as operators list it, without its recipient or payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverySummary {
    /// Delivery identifier.
    pub id: DeliveryId,
    /// Its channel's name.
    pub channel: String,
    /// Where it goes.
    pub destination: String,
    /// Where it is in its life.
    pub status: DeliveryStatus,
    /// Attempts so far.
    pub attempts: u64,
    /// Its ordering key and its place in that order, if it is ordered.
    pub ordering: Option<(String, i64)>,
    /// When the next attempt is due, while pending.
    pub next_attempt_at: DateTime<Utc>,
    /// The latest attempt's error.
    pub last_error: Option<String>,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When it succeeded, failed or was cancelled.
    pub finished_at: Option<DateTime<Utc>>,
}

impl DeliverySummary {
    /// Whether an operator may attempt it again: a failed delivery, or a
    /// cancelled one no other delivery is ordered after.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        match self.status {
            DeliveryStatus::Failed => true,
            DeliveryStatus::Cancelled => self.ordering.is_none(),
            DeliveryStatus::Pending | DeliveryStatus::Succeeded => false,
        }
    }

    /// Whether an operator may cancel it: while pending or failed.
    #[must_use]
    pub const fn cancellable(&self) -> bool {
        matches!(
            self.status,
            DeliveryStatus::Pending | DeliveryStatus::Failed
        )
    }
}

crate::str_enum! {
    /// Where a signing key is in its lifecycle.
    pub enum SigningKeyState {
        /// Published ahead of use, so verifiers have it before it signs.
        Next = "next",
        /// Signs new tokens; one per key type.
        Active = "active",
        /// No longer signs, but stays published while its tokens may be valid.
        Retiring = "retiring",
        /// Unpublished, its private key erased; verifies only `id_token_hint`s.
        Retired = "retired",
    }
}

crate::str_enum! {
    /// The family of a signing key, which fixes the algorithms it signs with.
    pub enum SigningKeyType {
        /// RSA, signing RS256.
        Rsa = "rsa",
    }
}

/// A signing key, without its public or private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKey {
    /// The key's `kid`.
    pub id: KeyId,
    /// Its family.
    pub key_type: SigningKeyType,
    /// Where it is in its lifecycle.
    pub state: SigningKeyState,
    /// When it was generated or imported.
    pub created_at: DateTime<Utc>,
    /// When it started signing.
    pub activated_at: Option<DateTime<Utc>>,
    /// When it stopped signing.
    pub deactivated_at: Option<DateTime<Utc>>,
    /// When it left the key set.
    pub retired_at: Option<DateTime<Utc>>,
}

/// A handle an administrator reserved: nobody takes it, or a look-alike, until an
/// administrator gives it to an account or removes it from the list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservedHandle {
    /// The reserved handle.
    pub handle: Handle,
    /// Who or what it is kept for.
    pub reason: String,
    /// When it was reserved.
    pub reserved_at: DateTime<Utc>,
}

/// A handle no account holds, but that is kept from others until an operator
/// releases it: one an account held before, which only it may claim again, or a
/// purged account's last one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedHandle {
    /// The handle.
    pub handle: Handle,
    /// The account that held it, or `None` once purged.
    pub user_id: Option<UserId>,
    /// When the account stopped using it, or `None` for a purged account's last one.
    pub released_at: Option<DateTime<Utc>>,
}
