//! The views of administration: what the admin dashboard shows and posts, and
//! what the CLI's `--output json` prints. Auth's service returns them, and its
//! database crate decodes some straight into them.
//!
//! Bodies the account settings also return come from [`crate::protocol::api`]
//! and are re-exported here.

pub use crate::protocol::api::{Identity, Passkey};
use crate::{
    AccountStatus, AuthenticationMethod, ClientId, EventId, Handle, SessionId, TokenId, TraceId,
    UserId, protocol::oauth::ClientAuthMethod,
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
