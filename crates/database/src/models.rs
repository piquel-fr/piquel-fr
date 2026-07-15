use chrono::{DateTime, Utc};
use piquel_auth_protocol::{AccountStatus, AuthenticationMethod, SessionId, TokenId, UserId};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredUser {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
    pub profile_version: u64,
    pub status: AccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct InsertUser {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
}
#[derive(Clone, Debug)]
pub struct UpdateUserProfile {
    pub id: UserId,
    pub expected_version: u64,
    pub username: String,
    pub display_name: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEmail {
    pub id: TokenId,
    pub user_id: UserId,
    pub normalized_email: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub is_primary: bool,
}
#[derive(Clone, Debug)]
pub struct InsertVerifiedEmail {
    pub id: TokenId,
    pub user_id: UserId,
    pub normalized_email: String,
    pub is_primary: bool,
    pub verified_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct InsertSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub user_agent_family: Option<String>,
}
#[derive(Clone, Debug)]
pub struct StoredSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug)]
pub struct AppendAuditEvent {
    pub id: TokenId,
    pub user_id: Option<UserId>,
    pub action: String,
    pub outcome: String,
    pub request_metadata: Value,
}
#[derive(Clone, Debug)]
pub struct AppendInternalEvent {
    pub id: TokenId,
    pub aggregate_type: String,
    pub aggregate_id: UserId,
    pub event_type: String,
    pub schema_version: u32,
    pub payload: Value,
}

#[derive(Clone, Debug)]
pub struct InsertPasskey {
    pub id: TokenId,
    pub credential_id: Vec<u8>,
    pub user_id: UserId,
    pub credential: Value,
    pub friendly_name: String,
}
#[derive(Clone, Debug)]
pub struct StoredPasskey {
    pub id: TokenId,
    pub credential_id: Vec<u8>,
    pub user_id: UserId,
    pub credential: Value,
    pub friendly_name: String,
    pub revoked_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug)]
pub struct InsertCeremony {
    pub id: TokenId,
    pub user_id: Option<UserId>,
    pub session_id: Option<SessionId>,
    pub kind: String,
    pub challenge_digest: Vec<u8>,
    pub state: Value,
    pub expires_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct ConsumedCeremony {
    pub user_id: Option<UserId>,
    pub session_id: Option<SessionId>,
    pub state: Value,
}
#[derive(Clone, Debug)]
pub struct InsertPurposeAuthorization {
    pub id: TokenId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
}
