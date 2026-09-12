use super::*;

#[derive(Clone, Debug)]
pub struct InsertFederationTransaction {
    pub id: TokenId,
    pub provider: String,
    pub state_digest: Vec<u8>,
    pub browser_digest: Vec<u8>,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    pub link_user_id: Option<UserId>,
    pub link_session_id: Option<SessionId>,
    pub expires_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct ConsumedFederationTransaction {
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    pub link_user_id: Option<UserId>,
    pub link_session_id: Option<SessionId>,
}
#[derive(Clone, Debug)]
pub struct InsertExternalIdentity {
    pub id: TokenId,
    pub user_id: UserId,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub linked_email: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredExternalIdentity {
    pub id: TokenId,
    pub user_id: UserId,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub linked_email: Option<String>,
}
/// Verified provider evidence, usable only by its initiating browser until expiry.
#[derive(Clone, Debug)]
pub struct PendingFederation {
    pub id: TokenId,
    pub browser_digest: Vec<u8>,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: String,
    pub return_to: String,
    pub link_user_id: Option<UserId>,
    pub link_session_id: Option<SessionId>,
    pub expires_at: DateTime<Utc>,
}
