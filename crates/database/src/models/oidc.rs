use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredOidcClient {
    pub id: String,
    pub display_name: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub allow_refresh: bool,
    pub enabled: bool,
    pub trusted: bool,
    pub client_secret_hash: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct InsertAuthorizationRequest {
    pub id: TokenId,
    pub secret_digest: Vec<u8>,
    pub client_id: String,
    pub redirect_uri: String,
    pub client_state: String,
    pub nonce: Option<String>,
    pub pkce_challenge: String,
    pub scopes: Vec<String>,
    pub audience: String,
    pub force_login: bool,
    pub force_consent: bool,
    pub max_age: Option<i64>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct StoredAuthorizationRequest {
    pub id: TokenId,
    pub client_id: String,
    pub client_display_name: String,
    pub redirect_uri: String,
    pub client_state: String,
    pub nonce: Option<String>,
    pub pkce_challenge: String,
    pub scopes: Vec<String>,
    pub audience: String,
    pub force_login: bool,
    pub force_consent: bool,
    pub max_age: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct BootstrapOidcClient {
    pub id: String,
    pub display_name: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub allow_refresh: bool,
    pub enabled: bool,
    pub trusted: bool,
    pub client_secret_hash: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct InsertAuthorizationCode {
    pub id: TokenId,
    pub secret_digest: Vec<u8>,
    pub client_id: String,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub redirect_uri: String,
    pub pkce_challenge: String,
    pub nonce: Option<String>,
    pub scopes: Vec<String>,
    pub audience: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ConsumedAuthorizationCode {
    pub client_id: String,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub redirect_uri: String,
    pub pkce_challenge: String,
    pub nonce: Option<String>,
    pub scopes: Vec<String>,
    pub audience: String,
}

#[derive(Clone, Debug)]
pub struct InsertRefreshFamily {
    pub id: TokenId,
    pub user_id: UserId,
    pub client_id: String,
    pub session_id: SessionId,
    pub audience: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct InsertRefreshToken {
    pub id: TokenId,
    pub family_id: TokenId,
    pub secret_digest: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RotatedRefreshToken {
    pub family_id: TokenId,
    pub user_id: UserId,
    pub client_id: String,
    pub session_id: SessionId,
    pub audience: String,
    pub scopes: Vec<String>,
}

#[derive(Debug)]
pub enum RefreshRotationError {
    Database(crate::DatabaseError),
    Invalid,
    Replay { user_id: UserId },
    Policy { user_id: UserId },
}

impl RefreshRotationError {
    pub(crate) fn database(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Database(crate::DatabaseError::Operation(Box::new(error)))
    }
}
