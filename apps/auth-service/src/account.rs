//! Account policy boundaries; persistence is delegated to the repository crate.

use crate::email::normalize;
use chrono::Utc;
use piquel_auth_protocol::{AccountStatus, TokenId, UserId};
use piquel_repository::{
    AppendAuditEvent, AppendInternalEvent, Database, DatabaseError, InsertUser,
    InsertVerifiedEmail, StoredUser,
};
use thiserror::Error;

/// Validated account profile snapshot used by the identity service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AccountProfile {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
    pub version: u64,
    pub status: AccountStatus,
}

pub(super) struct CreateAccount {
    pub username: String,
    pub display_name: String,
    pub verified_email: Option<String>,
}

#[derive(Debug, Error)]
pub(super) enum AccountError {
    #[error("invalid account profile")]
    InvalidProfile,
    #[error("account operation failed")]
    Database(#[from] DatabaseError),
}

/// Creates account state, optional verified email, audit, and internal event in one transaction.
pub(super) async fn create(
    database: &Database,
    input: CreateAccount,
) -> Result<StoredUser, AccountError> {
    validate_username(&input.username).map_err(|()| AccountError::InvalidProfile)?;
    validate_display_name(&input.display_name).map_err(|()| AccountError::InvalidProfile)?;
    let email = input
        .verified_email
        .as_deref()
        .map(normalize)
        .transpose()
        .map_err(|()| AccountError::InvalidProfile)?;
    let user_id = UserId::new();
    let mut transaction = database.begin().await?;
    let user = transaction
        .users()
        .insert(&InsertUser {
            id: user_id,
            username: input.username,
            display_name: input.display_name,
        })
        .await?;
    if let Some(email) = email {
        transaction
            .emails()
            .insert_verified(&InsertVerifiedEmail {
                id: TokenId::new(),
                user_id,
                normalized_email: email.as_str().to_owned(),
                is_primary: true,
                verified_at: Utc::now(),
            })
            .await?;
    }
    transaction
        .audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(user_id),
            action: "account.create".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({}),
        })
        .await?;
    transaction
        .internal_events()
        .append(&AppendInternalEvent {
            id: TokenId::new(),
            aggregate_type: "user".into(),
            aggregate_id: user_id,
            event_type: "account.created".into(),
            schema_version: 1,
            payload: serde_json::json!({"profile_version": 1}),
        })
        .await?;
    transaction.commit().await?;
    Ok(user)
}

/// Checks the deliberately narrow username policy used for initial accounts.
pub(super) fn validate_username(value: &str) -> Result<(), ()> {
    if !(3..=32).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(());
    }
    Ok(())
}
/// Checks a presentation name without treating it as an identity key.
pub(super) fn validate_display_name(value: &str) -> Result<(), ()> {
    if value.trim().is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_validation_is_deliberate() {
        assert!(validate_username("ada_lovelace").is_ok());
        assert!(validate_username("Ada").is_err());
        assert!(validate_display_name("Ada Lovelace").is_ok());
    }
}
