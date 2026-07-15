//! Account policy boundaries; persistence is delegated to the repository crate.

use crate::email::normalize;
use chrono::Utc;
use piquel_auth_protocol::{AccountStatus, TokenId, UserId};
use piquel_repository::{
    AppendAuditEvent, AppendInternalEvent, Database, DatabaseError, InsertUser,
    InsertVerifiedEmail, StoredUser, UpdateUserProfile,
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

pub(super) struct UpdateAccountProfile {
    pub id: UserId,
    pub expected_version: u64,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Error)]
pub(super) enum AccountError {
    #[error("invalid account profile")]
    InvalidProfile,
    #[error("account operation failed")]
    Database(#[from] DatabaseError),
}

impl From<StoredUser> for AccountProfile {
    fn from(user: StoredUser) -> Self {
        Self {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            version: user.profile_version,
            status: user.status,
        }
    }
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

/// Disables an account and invalidates every central session atomically.
///
/// Later token plans extend this same transaction with refresh-family
/// revocation; callers must not update account status directly.
pub(super) async fn disable(database: &Database, user_id: UserId) -> Result<bool, AccountError> {
    let mut transaction = database.begin().await?;
    let changed = transaction
        .users()
        .set_status(user_id, AccountStatus::Disabled)
        .await?;
    if !changed {
        transaction.rollback().await?;
        return Ok(false);
    }
    transaction.sessions().revoke_all_for_user(user_id).await?;
    transaction.tokens().revoke_all_for_user(user_id).await?;
    transaction
        .audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(user_id),
            action: "account.disable".into(),
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
            event_type: "account.disabled".into(),
            schema_version: 1,
            payload: serde_json::json!({}),
        })
        .await?;
    transaction.commit().await?;
    Ok(true)
}

/// Reads the current account profile snapshot.
pub(super) async fn find(
    database: &Database,
    user_id: UserId,
) -> Result<Option<AccountProfile>, AccountError> {
    Ok(database
        .users()
        .find_by_id(user_id)
        .await?
        .map(AccountProfile::from))
}

/// Updates presentation fields and emits the matching event atomically.
pub(super) async fn update_profile(
    database: &Database,
    input: UpdateAccountProfile,
) -> Result<AccountProfile, AccountError> {
    validate_username(&input.username).map_err(|()| AccountError::InvalidProfile)?;
    validate_display_name(&input.display_name).map_err(|()| AccountError::InvalidProfile)?;

    let mut transaction = database.begin().await?;
    let user = transaction
        .users()
        .update_profile(&UpdateUserProfile {
            id: input.id,
            expected_version: input.expected_version,
            username: input.username,
            display_name: input.display_name,
        })
        .await?;
    transaction
        .internal_events()
        .append(&AppendInternalEvent {
            id: TokenId::new(),
            aggregate_type: "user".into(),
            aggregate_id: user.id,
            event_type: "profile.updated".into(),
            schema_version: 1,
            payload: serde_json::json!({"profile_version": user.profile_version}),
        })
        .await?;
    transaction.commit().await?;
    Ok(user.into())
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
    use piquel_repository::DatabaseConfig;
    use std::{env, time::Duration};

    #[test]
    fn profile_validation_is_deliberate() {
        assert!(validate_username("ada_lovelace").is_ok());
        assert!(validate_username("Ada").is_err());
        assert!(validate_display_name("Ada Lovelace").is_ok());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn profile_update_and_event_commit_together() {
        let url = env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        let config = DatabaseConfig::new_development(&url, 5, Duration::from_secs(5))
            .expect("test database configuration");
        let database = Database::connect(config).await.expect("connect database");
        database.run_migrations().await.expect("run migrations");

        let unique = UserId::new().to_string();
        let suffix = &unique[unique.len() - 12..];
        let created = create(
            &database,
            CreateAccount {
                username: format!("profile_{suffix}"),
                display_name: "Before".into(),
                verified_email: None,
            },
        )
        .await
        .expect("create account");
        let updated = update_profile(
            &database,
            UpdateAccountProfile {
                id: created.id,
                expected_version: created.profile_version,
                username: created.username,
                display_name: "After".into(),
            },
        )
        .await
        .expect("update profile");
        assert_eq!(updated.version, 2);

        let next_sequence = database
            .internal_events()
            .append(&AppendInternalEvent {
                id: TokenId::new(),
                aggregate_type: "user".into(),
                aggregate_id: created.id,
                event_type: "test.probe".into(),
                schema_version: 1,
                payload: serde_json::json!({}),
            })
            .await
            .expect("append probe event");
        assert_eq!(next_sequence, 3);
    }
}
