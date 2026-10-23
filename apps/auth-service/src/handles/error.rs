//! Why a handle cannot be taken, and the single mapping to browser responses.

use crate::security::ApiError;
use chrono::{DateTime, Utc};
use piquel_common::{Handle, HandleError, protocol::api::ErrorCode};
use piquel_repository::DatabaseError;
use thiserror::Error;

/// Why an account cannot take a handle, or why looking it up failed. Signup, the
/// settings API and the admin operations share it, mapped to HTTP once in
/// `From<HandlesError>`.
#[derive(Debug, Error)]
pub enum HandlesError {
    /// The handle breaks the syntax, or is reserved.
    #[error(transparent)]
    Refused(#[from] HandleError),
    /// Another account has the handle.
    #[error("another account has this handle")]
    Taken,
    /// The handle belonged to another account. Handles are never reassigned.
    #[error("this handle belonged to another account")]
    Retired,
    /// The handle looks like this one, which an account holds or held.
    #[error("this handle looks like {0}")]
    Confusable(Handle),
    /// The account already has the handle.
    #[error("this is already the account's handle")]
    Current,
    /// The handle changed less than the cooldown ago.
    #[error("the handle changed recently; it can change again at {retry_after}")]
    Cooldown {
        /// When it may change again.
        retry_after: DateTime<Utc>,
    },
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

impl From<HandlesError> for ApiError {
    /// Says why the handle is refused, with its `handle_*` code.
    fn from(error: HandlesError) -> Self {
        let (message, code) = match error {
            HandlesError::Refused(error) => return error.into(),
            HandlesError::Database(error) => return error.into(),
            HandlesError::Taken => (
                "This handle is taken. Choose another one.".to_owned(),
                ErrorCode::HandleTaken,
            ),
            HandlesError::Retired => (
                "This handle belonged to another account, and handles are never reused. \
                 Choose another one."
                    .to_owned(),
                ErrorCode::HandleRetired,
            ),
            HandlesError::Confusable(handle) => (
                format!("This handle looks too much like @{handle}. Choose another one."),
                ErrorCode::HandleConfusable,
            ),
            HandlesError::Current => (
                "This is already your handle.".to_owned(),
                ErrorCode::HandleCurrent,
            ),
            HandlesError::Cooldown { retry_after } => (
                format!(
                    "Your handle changed less than {} days ago. You can change it again on {}.",
                    super::COOLDOWN.num_days(),
                    retry_after.format("%B %-d, %Y")
                ),
                ErrorCode::HandleCooldown { retry_after },
            ),
        };
        Self::conflict(message).with_code(code)
    }
}
