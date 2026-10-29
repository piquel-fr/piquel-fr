//! Why a handle cannot be taken, and the single mapping to browser responses.

use crate::security::ApiError;
use chrono::{DateTime, Utc};
use piquel_common::{Handle, HandleError, protocol::api::ErrorCode};
use piquel_repository::DatabaseError;
use thiserror::Error;

/// Why an account cannot take a handle, or why looking it up failed. Signup, the
/// settings and the admin operations share it, mapped to HTTP once in
/// `From<HandlesError>`.
#[derive(Debug, Error)]
pub enum HandlesError {
    /// The handle breaks the syntax, or is reserved.
    #[error(transparent)]
    Refused(#[from] HandleError),
    /// Another account has the handle.
    #[error("another account has this handle")]
    Taken,
    /// The handle belonged to another account, which keeps it until an operator
    /// releases it.
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
    /// Says why the handle is refused. A taken handle has the code signup always
    /// answered with.
    fn from(error: HandlesError) -> Self {
        let message = match error {
            HandlesError::Refused(error) => return error.into(),
            HandlesError::Database(error) => return error.into(),
            HandlesError::Taken => {
                return Self::conflict("This handle is taken. Choose another one.")
                    .with_code(ErrorCode::HandleTaken);
            }
            HandlesError::Retired => {
                "This handle belonged to another account. Choose another one.".to_owned()
            }
            HandlesError::Confusable(handle) => {
                format!("This handle looks too much like @{handle}. Choose another one.")
            }
            HandlesError::Current => "This is already the account's handle.".to_owned(),
            HandlesError::Cooldown { retry_after } => format!(
                "Your handle changed less than {} days ago. You can change it again on {}.",
                super::COOLDOWN.num_days(),
                retry_after.format("%B %-d, %Y")
            ),
        };
        Self::conflict(message)
    }
}
