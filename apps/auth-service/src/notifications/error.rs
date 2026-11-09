//! Notification failures and their single mapping to responses.

use crate::security::ApiError;
use thiserror::Error;

/// Why a notification could not be read or marked, mapped to HTTP once in
/// `From<NotificationError>`.
#[derive(Debug, Error)]
pub(crate) enum NotificationError {
    /// The account has no notification with this ID.
    #[error("notification not found")]
    NotFound,
}

impl From<NotificationError> for ApiError {
    /// Says the inbox has no such notification.
    fn from(error: NotificationError) -> Self {
        match error {
            NotificationError::NotFound => Self::not_found("Your inbox has no such notification."),
        }
    }
}
