//! Removal failures and their single mapping to browser responses.

use crate::security::ApiError;
use thiserror::Error;

/// Apps whose access cannot be removed, mapped to HTTP once in `From<GrantError>`.
#[derive(Debug, Error)]
pub(crate) enum GrantError {
    /// The app keeps no access to the account.
    #[error("app not connected")]
    NotFound,
}

impl From<GrantError> for ApiError {
    /// Says the app has nothing left to remove.
    fn from(error: GrantError) -> Self {
        match error {
            GrantError::NotFound => Self::not_found(
                "This app has no access to your account; it may already be removed.",
            ),
        }
    }
}
