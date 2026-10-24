//! Recovery failures and their single mapping to browser responses.

use crate::security::ApiError;
use thiserror::Error;

/// Why a recovery link or an undo was refused.
#[derive(Debug, Error)]
pub(crate) enum RecoveryError {
    /// The link is unknown, expired, used, replaced or undone.
    #[error("the recovery link no longer works")]
    InvalidLink,
    /// The account has no recovery its owner could undo.
    #[error("no recovery to undo")]
    NothingToUndo,
    /// The session was not signed in, or confirmed, by a passkey enrolled before
    /// the recovery started.
    #[error("undoing a recovery needs a passkey enrolled before it")]
    OlderPasskeyRequired,
}

impl From<RecoveryError> for ApiError {
    /// Says what the browser can do instead.
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::InvalidLink => Self::bad_request(
                "This recovery link no longer works. Ask Piquel support for a new one.",
            ),
            RecoveryError::NothingToUndo => {
                Self::not_found("Your account has no recovery to undo.")
            }
            RecoveryError::OlderPasskeyRequired => {
                Self::forbidden("Sign in with a passkey you had before this recovery to undo it.")
            }
        }
    }
}
