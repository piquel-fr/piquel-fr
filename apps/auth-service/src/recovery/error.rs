//! Recovery failures and their single mapping to browser responses.

use crate::security::ApiError;
use thiserror::Error;

/// Why a recovery link or an undo was refused.
#[derive(Debug, Error)]
pub(crate) enum RecoveryError {
    /// The link is unknown, expired, used, replaced or undone, or its account was
    /// disabled.
    #[error("the recovery link no longer works")]
    InvalidLink,
    /// The account has no recovery its owner could undo.
    #[error("no recovery to undo")]
    NothingToUndo,
    /// The undo named a recovery that is no longer the account's newest
    /// undoable one.
    #[error("the recovery to undo changed")]
    Changed,
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
            RecoveryError::Changed => Self::conflict(
                "This recovery changed since you opened this page. Reload it to see what undoing it removes.",
            ),
            RecoveryError::OlderPasskeyRequired => {
                Self::forbidden("Sign in with a passkey you had before this recovery to undo it.")
            }
        }
    }
}
