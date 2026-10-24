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
    /// A session no older passkey signed in tried to remove a passkey, identity
    /// or address from before a recovery that can still be undone.
    #[error("what predates an undoable recovery needs an older passkey to remove")]
    Protected,
    /// The undo's passkey was not enrolled before every recovery that can still
    /// be undone, or the account has no such passkey.
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
            RecoveryError::Protected => Self::forbidden(
                "Your account was recovered recently. Only a passkey you had before the recovery can remove what you had before it; Piquel support can too.",
            ),
            RecoveryError::OlderPasskeyRequired => {
                Self::forbidden("Use a passkey you had before this recovery to undo it.")
            }
        }
    }
}
