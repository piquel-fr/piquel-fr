//! Recovery failures and their single mapping to browser responses.

use crate::security::ApiError;
use chrono::{DateTime, Utc};
use piquel_common::protocol::api::ErrorCode;
use thiserror::Error;

/// Why a recovery link, a passkey of a recovery, or an undo was refused.
#[derive(Debug, Error)]
pub(crate) enum RecoveryError {
    /// The link is unknown, expired, used or cancelled, or its account was
    /// disabled.
    #[error("the recovery link no longer works")]
    InvalidLink,
    /// The named recovery is not the account's undoable one.
    #[error("no recovery to undo")]
    NothingToUndo,
    /// The undo's passkey is the recovery's own, or the account has no other.
    #[error("undoing a recovery needs a passkey from before it")]
    OlderPasskeyRequired,
    /// The passkey belongs to a recovery in probation, which never confirms a
    /// session.
    #[error("a recovered passkey confirms nothing until {settles_at}")]
    Probation {
        /// When the probation ends.
        settles_at: DateTime<Utc>,
    },
    /// While a recovery can be undone, no passkey but its own is removed.
    #[error("the account has a recovery that can still be undone")]
    InProgress,
}

impl From<RecoveryError> for ApiError {
    /// Says what the browser can do instead.
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::InvalidLink => Self::bad_request(
                "This recovery link no longer works. Ask Piquel support for a new one.",
            )
            .with_code(ErrorCode::InvalidLink),
            RecoveryError::NothingToUndo => {
                Self::not_found("Your account has no recovery to undo.")
                    .with_code(ErrorCode::NothingToUndo)
            }
            RecoveryError::OlderPasskeyRequired => Self::forbidden(
                "Use a passkey you had before this recovery to undo it, or ask Piquel support.",
            )
            .with_code(ErrorCode::OlderPasskeyRequired),
            RecoveryError::Probation { settles_at } => Self::forbidden(
                "Your account was recovered recently. Until the recovery settles, its passkey can't confirm changes to your account.",
            )
            .with_code(ErrorCode::RecoveryProbation { settles_at }),
            RecoveryError::InProgress => Self::conflict(
                "Your account has a recovery that can still be undone. Until it settles, only the recovery's passkey can be removed.",
            )
            .with_code(ErrorCode::RecoveryInProgress),
        }
    }
}
