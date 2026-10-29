//! Failures of deleting, restoring or purging an account, and their one
//! conversion to responses.

use crate::{ClientRegistryError, security::ApiError};
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;

/// Why an account could not be deleted, restored or purged, from settings, the
/// sign-in page, `AdminService`, the CLI or the purge job.
#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    /// The handle typed to confirm a deletion is not the account's.
    #[error("the handle does not match the account")]
    HandleMismatch,
    /// Deleting the last active administrator would leave nobody to administer.
    #[error(
        "the last administrator's account cannot be deleted; grant another administrator first"
    )]
    LastAdministrator,
    /// Only active accounts can be scheduled for deletion. A disabled one is
    /// purged at once, or enabled first.
    #[error("only an active account can be scheduled for deletion")]
    NotActive,
    /// The account is not scheduled for deletion.
    #[error("the account is not scheduled for deletion")]
    NotScheduled,
    /// The browser holds no restore offer, or it expired, was replaced or used.
    #[error("the restore offer is missing or expired")]
    RestoreExpired,
    /// No account has this ID.
    #[error("no account has this ID")]
    NotFound,
    /// A client the account manages could not be deleted.
    #[error(transparent)]
    Client(#[from] ClientRegistryError),
    /// The restore token could not be generated.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

impl From<DeletionError> for ApiError {
    /// Maps every failure to a stable status and a message to show.
    fn from(error: DeletionError) -> Self {
        match error {
            DeletionError::HandleMismatch => {
                Self::bad_request("Type your handle exactly as shown to confirm.")
            }
            DeletionError::RestoreExpired => Self::bad_request(
                "This restore offer has expired. Sign in with your passkey again to restore your account.",
            ),
            DeletionError::LastAdministrator => Self::forbidden(
                "The last administrator's account cannot be deleted. Grant another administrator first.",
            ),
            DeletionError::NotFound => Self::not_found("No account has this ID."),
            DeletionError::NotActive => {
                Self::conflict("Only an active account can be scheduled for deletion.")
            }
            DeletionError::NotScheduled => {
                Self::conflict("This account is not scheduled for deletion.")
            }
            DeletionError::Client(error) => error.into(),
            DeletionError::Database(error) => error.into(),
            error @ DeletionError::Crypto(_) => Self::internal(error),
        }
    }
}
