//! Account export and deletion failures, and their one conversion to responses.

use crate::{ClientRegistryError, security::ApiError};
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;

/// Failures of exporting, deleting, restoring or purging an account, from
/// settings, the admin API, the CLI or the purge job.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// The username typed to confirm a deletion is not the account's.
    #[error("the username does not match the account")]
    UsernameMismatch,
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
    /// The restore token is malformed, expired, replaced or already used.
    #[error("the restore token is invalid or expired")]
    RestoreExpired,
    /// No account has this ID.
    #[error("no account has this ID")]
    NotFound,
    /// Deleting a client the account manages failed.
    #[error(transparent)]
    Client(#[from] ClientRegistryError),
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// The restore token could not be generated.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<AccountError> for ApiError {
    /// Maps every account failure to a stable status and a message to show.
    fn from(error: AccountError) -> Self {
        match error {
            AccountError::UsernameMismatch => {
                Self::bad_request("Type your username exactly as shown to confirm.")
            }
            AccountError::RestoreExpired => Self::bad_request(
                "This restore request has expired. Sign in with your passkey again to restore your account.",
            ),
            AccountError::LastAdministrator => Self::forbidden(
                "The last administrator's account cannot be deleted. Grant another administrator first.",
            ),
            AccountError::NotFound => Self::not_found("No account has this ID."),
            AccountError::NotActive => {
                Self::conflict("Only an active account can be scheduled for deletion.")
            }
            AccountError::NotScheduled => {
                Self::conflict("This account is not scheduled for deletion.")
            }
            AccountError::Client(error) => error.into(),
            AccountError::Database(error) => error.into(),
            error @ AccountError::Crypto(_) => Self::internal(error),
        }
    }
}
