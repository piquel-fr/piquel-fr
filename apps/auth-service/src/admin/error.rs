//! Admin operation failures and their single conversion boundary to browser responses.

use crate::security::ApiError;
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;

/// Failures of an administrative operation, from the admin API or the CLI.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// No account has this ID or username.
    #[error("no account has this ID or username")]
    UserNotFound,
    /// No active session has this ID.
    #[error("no active session has this ID")]
    SessionNotFound,
    /// No unredeemed, unrevoked invitation has this ID.
    #[error("no unredeemed, unrevoked invitation has this ID")]
    InvitationNotFound,
    /// No OIDC client has this ID.
    #[error("no OIDC client has this ID")]
    ClientNotFound,
    /// The admin API never changes administrator accounts, so a stolen admin
    /// session cannot lock other administrators out. Only the CLI can.
    #[error("administrator accounts can only be changed with the auth-service CLI")]
    AdministratorTarget,
    /// The calling administrator lost its rights, session or passkey confirmation
    /// while the request was in progress.
    #[error("administrator caller is no longer authorized")]
    CallerUnauthorized,
    /// The account is already disabled.
    #[error("the account is already disabled")]
    AlreadyDisabled,
    /// The account is already active.
    #[error("the account is already active")]
    AlreadyActive,
    /// Reactivation found a verified email of the account owned by another active account.
    #[error("another active account has claimed one of this account's verified emails")]
    EmailClaimed(#[source] DatabaseError),
    /// The administrator's reason is blank, too long or contains control characters.
    #[error("invalid reason")]
    InvalidReason,
    /// Only active accounts can become administrators.
    #[error("the account is disabled; enable it before granting administrator rights")]
    AccountDisabled,
    /// The account is already an administrator.
    #[error("the account is already an administrator")]
    AlreadyAdministrator,
    /// The account is not an administrator.
    #[error("the account is not an administrator")]
    NotAdministrator,
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// Invitation secret generation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<AdminError> for ApiError {
    /// Maps every admin failure to a stable status and actionable message.
    fn from(error: AdminError) -> Self {
        match error {
            AdminError::UserNotFound => Self::not_found("No account has this ID."),
            AdminError::SessionNotFound => Self::not_found("No active session has this ID."),
            AdminError::InvitationNotFound => {
                Self::not_found("No unredeemed, unrevoked invitation has this ID.")
            }
            AdminError::ClientNotFound => Self::not_found("No OIDC client has this ID."),
            AdminError::AdministratorTarget => Self::forbidden(
                "Administrator accounts can only be changed with the auth-service CLI.",
            ),
            AdminError::CallerUnauthorized => Self::forbidden(
                "Your admin session or passkey confirmation ended. Confirm with a passkey again.",
            ),
            AdminError::AlreadyDisabled => Self::conflict("This account is already disabled."),
            AdminError::AlreadyActive => Self::conflict("This account is already active."),
            AdminError::EmailClaimed(_) => Self::conflict(
                "Another active account has claimed one of this account's verified emails.",
            ),
            AdminError::InvalidReason => Self::bad_request(
                "Give a reason of 1 to 500 characters, without control characters.",
            ),
            AdminError::AccountDisabled => {
                Self::conflict("This account is disabled. Enable it first.")
            }
            AdminError::AlreadyAdministrator => {
                Self::conflict("This account is already an administrator.")
            }
            AdminError::NotAdministrator => Self::conflict("This account is not an administrator."),
            AdminError::Database(error) => error.into(),
            error @ AdminError::Crypto(_) => Self::internal(error),
        }
    }
}
