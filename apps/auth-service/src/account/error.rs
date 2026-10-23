//! Failures of a shared settings operation, from the owner's routes or the CLI.

use crate::{
    AdminError,
    emails::EmailError,
    federation::FederationError,
    passkey::PasskeyError,
    security::{ApiError, SessionError},
    sessions::SessionsError,
};
use axum::response::{IntoResponse, Response};
use piquel_repository::DatabaseError;

/// Why a shared settings operation failed: the setting's own failure, or the
/// actor's. The owner's routes answer each failure as its module always has.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AccountError {
    /// A passkey could not be renamed or removed.
    #[error(transparent)]
    Passkey(#[from] PasskeyError),
    /// A linked identity could not be unlinked.
    #[error(transparent)]
    Identity(#[from] FederationError),
    /// An email address could not be changed or removed.
    #[error(transparent)]
    Email(#[from] EmailError),
    /// A session could not be signed out.
    #[error(transparent)]
    Session(#[from] SessionsError),
    /// The owner's session ended, or lacks a recent enough passkey confirmation.
    #[error(transparent)]
    Owner(#[from] SessionError),
    /// The administrator or operator may not act on this account.
    #[error(transparent)]
    Operator(#[from] AdminError),
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

impl From<AccountError> for ApiError {
    /// Answers as the failure's own module does.
    fn from(error: AccountError) -> Self {
        match error {
            AccountError::Passkey(error) => error.into(),
            AccountError::Identity(error) => error.into(),
            AccountError::Email(error) => error.into(),
            AccountError::Session(error) => error.into(),
            AccountError::Owner(error) => error.into(),
            AccountError::Operator(error) => error.into(),
            AccountError::Database(error) => error.into(),
        }
    }
}

impl IntoResponse for AccountError {
    /// Answers as [`ApiError`] does.
    fn into_response(self) -> Response {
        ApiError::from(self).into_response()
    }
}
