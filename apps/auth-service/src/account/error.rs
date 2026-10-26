//! Failures of an account operation, from the owner's routes or the CLI.

use crate::{
    AdminError,
    clients::OwnedClientError,
    emails::EmailError,
    federation::FederationError,
    grants::GrantError,
    history::HistoryError,
    passkey::PasskeyError,
    recovery::RecoveryError,
    security::{ApiError, SessionError},
    sessions::SessionsError,
};
use axum::response::{IntoResponse, Response};
use piquel_repository::DatabaseError;

/// Why an account operation failed: the setting's own failure, or the actor's.
/// The owner's routes answer each failure as its module always has.
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
    /// An app's access could not be removed.
    #[error(transparent)]
    Grant(#[from] GrantError),
    /// A history entry could not be reported.
    #[error(transparent)]
    History(#[from] HistoryError),
    /// One of the owner's clients could not be registered or changed.
    #[error(transparent)]
    Client(#[from] OwnedClientError),
    /// A recovery link was refused, or a recovery could not be undone.
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
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
            AccountError::Grant(error) => error.into(),
            AccountError::History(error) => error.into(),
            AccountError::Client(error) => error.into(),
            AccountError::Recovery(error) => error.into(),
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
