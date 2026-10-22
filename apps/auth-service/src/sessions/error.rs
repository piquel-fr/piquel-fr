//! Sign-out failures and their single mapping to browser responses.

use crate::security::ApiError;
use thiserror::Error;

/// Sessions that cannot be signed out from settings, mapped to HTTP once in
/// `From<SessionsError>`.
#[derive(Debug, Error)]
pub(crate) enum SessionsError {
    /// The account has no active session with this ID.
    #[error("session not found")]
    NotFound,
    /// The request named its own session.
    #[error("the current session cannot sign itself out here")]
    Current,
}

impl From<SessionsError> for ApiError {
    /// Says which sessions can be signed out here.
    fn from(error: SessionsError) -> Self {
        match error {
            SessionsError::NotFound => {
                Self::not_found("You have no such session; it may already be signed out.")
            }
            SessionsError::Current => Self::bad_request(
                "This is the session you are using; sign out of it with /session/logout.",
            ),
        }
    }
}
