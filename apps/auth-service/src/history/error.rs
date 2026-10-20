//! History failures and their single mapping to browser responses.

use crate::security::ApiError;
use thiserror::Error;

/// Reports that cannot be made, mapped to HTTP once in `From<HistoryError>`.
#[derive(Debug, Error)]
pub(crate) enum HistoryError {
    /// The account's history shows no entry with this ID.
    #[error("history entry not found")]
    EntryNotFound,
    /// The entry was caused by someone other than the account's user, such as an
    /// administrator or an application.
    #[error("history entry was not caused by the account")]
    NotReportable,
}

impl From<HistoryError> for ApiError {
    /// Says which entries can be reported.
    fn from(error: HistoryError) -> Self {
        match error {
            HistoryError::EntryNotFound => {
                Self::not_found("Your security history has no such entry.")
            }
            HistoryError::NotReportable => Self::bad_request(
                "Only entries from your own sessions can be reported; this one was not.",
            ),
        }
    }
}
