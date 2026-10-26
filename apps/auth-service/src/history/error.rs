//! History failures and their single mapping to browser responses.

use crate::security::ApiError;
use thiserror::Error;

/// Reports that cannot be made, mapped to HTTP once in `From<HistoryError>`.
#[derive(Debug, Error)]
pub(crate) enum HistoryError {
    /// The account's history shows no entry with this ID.
    #[error("history entry not found")]
    EntryNotFound,
    /// The entry cannot be reported: someone other than the account's user caused
    /// it, such as an administrator or an application, or it is one no report
    /// applies to, such as the account's creation.
    #[error("history entry cannot be reported")]
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
                "Only entries from your own sessions can be reported, and not this one.",
            ),
        }
    }
}
