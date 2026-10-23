//! Client API failures and their single mapping to browser responses.

use crate::{
    clients::{ClientRegistryError, MAX_DAILY_REGISTRATIONS, MAX_OWNED_CLIENTS},
    security::ApiError,
};
use piquel_common::{clients::ClientField, protocol::api::ErrorCode};
use std::error::Error;
use thiserror::Error;

/// Requests the client API refuses before the registry sees them.
#[derive(Debug, Error)]
pub(super) enum ClientApiError {
    /// The account manages no live client with this ID.
    #[error("client not found")]
    NotFound,
}

/// A setting an owner gave that is invalid, with the field it was given for.
#[derive(Debug, Error)]
#[error("{field}: {source}")]
pub(super) struct InvalidSetting {
    /// The rejected setting.
    field: ClientField,
    /// What is wrong with it, from the type that validates it.
    source: Box<dyn Error + Send + Sync>,
}

impl InvalidSetting {
    /// Rejects `field` for `reason`.
    pub(super) fn new(field: ClientField, reason: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self {
            field,
            source: reason.into(),
        }
    }

    /// Rejects `field` for the error the mapped function receives.
    pub(super) fn with<E: Error + Send + Sync + 'static>(field: ClientField) -> impl Fn(E) -> Self {
        move |error| Self::new(field.clone(), error)
    }
}

impl From<ClientApiError> for ApiError {
    /// Says that no client of the account has the ID.
    fn from(error: ClientApiError) -> Self {
        match error {
            ClientApiError::NotFound => Self::not_found("You have no client with this ID."),
        }
    }
}

impl From<InvalidSetting> for ApiError {
    /// Names the field, with RFC 7591's code for redirect URIs or other metadata.
    fn from(error: InvalidSetting) -> Self {
        let field = error.field.clone();
        let code = if field.redirects() {
            ErrorCode::InvalidRedirectUri { field }
        } else {
            ErrorCode::InvalidClientMetadata { field }
        };
        Self::bad_request(error.to_string()).with_code(code)
    }
}

impl From<ClientRegistryError> for ApiError {
    /// A deleted client is as unknown as one that never existed. Related-origin
    /// refusals, which only the admin API causes, name what to fix. Other failures
    /// the account API cannot cause are internal.
    fn from(error: ClientRegistryError) -> Self {
        match error {
            ClientRegistryError::Unknown(_) | ClientRegistryError::Deleted(_) => {
                ClientApiError::NotFound.into()
            }
            ClientRegistryError::Public(_) => {
                Self::bad_request("This client is public, so it has no secret to rotate.")
            }
            ClientRegistryError::QuotaExceeded => Self::conflict(format!(
                "You can have at most {MAX_OWNED_CLIENTS} clients. Delete one to register another."
            ))
            .with_code(ErrorCode::ClientQuotaExceeded {
                limit: MAX_OWNED_CLIENTS,
            }),
            ClientRegistryError::DailyLimitExceeded => Self::conflict(format!(
                "You can register at most {MAX_DAILY_REGISTRATIONS} clients a day, deleted ones \
                 included. Try again tomorrow."
            ))
            .with_code(ErrorCode::DailyClientLimitExceeded {
                limit: MAX_DAILY_REGISTRATIONS,
            }),
            ClientRegistryError::Suspended(_) => Self::forbidden(
                "This client was suspended by an administrator. Contact them to restore it.",
            )
            .with_code(ErrorCode::ClientSuspended),
            error @ (ClientRegistryError::Untrusted(_)
            | ClientRegistryError::NotRedirectOrigin { .. }
            | ClientRegistryError::PublicSuffix(_)) => Self::bad_request(error.to_string()),
            error @ (ClientRegistryError::TooManyDomains(_)
            | ClientRegistryError::OriginApproved { .. }) => Self::conflict(error.to_string()),
            error @ ClientRegistryError::OriginNotApproved { .. } => {
                Self::not_found(error.to_string())
            }
            ClientRegistryError::Database(error) => error.into(),
            error @ (ClientRegistryError::Exists { .. }
            | ClientRegistryError::MissingSecret(_)
            | ClientRegistryError::Immutable(_)
            | ClientRegistryError::Crypto(_)) => Self::internal(error),
        }
    }
}
