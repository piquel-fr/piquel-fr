//! Federation failures and their single mapping to browser responses.

use crate::security::{ApiError, SessionError};
use axum::http::header::InvalidHeaderValue;
use piquel_common::{ConfigurationError, VocabularyError};
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;
use thiserror::Error;

/// Federation failures that reach the browser, mapped to HTTP once in `From<FederationError>`.
/// Provider exchange failures are a separate `ProviderError`: they are logged, never shown.
#[derive(Debug, Error)]
pub(crate) enum FederationError {
    /// A route names a provider outside the shared vocabulary.
    #[error("unsupported sign-in provider")]
    UnsupportedProvider(#[source] VocabularyError),
    /// The requested provider has no configured credentials.
    #[error("sign-in provider is not configured")]
    ProviderNotConfigured,
    /// `return_to` is neither the settings URL nor a safe path on the auth origin.
    #[error("return address is not allowed")]
    InvalidReturnTo,
    /// The flow cookie is missing, or the account is inactive or lacks a passkey.
    #[error("active browser binding or account required")]
    Unauthorized,
    /// The callback's `state` is missing or malformed.
    #[error("sign-in attempt is invalid or expired")]
    InvalidAttempt,
    /// The linking callback arrived in a different session than the one that started it.
    #[error("session changed during provider linking")]
    SessionChanged,
    /// Another account already owns this provider subject.
    #[error("provider identity belongs to another account")]
    IdentityAlreadyLinked,
    /// The signup ID named by registration is not this browser's pending evidence.
    #[error("pending signup expired")]
    PendingSignupExpired,
    /// This browser's pending sign-in or link evidence is gone.
    #[error("pending sign-in expired")]
    PendingSignInExpired,
    /// A social signup names evidence that must be linked to an existing account instead.
    #[error("existing account must confirm linking with a passkey")]
    SignupRequiresLink,
    /// Signup tried to attach evidence before the account's first passkey existed.
    #[error("first passkey required for social signup")]
    FirstPasskeyRequired,
    /// The provider's verified email belongs to another account.
    #[error("observed email belongs to an existing account")]
    EmailAlreadyOwned,
    /// The passkey management grant expired before the account lock was acquired.
    #[error("passkey management authorization expired")]
    ManagementExpired,
    /// The current account or session is not the one the pending link targets.
    #[error("passkey session does not match the intended linking account")]
    LinkAccountMismatch,
    /// The account to link has no active passkey.
    #[error("linking requires an active passkey")]
    LinkRequiresPasskey,
    /// The provider being unlinked has no active identity on this account.
    #[error("provider is not linked to this account")]
    IdentityNotLinked,
    /// A built-in provider authorization URL is invalid.
    #[error("provider authorization URL is invalid")]
    Url(#[from] url::ParseError),
    /// A database operation failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// Shared browser-session policy rejected the request.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// Random flow secrets or the PKCE challenge could not be generated.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A generated cookie is not a valid HTTP header value.
    #[error("federation cookie header is invalid")]
    CookieHeader(#[from] InvalidHeaderValue),
}

impl From<FederationError> for ApiError {
    /// The single place mapping each federation failure to its status and browser message.
    fn from(error: FederationError) -> Self {
        match error {
            FederationError::UnsupportedProvider(_) => {
                Self::bad_request("This sign-in provider is not supported.")
            }
            FederationError::ProviderNotConfigured => {
                Self::bad_request("This sign-in provider is not configured.")
            }
            FederationError::InvalidReturnTo => {
                Self::bad_request("This return address is not allowed.")
            }
            FederationError::Unauthorized => Self::unauthorized(),
            FederationError::InvalidAttempt => Self::bad_request(
                "This sign-in attempt is invalid or has expired. Please start again.",
            ),
            FederationError::SessionChanged => {
                Self::forbidden("Your session changed. Please start linking this provider again.")
            }
            FederationError::IdentityAlreadyLinked => Self::forbidden(
                "This provider account is already linked to another Piquel account.",
            ),
            FederationError::PendingSignupExpired => {
                Self::bad_request("This signup has expired. Please start again.")
            }
            FederationError::PendingSignInExpired => {
                Self::bad_request("This sign-in attempt has expired. Please start again.")
            }
            FederationError::SignupRequiresLink => {
                Self::forbidden("Use a passkey for your existing account to link this provider.")
            }
            FederationError::FirstPasskeyRequired => {
                Self::forbidden("Create your first passkey before continuing.")
            }
            FederationError::EmailAlreadyOwned => Self::forbidden(
                "This email belongs to an existing account. Sign in with its passkey to link this provider.",
            ),
            FederationError::ManagementExpired => {
                Self::forbidden("Confirm with a passkey to change authentication settings.")
            }
            FederationError::LinkAccountMismatch => Self::forbidden(
                "Sign in with a passkey for the account this provider should be linked to.",
            ),
            FederationError::LinkRequiresPasskey => {
                Self::forbidden("A passkey is required to continue.")
            }
            FederationError::IdentityNotLinked => {
                Self::bad_request("This provider is not linked to your account.")
            }
            FederationError::Database(error) => error.into(),
            FederationError::Session(error) => error.into(),
            error @ (FederationError::Crypto(_)
            | FederationError::CookieHeader(_)
            | FederationError::Url(_)) => Self::internal(error),
        }
    }
}

/// Provider startup failures with operator-facing configuration context and sources.
#[derive(Debug, Error)]
pub enum FederationConfigError {
    /// A configured provider secret could not be loaded or decoded.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// The bounded HTTP client could not be initialized.
    #[error("could not initialize federation HTTP client")]
    Http(#[source] reqwest::Error),
}
