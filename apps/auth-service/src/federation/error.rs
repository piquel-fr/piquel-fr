//! Federation failures and their single mapping to browser responses.

use super::MAX_RETURN_TO_BYTES;
use crate::config::FrontendOrigins;
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
    /// `return_to` is neither a safe path on the auth origin nor a frontend URL.
    #[error(transparent)]
    InvalidReturnTo(#[from] InvalidReturnTo),
    /// The callback's browser lacks the cookie set when its flow started.
    #[error("federation flow cookie missing")]
    FlowBrowserMissing,
    /// The browser lacks the cookie binding its pending provider evidence.
    #[error("pending federation cookie missing")]
    PendingBrowserMissing,
    /// The account linked to the provider identity is inactive or has no active passkey.
    #[error("linked account is inactive or has no passkey")]
    LinkedAccountUnavailable,
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
            FederationError::InvalidReturnTo(error) => Self::bad_request(error.to_string()),
            FederationError::FlowBrowserMissing => Self::unauthorized(
                "This sign-in did not start in this browser, or it has expired. Please start again.",
            ),
            FederationError::PendingBrowserMissing => Self::unauthorized(
                "No provider sign-in is waiting in this browser. Please start again.",
            ),
            FederationError::LinkedAccountUnavailable => Self::unauthorized(
                "The Piquel account linked to this provider account is disabled or has no passkey.",
            ),
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

/// Why a `return_to` address is refused. Each message names the rule it breaks.
#[derive(Debug, Error)]
pub(crate) enum InvalidReturnTo {
    /// Anything that is neither a path nor a URL on a frontend origin.
    #[error("return_to must be a path on this site, starting with /, or a URL on {0}")]
    External(FrontendOrigins),
    /// A user name or password in the URL can disguise its real host.
    #[error("return_to cannot contain a user name or password")]
    Credentials,
    /// Browsers read a leading `//` as another host.
    #[error("return_to cannot start with //, which browsers read as another host")]
    ProtocolRelative,
    /// Browsers treat `\` like `/`, so it could also reach another host.
    #[error("return_to cannot contain a backslash")]
    Backslash,
    /// Fragments are not kept through the sign-in redirects.
    #[error("return_to cannot contain a # fragment")]
    Fragment,
    /// Control characters have no place in a URL path.
    #[error("return_to cannot contain control characters")]
    ControlCharacter,
    /// The path is longer than we store.
    #[error("return_to is {0} bytes; at most {MAX_RETURN_TO_BYTES} are allowed")]
    TooLong(usize),
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
    /// A provider's built-in endpoint is not a URL.
    #[error("a built-in provider endpoint is not a URL")]
    ProviderEndpoint(#[source] url::ParseError),
}
