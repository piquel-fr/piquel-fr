//! Error codes every SDK shares, and the shape of the expected errors in
//! `tests/sdk-vectors`. Each SDK error exposes one
//! [`SdkError`](crate::protocol::sdk::SdkError), so every SDK reports a given failure with
//! the same code and reason.

use serde::{Deserialize, Serialize};

crate::str_enum! {
    /// What kind of operation failed.
    pub enum ErrorCategory {
        /// Fetching or checking the issuer's metadata.
        Discovery = "discovery",
        /// Fetching or parsing the issuer's signing keys.
        Keys = "keys",
        /// A token failed validation; the reason says which check.
        InvalidToken = "invalid_token",
        /// A valid token lacks a required scope.
        InsufficientScope = "insufficient_scope",
        /// A valid token's authentication is too weak or too old (RFC 9470).
        InsufficientUserAuthentication = "insufficient_user_authentication",
        /// An authorization response failed its checks before any code exchange.
        Callback = "callback",
        /// An auth endpoint answered with an OAuth error.
        OAuth = "oauth",
        /// Auth could not be reached, or answered with something other than its protocol.
        Network = "network",
    }
}

crate::str_enum! {
    /// Which check failed. One flat list, since several categories share a reason.
    pub enum ErrorReason {
        /// An issuer differs from the configured one: in metadata, `iss` or a callback.
        IssuerMismatch = "issuer_mismatch",
        /// A metadata document or key set does not parse.
        InvalidDocument = "invalid_document",
        /// The issuer does not support PKCE with `S256`.
        PkceUnsupported = "pkce_unsupported",
        /// Two keys in one set share a `kid`.
        DuplicateKeyId = "duplicate_key_id",
        /// The token is not a compact JWS, or a segment does not decode.
        Malformed = "malformed",
        /// The header lists `crit` extensions, which the SDKs do not support
        /// (RFC 7515 §4.1.11).
        UnsupportedCriticalHeader = "unsupported_critical_header",
        /// The `typ` header is not the one expected for this kind of token.
        WrongType = "wrong_type",
        /// `alg` is not both advertised by the issuer and allowed by the SDK.
        UnsupportedAlgorithm = "unsupported_algorithm",
        /// No key matches `kid`, even after a refetch.
        UnknownKey = "unknown_key",
        /// The signature does not verify.
        BadSignature = "bad_signature",
        /// `aud` does not contain the expected value, or an ID token's `aud` names
        /// another client too.
        WrongAudience = "wrong_audience",
        /// `exp` has passed, beyond the leeway.
        Expired = "expired",
        /// `nbf` is in the future, beyond the leeway.
        NotYetValid = "not_yet_valid",
        /// `iat` is in the future, beyond the leeway.
        IssuedInFuture = "issued_in_future",
        /// A logout token's `exp` is more than 10 minutes after its `iat`.
        LifetimeTooLong = "lifetime_too_long",
        /// A required claim is missing or has the wrong type.
        InvalidClaims = "invalid_claims",
        /// An ID token's `nonce` differs from the pending login's.
        NonceMismatch = "nonce_mismatch",
        /// An ID token's `azp` names another client.
        WrongAuthorizedParty = "wrong_authorized_party",
        /// `auth_time` is missing or older than the requested `max_age`.
        AuthenticationTooOld = "authentication_too_old",
        /// A callback's `state` differs from the pending login's.
        StateMismatch = "state_mismatch",
        /// A callback has no `iss` although the issuer advertises it (RFC 9207 §2.4).
        MissingIssuer = "missing_issuer",
        /// A successful callback has no `code`.
        MissingCode = "missing_code",
    }
}

/// The shared code of an SDK error: a category, and for most categories the check
/// that failed. It serializes as the vectors' expected errors do:
///
/// ```
/// use piquel_common::protocol::sdk::{ErrorCategory, ErrorReason, SdkError};
///
/// let expired = SdkError::new(ErrorCategory::InvalidToken, ErrorReason::Expired);
/// assert_eq!(
///     serde_json::to_string(&expired)?,
///     r#"{"code":"invalid_token","reason":"expired"}"#
/// );
/// let unreachable = SdkError::category(ErrorCategory::Network);
/// assert_eq!(serde_json::to_string(&unreachable)?, r#"{"code":"network"}"#);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkError {
    /// What kind of operation failed.
    pub code: ErrorCategory,
    /// Which check failed, when the category has several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<ErrorReason>,
}

impl SdkError {
    /// An error in `code` caused by `reason`.
    #[must_use]
    pub const fn new(code: ErrorCategory, reason: ErrorReason) -> Self {
        Self {
            code,
            reason: Some(reason),
        }
    }

    /// An error in `code` with no finer reason.
    #[must_use]
    pub const fn category(code: ErrorCategory) -> Self {
        Self { code, reason: None }
    }
}
