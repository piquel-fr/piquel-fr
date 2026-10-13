//! Passkey failures and their single conversion boundary to browser responses.

use super::ApiError;
use crate::security::SessionError;
use piquel_auth_protocol::InvalidValue;
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;
use webauthn_rs::prelude::WebauthnError;

/// Failures while validating, persisting or completing a passkey operation.
#[derive(Debug, thiserror::Error)]
pub(super) enum PasskeyError {
    /// The signup username violates the account naming rules.
    #[error("invalid username")]
    InvalidUsername,
    /// The account's displayed name is blank, too long or contains controls.
    #[error("invalid display name")]
    InvalidDisplayName,
    /// The credential label is blank, too long or contains controls.
    #[error("invalid passkey name")]
    InvalidPasskeyName,
    /// An invitation-gated registration has no valid invitation secret.
    #[error("registration invitation required")]
    InvitationRequired,
    /// The registration started before invitations became required, so it carries none.
    #[error("registration finish invitation missing")]
    InvitationMissingAtFinish,
    /// The invitation expired or another registration already redeemed it.
    #[error("registration invitation expired or used")]
    InvitationExpired,
    /// The browser lacks the cookie that binds its ceremony.
    #[error("ceremony browser cookie missing")]
    CeremonyBrowserMissing,
    /// The presented browser cookie does not own this ceremony.
    #[error("ceremony browser mismatch")]
    BrowserMismatch,
    /// The stored ceremony payload does not match its expected purpose.
    #[error("wrong ceremony payload")]
    WrongCeremony,
    /// The management or enrollment proof belongs to another session.
    #[error("ceremony session changed")]
    SessionChanged,
    /// The Google-only registration workaround was selected outside Android.
    #[error("Google Password Manager registration requires Android")]
    GooglePasswordManagerRequiresAndroid,
    /// `WebAuthn` rejected the challenge, credential or authenticator options.
    #[error("WebAuthn operation rejected")]
    Webauthn(#[from] WebauthnError),
    /// A discoverable credential returned an invalid account handle.
    #[error("invalid discoverable account handle")]
    InvalidUserHandle(#[source] InvalidValue),
    /// Username-based authentication must not reveal account availability.
    #[error("account unavailable for passkey authentication")]
    AccountUnavailable,
    /// The account, or the credential it signed with, was disabled or removed.
    #[error("active account and credential required")]
    AccountInactive,
    /// The authenticator did not verify the person using it.
    #[error("passkey user verification required")]
    UserVerificationRequired,
    /// The latest stored signature counter is absent or malformed.
    #[error("stored passkey counter is missing")]
    MissingCounter,
    /// A counter-capable authenticator reused or decreased its counter.
    #[error("passkey signature counter did not increase")]
    CounterRegression,
    /// The verified credential does not match the stored passkey.
    #[error("verified passkey credential mismatch")]
    CredentialMismatch,
    /// The credential was revoked before its authentication update.
    #[error("passkey credential revoked")]
    CredentialRevoked,
    /// Removal failed because the key is absent or no other passkey remains.
    #[error("cannot remove the last or an unavailable passkey")]
    LastPasskey,
    /// Renaming found no active passkey owned by the account.
    #[error("passkey not found")]
    PasskeyNotFound,
    /// Settings authorization expired before the transaction acquired its lock.
    #[error("passkey management window expired")]
    ManagementExpired,
    /// A persisted credential cannot be decoded.
    #[error("stored passkey credential is corrupt")]
    StoredCredential(#[source] serde_json::Error),
    /// A persisted ceremony cannot be decoded.
    #[error("stored passkey ceremony is corrupt")]
    StoredCeremony(#[source] serde_json::Error),
    /// `WebAuthn` state cannot be encoded for persistence.
    #[error("could not serialize passkey state")]
    Serialization(#[source] serde_json::Error),
    /// A generated cookie cannot be represented as an HTTP header.
    #[error("could not encode passkey cookie header")]
    CookieHeader(#[from] axum::http::header::InvalidHeaderValue),
    /// Passkey persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// Creating a browser session failed.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// Generating a browser-binding secret failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<PasskeyError> for ApiError {
    /// Maps each failure to its browser status and message; internal details stay in the logs.
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::InvalidUsername => Self::bad_request(
                "Use 3–32 lowercase letters, numbers, underscores or hyphens for your username.",
            ),
            PasskeyError::InvalidDisplayName => {
                Self::bad_request("Choose a display name of at most 80 characters.")
            }
            PasskeyError::InvalidPasskeyName => {
                Self::bad_request("Choose a passkey name of at most 80 characters.")
            }
            PasskeyError::InvitationRequired => Self::forbidden("A valid invitation is required."),
            PasskeyError::InvitationMissingAtFinish => Self::forbidden("Invitation required."),
            PasskeyError::InvitationExpired => {
                Self::forbidden("This invitation has expired or has already been used.")
            }
            PasskeyError::CeremonyBrowserMissing => {
                Self::bad_request("Please restart the passkey flow in this browser.")
            }
            PasskeyError::GooglePasswordManagerRequiresAndroid => Self::bad_request(
                "Choose Google Password Manager only on an Android device with Google services.",
            ),
            PasskeyError::AccountInactive => Self::unauthorized("Sign in to continue."),
            PasskeyError::ManagementExpired => {
                Self::forbidden("Your management window expired. Confirm with a passkey again.")
            }
            PasskeyError::PasskeyNotFound => Self::bad_request("Passkey not found."),
            PasskeyError::LastPasskey => {
                Self::bad_request("Keep at least one passkey on your account.")
            }
            error @ (PasskeyError::BrowserMismatch
            | PasskeyError::WrongCeremony
            | PasskeyError::SessionChanged
            | PasskeyError::Webauthn(_)
            | PasskeyError::InvalidUserHandle(_)
            | PasskeyError::AccountUnavailable
            | PasskeyError::UserVerificationRequired
            | PasskeyError::CounterRegression
            | PasskeyError::CredentialMismatch
            | PasskeyError::CredentialRevoked) => {
                // Display contains only the rejection reason, never challenges or credentials.
                tracing::debug!(error = %piquel_common::ErrorChain(&error), "WebAuthn request rejected");
                Self::bad_request("Passkey verification failed. Please try again.")
            }
            PasskeyError::Database(error) => error.into(),
            PasskeyError::Session(error) => error.into(),
            error @ (PasskeyError::MissingCounter
            | PasskeyError::StoredCredential(_)
            | PasskeyError::StoredCeremony(_)
            | PasskeyError::Serialization(_)
            | PasskeyError::CookieHeader(_)
            | PasskeyError::Crypto(_)) => Self::internal(error),
        }
    }
}

/// Failure to initialize `WebAuthn` from validated configuration.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyConfigError {
    /// `WebAuthn` rejected its validated configuration.
    #[error("WebAuthn initialization failed")]
    Webauthn(#[from] WebauthnError),
}
