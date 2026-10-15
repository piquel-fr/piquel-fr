//! Validated names and the browser API's request and response bodies.

use super::PasskeyError;
use piquel_auth_protocol::{TokenId, UserId};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

/// Maximum Unicode characters in display names and credential labels.
const MAX_NAME_CHARS: usize = 80;
/// Smallest supported ASCII username.
const MIN_USERNAME_LEN: usize = 3;
/// Largest supported ASCII username.
const MAX_USERNAME_LEN: usize = 32;
/// Friendly name used when the browser omits a credential label.
const DEFAULT_PASSKEY_NAME: &str = "Passkey";

/// Declares a validated name type that keeps the browser's exact text.
/// Deserializing runs the same check, so stored ceremony state stays valid too.
macro_rules! validated_name {
    ($(#[$meta:meta])* $name:ident, $invalid:ident, $valid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub(super) struct $name(String);
        impl $name {
            /// Whether `value` satisfies this name's rule.
            fn is_valid(value: &str) -> bool {
                ($valid)(value)
            }
            /// Accepts `value` unchanged if it satisfies the rule.
            pub(super) fn parse(value: String) -> Result<Self, PasskeyError> {
                if Self::is_valid(&value) {
                    Ok(Self(value))
                } else {
                    Err(PasskeyError::$invalid)
                }
            }
            /// Borrows the validated text.
            pub(super) fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = PasskeyError;
            /// Validates names read back from stored ceremony state.
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }
        impl From<$name> for String {
            /// Unwraps the validated text for storage.
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

validated_name! {
    /// An account username: 3 to 32 lower-case ASCII letters, digits, `_` or `-`.
    Username, InvalidUsername, |value: &str| {
        (MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&value.len())
            && value.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
    }
}
validated_name! {
    /// A display name: not blank, no control characters, at most `MAX_NAME_CHARS` characters.
    DisplayName, InvalidDisplayName, |value: &str| {
        !value.trim().is_empty()
            && value.chars().count() <= MAX_NAME_CHARS
            && !value.chars().any(char::is_control)
    }
}
validated_name! {
    /// A passkey label, following the same rule as display names.
    PasskeyName, InvalidPasskeyName, DisplayName::is_valid
}

/// Registration authenticator selection, rather than a different authentication provider.
/// The Google variant exposes webauthn-rs's Android/GMS Core selection workaround;
/// both paths create ordinary passkeys verified by the same finish operation.
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PasskeyKind {
    /// Allows security keys and device unlock. Resident credentials are preferred,
    /// so account pickers work where supported while username-only keys remain usable.
    #[default]
    Standard,
    /// Requests a resident platform credential with a client-device hint and omits
    /// `credProtect`, which Android does not support. Only Android with GMS Core
    /// supports this library workaround; the browser must explicitly select it.
    GooglePasswordManager,
}

/// Optional authenticator selection when adding another passkey.
#[derive(Default, Deserialize)]
pub(super) struct EnrollmentStart {
    /// Defaults to the compatible standard registration path.
    #[serde(default)]
    pub(super) passkey_kind: PasskeyKind,
}

/// Signup input. Names stay plain strings so invalid ones get our 400 message, not a JSON rejection.
#[derive(Deserialize)]
pub(super) struct RegistrationStart {
    /// Requested authenticator selection.
    #[serde(default)]
    pub(super) passkey_kind: PasskeyKind,
    /// Account username, validated before starting `WebAuthn`.
    pub(super) username: String,
    /// Account display name; an empty value defaults to the username.
    #[serde(default)]
    pub(super) display_name: String,
    /// Invitation secret, required only when admission is gated.
    pub(super) invitation: Option<String>,
    /// Pending social signup to attach; sent only by the social signup page.
    pub(super) pending_signup: Option<TokenId>,
}

/// Browser credential response used for signup and additional enrollment.
#[derive(Deserialize)]
pub(super) struct RegistrationFinish {
    /// Server-side ceremony to consume exactly once.
    pub(super) ceremony_id: TokenId,
    /// Authenticator's registration response, never logged.
    pub(super) credential: RegisterPublicKeyCredential,
    /// Credential label; omission receives the default friendly name.
    #[serde(default = "RegistrationFinish::default_name")]
    pub(super) friendly_name: String,
}

impl RegistrationFinish {
    /// Label used when the browser sends none.
    fn default_name() -> String {
        DEFAULT_PASSKEY_NAME.into()
    }
}

/// Username-based login, or account-picker login when absent or empty.
#[derive(Deserialize)]
pub(super) struct LoginStart {
    /// Existing username; login deliberately does not apply signup validation.
    pub(super) username: Option<String>,
}

/// Browser assertion response for login and session confirmation.
#[derive(Deserialize)]
pub(super) struct AuthenticationFinish {
    /// Server-side ceremony to consume exactly once.
    pub(super) ceremony_id: TokenId,
    /// Authenticator's signed assertion, never logged.
    pub(super) credential: PublicKeyCredential,
}

/// New label for an existing credential.
#[derive(Deserialize)]
pub(super) struct Rename {
    /// Label validated before the rename transaction.
    pub(super) friendly_name: String,
}

/// Challenge and opaque ceremony identifier returned to the browser.
#[derive(Serialize)]
pub(super) struct CeremonyResponse {
    /// Opaque identifier of the stored ceremony.
    pub(super) ceremony_id: TokenId,
    /// `WebAuthn` options passed directly to the browser authenticator API.
    pub(super) public_key: serde_json::Value,
}

/// Public credential metadata, excluding the credential's cryptographic contents.
#[derive(Serialize)]
pub(super) struct PasskeyView {
    /// User-chosen credential label.
    pub(super) friendly_name: String,
    /// Credential row identifier used for rename and removal.
    pub(super) id: TokenId,
}

/// Account identity shown in the browser session view.
#[derive(Serialize)]
pub(super) struct UserView {
    /// User-chosen display name.
    pub(super) display_name: String,
    /// Immutable account identifier.
    pub(super) id: UserId,
    /// Account username.
    pub(super) username: String,
}

/// Signed-in account of the browser session.
#[derive(Serialize)]
pub(super) struct SessionView {
    /// Current account identity.
    pub(super) user: UserView,
}
