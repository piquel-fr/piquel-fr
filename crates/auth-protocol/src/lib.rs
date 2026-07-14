//! Stable, framework-independent values shared by authentication participants.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

/// An invalid protocol value received at a trust boundary.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("invalid {kind}")]
pub struct InvalidValue {
    kind: &'static str,
}

impl InvalidValue {
    const fn new(kind: &'static str) -> Self {
        Self { kind }
    }
}

macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(Uuid);

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Generates a `UUIDv7` value.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            /// Returns the canonical lower-case UUID string.
            #[must_use]
            pub fn as_uuid(self) -> Uuid {
                self.0
            }
<<<<<<< HEAD

            /// Validates and wraps an existing UUID.
            ///
            /// # Errors
            ///
            /// Returns an error unless the value is `UUIDv7`.
            pub fn from_uuid(value: Uuid) -> Result<Self, InvalidValue> {
                if value.get_version_num() != 7 {
                    return Err(InvalidValue::new(stringify!($name)));
                }
                Ok(Self(value))
            }
=======
>>>>>>> main
        }
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
        impl FromStr for $name {
            type Err = InvalidValue;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let parsed =
                    Uuid::parse_str(value).map_err(|_| InvalidValue::new(stringify!($name)))?;
                if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
                    return Err(InvalidValue::new(stringify!($name)));
                }
                Ok(Self(parsed))
            }
        }
        impl TryFrom<String> for $name {
            type Error = InvalidValue;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.to_string()
            }
        }
    };
}

uuid_id!(UserId, "Immutable global Piquel account identifier.");
uuid_id!(SessionId, "Opaque central-session identifier.");
uuid_id!(TokenId, "Identifier for a token record or JWT.");

macro_rules! text_id {
    ($name:ident, $doc:literal, $kind:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            /// Returns the validated wire representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl FromStr for $name {
            type Err = InvalidValue;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.is_empty()
                    || value.len() > 128
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                    })
                {
                    return Err(InvalidValue::new($kind));
                }
                Ok(Self(value.to_owned()))
            }
        }
        impl TryFrom<String> for $name {
            type Error = InvalidValue;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

text_id!(ClientId, "Registered OAuth client identifier.", "client_id");
text_id!(Audience, "Exact resource-server audience.", "audience");
text_id!(
    ServiceId,
    "Registered internal service identifier.",
    "service_id"
);

/// Account availability state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// The account can authenticate.
    Active,
    /// The account is administratively unavailable.
    Disabled,
}

/// Authentication method recorded on a session or token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    /// A `WebAuthn` passkey authenticated the user.
    Passkey,
    /// An approved external identity provider authenticated the user.
    Federation,
    /// An existing central session continued the authentication.
    Session,
}

/// Shared fields in a resource-server access token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Issuing authority URL.
    pub iss: String,
    /// Immutable account subject.
    pub sub: UserId,
    /// Exact intended resource audience.
    pub aud: Audience,
    /// Session that authenticated the subject.
    pub sid: SessionId,
    /// Unique token identifier.
    pub jti: TokenId,
    /// Expiry timestamp in Unix seconds.
    pub exp: i64,
    /// Issued-at timestamp in Unix seconds.
    pub iat: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_canonical_uuid_v7() {
        let id = UserId::new();
        assert_eq!(id.to_string().parse::<UserId>(), Ok(id));
        assert!(
            "00000000-0000-4000-8000-000000000000"
                .parse::<UserId>()
                .is_err()
        );
        assert!(id.to_string().to_uppercase().parse::<UserId>().is_err());
    }

    #[test]
    fn text_identifiers_reject_wire_ambiguity() {
        assert!("product-api".parse::<Audience>().is_ok());
        assert!("product api".parse::<Audience>().is_err());
        assert!("".parse::<ClientId>().is_err());
    }
}
