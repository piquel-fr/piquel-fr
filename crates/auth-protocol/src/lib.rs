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

            /// Validates and wraps an existing UUID.
            ///
            /// # Errors
            ///
            /// Returns an error if the value is not `UUIDv7`.
            pub fn from_uuid(value: Uuid) -> Result<Self, InvalidValue> {
                if value.get_version_num() != 7 {
                    return Err(InvalidValue::new(stringify!($name)));
                }
                Ok(Self(value))
            }
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
}
