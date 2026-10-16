//! Stable, framework-independent values shared by authentication participants: auth
//! itself, its first-party apps and the SDKs. Auth issues tokens and documents by
//! serializing these types, and the SDKs read them back with the same types.

/// `WWW-Authenticate: Bearer` challenges sent by resource servers.
pub mod challenge;
/// Access token, ID token and `UserInfo` claims.
pub mod claims;
/// JWT claim and JOSE field vocabulary shared by token issuers and verifiers.
pub mod jwt;
/// Authorization server metadata, as published at both well-known discovery paths.
pub mod metadata;
/// OAuth and OpenID Connect vocabulary shared by clients and the provider.
pub mod oauth;
/// Error codes shared by the SDKs and their test vectors.
pub mod sdk;

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

piquel_common::str_enum! {
    /// Supported external authentication providers.
    pub enum Provider {
        /// GitHub OAuth identity.
        GitHub = "github",
        /// Google `OpenID` Connect identity.
        Google = "google",
    }
}

/// An invalid protocol value received at a trust boundary.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("invalid {kind}")]
pub struct InvalidValue {
    /// Protocol type whose contract was violated.
    kind: &'static str,
    /// UUID parser diagnostic, absent for canonical-format or version failures.
    #[source]
    source: Option<uuid::Error>,
}

impl InvalidValue {
    /// Reports a semantic contract violation without an underlying parser failure.
    const fn new(kind: &'static str) -> Self {
        Self { kind, source: None }
    }
    /// Retains syntax diagnostics when a protocol identifier cannot be decoded.
    fn parse(kind: &'static str, source: uuid::Error) -> Self {
        Self {
            kind,
            source: Some(source),
        }
    }
}

/// Declares canonical `UUIDv7` identifiers with consistent parsing, serde and conversions,
/// plus `SQLx` decoding when the `sqlx` feature is on.
macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(Uuid);

        impl Default for $name {
            /// Creates a fresh `UUIDv7` identifier rather than a sentinel value.
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
            /// Exposes the UUID for typed persistence without re-parsing a string.
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
            /// Formats the identifier as its canonical lower-case UUID string.
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
        impl FromStr for $name {
            type Err = InvalidValue;
            /// Parses and validates the type at its text boundary, retaining syntax diagnostics.
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let parsed = Uuid::parse_str(value)
                    .map_err(|source| InvalidValue::parse(stringify!($name), source))?;
                if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
                    return Err(InvalidValue::new(stringify!($name)));
                }
                Ok(Self(parsed))
            }
        }
        impl TryFrom<String> for $name {
            type Error = InvalidValue;
            /// Parses the canonical identifier from owned text.
            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }
        impl From<$name> for String {
            /// Encodes the identifier using its canonical lower-case UUID representation.
            fn from(value: $name) -> Self {
                value.to_string()
            }
        }
        #[cfg(feature = "sqlx")]
        impl sqlx::Type<sqlx::Postgres> for $name {
            /// Stored as `UUID`.
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                <Uuid as sqlx::Type<sqlx::Postgres>>::type_info()
            }
        }
        #[cfg(feature = "sqlx")]
        impl<'r> sqlx::Decode<'r, sqlx::Postgres> for $name {
            /// Decodes a `UUID` column, rejecting values that are not `UUIDv7`.
            fn decode(
                value: sqlx::postgres::PgValueRef<'r>,
            ) -> Result<Self, sqlx::error::BoxDynError> {
                Ok(Self::from_uuid(<Uuid as sqlx::Decode<
                    'r,
                    sqlx::Postgres,
                >>::decode(value)?)?)
            }
        }
    };
}

uuid_id!(UserId, "Immutable global Piquel account identifier.");
uuid_id!(SessionId, "Opaque central-session identifier.");
uuid_id!(TokenId, "Identifier for a token record or JWT.");

/// A registered OAuth client's identifier. Chosen by whoever registers the client,
/// so any non-empty string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientId(String);

impl ClientId {
    /// Wraps a client identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    /// The identifier as sent on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    /// Writes the identifier unchanged.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

piquel_common::str_enum! {
    /// Account availability state in SQL and JSON.
    pub enum AccountStatus {
        /// The account can authenticate.
        Active = "active",
        /// The account is administratively unavailable.
        Disabled = "disabled",
    }
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
    //! Protocol identifier syntax and storage contracts.
    use super::*;

    /// IDs accept only canonical `UUIDv7`, preserving syntax diagnostics on malformed text.
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
        let error = "not-a-uuid".parse::<UserId>().expect_err("UUID syntax");
        assert!(std::error::Error::source(&error).is_some());
    }
}
