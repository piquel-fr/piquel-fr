//! The vocabulary shared across Piquel: identifiers, string vocabularies, the auth
//! protocol's wire types and, behind features, what only servers need.
//!
//! With no features, this crate is what the SDKs build on: identifiers such as
//! [`UserId`], the [`protocol`] documents, the [`clients`] registration types and
//! the vocabulary macros. Servers add:
//!
//! - `config`: environment variables, validated URLs and secret references.
//! - `events`: the domain events auth records.
//! - `sqlx`: decoding identifiers and vocabularies from `PostgreSQL` columns.

/// OAuth client registrations, each field validated by its type.
pub mod clients;
/// Environment variables, validated URLs and secret references.
#[cfg(feature = "config")]
pub mod config;
/// Typed domain events: what changed in an account, and who changed it.
#[cfg(feature = "events")]
pub mod events;
/// The auth protocol's wire documents, shared by auth and the SDKs.
pub mod protocol;

use serde::{Deserialize, Serialize};
use std::{error::Error as StdError, fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

pub use clients::ClientId;

/// Formats an error followed by each of its causes, e.g.
/// `AUTH_PUBLIC_BASE_URL is invalid: must use https://`.
pub struct ErrorChain<'a>(pub &'a (dyn StdError + 'a));
impl fmt::Display for ErrorChain<'_> {
    /// Writes the error, then every `source()` separated by `: `.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(cause) = source {
            write!(f, ": {cause}")?;
            source = cause.source();
        }
        Ok(())
    }
}

/// A string outside a named, closed vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown {vocabulary} value")]
pub struct VocabularyError {
    /// Name of the vocabulary; the supplied value is omitted.
    pub vocabulary: &'static str,
}

/// Serde paths used by exported macros, independent of downstream dependencies.
#[doc(hidden)]
pub use serde as __serde;
/// `SQLx` paths used by exported macros when the `sqlx` feature is on.
#[cfg(feature = "sqlx")]
#[doc(hidden)]
pub use sqlx as __sqlx;

/// Lets `str_enum!` vocabularies and other validated text types decode from
/// `PostgreSQL` text columns through `FromStr`, e.g. `status AS "status: AccountStatus"`
/// in a checked query. A value the type rejects fails decoding. This crate's `sqlx` feature selects which
/// definition every `str_enum!` expands to, wherever it is invoked.
#[cfg(feature = "sqlx")]
#[doc(hidden)]
#[macro_export]
macro_rules! __str_enum_sqlx {
    ($name:ident) => {
        impl $crate::__sqlx::Type<$crate::__sqlx::Postgres> for $name {
            /// Stored as `TEXT`.
            fn type_info() -> $crate::__sqlx::postgres::PgTypeInfo {
                <str as $crate::__sqlx::Type<$crate::__sqlx::Postgres>>::type_info()
            }
            /// Accepts every text-like column, as `str` does.
            fn compatible(ty: &$crate::__sqlx::postgres::PgTypeInfo) -> bool {
                <str as $crate::__sqlx::Type<$crate::__sqlx::Postgres>>::compatible(ty)
            }
        }
        impl<'r> $crate::__sqlx::Decode<'r, $crate::__sqlx::Postgres> for $name {
            /// Parses the stored spelling, rejecting values outside the vocabulary.
            fn decode(
                value: $crate::__sqlx::postgres::PgValueRef<'r>,
            ) -> Result<Self, $crate::__sqlx::error::BoxDynError> {
                Ok(
                    <&str as $crate::__sqlx::Decode<'r, $crate::__sqlx::Postgres>>::decode(value)?
                        .parse()?,
                )
            }
        }
    };
}

/// Without the `sqlx` feature, vocabularies carry no database impls.
#[cfg(not(feature = "sqlx"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __str_enum_sqlx {
    ($name:ident) => {};
}

/// Declares a documented, closed string vocabulary with serde and parsing support,
/// plus `SQLx` text decoding when the `sqlx` feature is on. Unknown spellings are
/// rejected, unless an `else` variant follows the enum: then they read as it, for
/// labels a newer release may extend that older ones can show coarsely.
///
/// ```
/// piquel_common::str_enum! {
///     /// A coarse label.
///     pub enum Shade {
///         /// Light.
///         Light = "light",
///         /// Anything else.
///         Other = "other",
///     } else Other
/// }
///
/// assert_eq!("teal".parse(), Ok(Shade::Other));
/// ```
#[macro_export]
macro_rules! str_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($(#[$variant_meta:meta])* $variant:ident = $value:literal),+ $(,)? } $(else $fallback:ident)?) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name { $($(#[$variant_meta])* $variant),+ }
        impl $name {
            /// Every vocabulary value in declaration order.
            pub const ALL: [Self; $crate::str_enum!(@count $($variant),+)] = [$(Self::$variant),+];
            /// Returns the stable storage and wire value.
            #[must_use]
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $value),+ } }
        }
        impl ::std::fmt::Display for $name {
            /// Formats the stable vocabulary spelling.
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result { f.write_str(self.as_str()) }
        }
        impl ::std::str::FromStr for $name {
            type Err = $crate::VocabularyError;
            /// Parses the stable spelling; an unknown one is rejected or reads as the `else` variant.
            fn from_str(value: &str) -> Result<Self, Self::Err> { match value { $($value => Ok(Self::$variant),)+ _ => $crate::str_enum!(@unknown $name $($fallback)?) } }
        }
        impl $crate::__serde::Serialize for $name {
            /// Writes the stable vocabulary spelling to its wire representation.
            fn serialize<S: $crate::__serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) }
        }
        impl<'de> $crate::__serde::Deserialize<'de> for $name {
            /// Parses the wire spelling as `FromStr` does.
            fn deserialize<D: $crate::__serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = <String as $crate::__serde::Deserialize>::deserialize(deserializer)?;
                value.parse().map_err($crate::__serde::de::Error::custom)
            }
        }
        $crate::__str_enum_sqlx!($name);
    };
    (@unknown $name:ident) => { Err($crate::VocabularyError { vocabulary: stringify!($name) }) };
    (@unknown $name:ident $fallback:ident) => { Ok(Self::$fallback) };
    (@count $($variant:ident),+) => { <[()]>::len(&[$($crate::str_enum!(@unit $variant)),+]) };
    (@unit $variant:ident) => { () };
}

/// Declares an open string vocabulary for values a newer peer may extend, such as
/// `amr` or `acr`. Known spellings parse to their variant; anything else is kept
/// verbatim in `Other` instead of failing. Build values with `From<&str>` or
/// `parse`, never `Other` directly, so a known spelling cannot hide in `Other`.
///
/// ```
/// piquel_common::open_str_enum! {
///     /// How a user authenticated.
///     pub enum Method {
///         /// A passkey.
///         Passkey = "passkey",
///     }
/// }
///
/// assert_eq!(Method::from("passkey"), Method::Passkey);
/// // A value a newer peer sends is kept, not rejected.
/// let newer: Method = serde_json::from_str(r#""face""#).unwrap();
/// assert_eq!(newer, Method::Other("face".into()));
/// assert_eq!(newer.as_str(), "face");
/// assert_eq!(Method::KNOWN, [Method::Passkey]);
/// ```
#[macro_export]
macro_rules! open_str_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($(#[$variant_meta:meta])* $variant:ident = $value:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name {
            $($(#[$variant_meta])* $variant,)+
            /// A value this version does not know, kept verbatim.
            Other(String),
        }
        impl $name {
            /// Every known value in declaration order.
            pub const KNOWN: [Self; $crate::str_enum!(@count $($variant),+)] = [$(Self::$variant),+];
            /// Returns the wire spelling.
            #[must_use]
            pub fn as_str(&self) -> &str { match self { $(Self::$variant => $value,)+ Self::Other(value) => value } }
        }
        impl From<&str> for $name {
            /// Maps a known spelling to its variant and keeps any other value in `Other`.
            fn from(value: &str) -> Self { match value { $($value => Self::$variant,)+ other => Self::Other(other.to_owned()) } }
        }
        impl ::std::str::FromStr for $name {
            type Err = ::std::convert::Infallible;
            /// Never fails: unknown values parse to `Other`.
            fn from_str(value: &str) -> Result<Self, Self::Err> { Ok(Self::from(value)) }
        }
        impl ::std::fmt::Display for $name {
            /// Formats the wire spelling.
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result { f.write_str(self.as_str()) }
        }
        impl $crate::__serde::Serialize for $name {
            /// Writes the wire spelling.
            fn serialize<S: $crate::__serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) }
        }
        impl<'de> $crate::__serde::Deserialize<'de> for $name {
            /// Reads any string, keeping unknown values in `Other`.
            fn deserialize<D: $crate::__serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = <::std::borrow::Cow<'de, str> as $crate::__serde::Deserialize>::deserialize(deserializer)?;
                Ok(Self::from(value.as_ref()))
            }
        }
    };
}

/// A value that identifies a person outside Piquel, such as a provider's subject
/// identifier or a client IP. Storage keeps it apart from the record holding it, so
/// it can be deleted on its own; it then reads back as [`Self::Erased`].
///
/// It serializes as `{"$personal": value}`, or `"$erased"` once deleted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Personal<T> {
    /// The value, while it is kept.
    #[serde(rename = "$personal")]
    Value(T),
    /// The value was deleted or never recorded.
    #[serde(rename = "$erased")]
    Erased,
}

str_enum! {
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
uuid_id!(PasskeyId, "Identifier of a stored passkey credential.");
uuid_id!(EventId, "Identifier of a recorded domain event.");
uuid_id!(
    ClientSecretId,
    "Identifier of one of an OAuth client's secrets."
);
uuid_id!(
    DeliveryId,
    "Identifier of an outbound delivery, reused by every attempt as its `jti` or `Message-ID`."
);

str_enum! {
    /// Account availability state in SQL and JSON.
    pub enum AccountStatus {
        /// The account can authenticate.
        Active = "active",
        /// The account is administratively unavailable.
        Disabled = "disabled",
        /// The account is scheduled for deletion. It cannot sign in, but a passkey
        /// can restore it until its grace period ends and it is purged.
        Deleting = "deleting",
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

impl AuthenticationMethod {
    /// The `amr` values (RFC 8176) this method stands for. A passkey requires user
    /// verification, so it proves possession and the user's presence: two factors.
    #[must_use]
    pub const fn amr(self) -> &'static [protocol::claims::Amr] {
        match self {
            Self::Passkey => &[
                protocol::claims::Amr::Pop,
                protocol::claims::Amr::Mfa,
                protocol::claims::Amr::User,
            ],
            Self::Federation => &[protocol::claims::Amr::Fed],
        }
    }
}

/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
