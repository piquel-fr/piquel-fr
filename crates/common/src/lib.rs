//! Shared environment variables, validated URLs, secret references and string vocabularies.

use std::{env, error::Error as StdError, fmt, fs, path::PathBuf, str::FromStr};
use thiserror::Error;
use url::Url;

/// An operator-facing configuration error; supplied values are never displayed.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// A required variable is absent.
    #[error("{variable} is required")]
    Missing {
        /// Variable to set.
        variable: &'static str,
    },
    /// A value violates its contract, e.g. `AUTH_CLIENTS_FILE must contain unique client IDs`.
    #[error("{variable} {reason}")]
    Invalid {
        /// Variable to correct.
        variable: &'static str,
        /// What the value must look like, without the supplied value.
        reason: &'static str,
        /// The underlying parse or resolution failure, when there is one.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
    /// Resolved secret bytes are not text.
    #[error("secret must contain UTF-8 text")]
    Utf8(#[from] std::str::Utf8Error),
}

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

/// A named environment variable, declared once beside its configuration section.
#[derive(Clone, Copy, Debug)]
pub struct Variable(&'static str);
impl Variable {
    /// Names an environment variable without reading it.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }
    /// Returns the name for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.0
    }
    /// Rejects the value with `reason`, which says what the operator must change.
    #[must_use]
    pub const fn invalid(self, reason: &'static str) -> ConfigurationError {
        ConfigurationError::Invalid {
            variable: self.0,
            reason,
            source: None,
        }
    }
    /// Like [`Self::invalid`], keeping the underlying failure as the error's source.
    pub fn error(
        self,
        reason: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> ConfigurationError {
        ConfigurationError::Invalid {
            variable: self.0,
            reason,
            source: Some(Box::new(source)),
        }
    }
    /// Reads an optional UTF-8 setting.
    ///
    /// # Errors
    /// Returns an error for non-Unicode environment values, without exposing them.
    pub fn optional(self) -> Result<Option<String>, ConfigurationError> {
        match env::var(self.0) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            // VarError::NotUnicode contains the value, so it must not enter diagnostics.
            Err(env::VarError::NotUnicode(_)) => Err(self.invalid("must contain UTF-8 text")),
        }
    }
    /// Reads a required setting.
    ///
    /// # Errors
    /// Returns an error when absent or non-Unicode.
    pub fn required(self) -> Result<String, ConfigurationError> {
        self.optional()?
            .ok_or(ConfigurationError::Missing { variable: self.0 })
    }
    /// Reads an exact `true` or `false`, using `default` when absent.
    ///
    /// # Errors
    /// Returns an error for any other value.
    pub fn flag(self, default: bool) -> Result<bool, ConfigurationError> {
        match self.optional()?.as_deref() {
            None => Ok(default),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(_) => Err(self.invalid("must be true or false")),
        }
    }
    /// Parses a required setting into its validated type.
    ///
    /// # Errors
    /// Preserves the parsing failure and names the variable.
    pub fn parse<T: FromStr>(self) -> Result<T, ConfigurationError>
    where
        T::Err: StdError + Send + Sync + 'static,
    {
        self.required()?
            .parse()
            .map_err(|source| self.error("is invalid", source))
    }
    /// Parses an optional setting, falling back to `default` when it is absent.
    ///
    /// # Errors
    /// Preserves the parsing failure and names the variable.
    pub fn parse_or<T: FromStr>(self, default: &str) -> Result<T, ConfigurationError>
    where
        T::Err: StdError + Send + Sync + 'static,
    {
        self.optional()?
            .as_deref()
            .unwrap_or(default)
            .parse()
            .map_err(|source| self.error("is invalid", source))
    }
}

/// Why a configured URL was rejected. Each message tells the operator what to change.
#[derive(Debug, Error)]
pub enum UrlError {
    /// The value is not an absolute URL.
    #[error("must be an absolute URL, e.g. https://piquel.fr/settings")]
    Malformed(#[source] url::ParseError),
    /// Only HTTPS is accepted; every environment is served over TLS.
    #[error("must use https://")]
    NotHttps,
    /// The URL has no host.
    #[error("must include a host name")]
    MissingHost,
    /// Credentials in a URL would leak into logs and redirects.
    #[error("must not contain a user name or password")]
    Credentials,
    /// Queries and fragments are not part of a base URL.
    #[error("must not contain a query or fragment")]
    QueryOrFragment,
    /// An origin cannot carry a path.
    #[error("must be an origin without a path, e.g. https://auth.piquel.fr")]
    Path,
}

/// An absolute HTTPS URL without credentials, query or fragment.
#[derive(Clone, Debug)]
pub struct PublicUrl(Url);
impl PublicUrl {
    /// Exposes the validated URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }
}
impl FromStr for PublicUrl {
    type Err = UrlError;
    /// Accepts an absolute HTTPS URL, optionally with a path.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(value).map_err(UrlError::Malformed)?;
        if url.scheme() != "https" {
            return Err(UrlError::NotHttps);
        }
        if url.host_str().is_none() {
            return Err(UrlError::MissingHost);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(UrlError::Credentials);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(UrlError::QueryOrFragment);
        }
        Ok(Self(url))
    }
}

/// An HTTPS origin such as `https://auth.piquel.fr`, validated once at startup.
#[derive(Clone, Debug)]
pub struct Origin {
    /// The origin as a URL, always with the root path.
    url: Url,
    /// Host name, kept separately because parsing guarantees it exists.
    host: String,
}
impl Origin {
    /// Exposes the validated URL, whose path is always `/`.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.url
    }
    /// The origin's host name, e.g. `auth.piquel.fr`.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    /// The origin without its trailing slash, as used in `Origin` headers and OIDC issuers.
    #[must_use]
    pub fn serialized(&self) -> String {
        self.url.origin().ascii_serialization()
    }
    /// The absolute URL of `path`, which must start with `/`, on this origin.
    #[must_use]
    pub fn url(&self, path: &str) -> Url {
        let mut url = self.url.clone();
        url.set_path(path);
        url
    }
    /// Like [`Self::url`], as text.
    #[must_use]
    pub fn join(&self, path: &str) -> String {
        self.url(path).into()
    }
}
impl FromStr for Origin {
    type Err = UrlError;
    /// Accepts an HTTPS origin without path, credentials, query or fragment.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let PublicUrl(url) = value.parse()?;
        if url.path() != "/" {
            return Err(UrlError::Path);
        }
        let host = url.host_str().ok_or(UrlError::MissingHost)?.to_owned();
        Ok(Self { url, host })
    }
}

/// Why a secret reference could not be parsed or resolved. Messages never contain
/// the reference or the secret.
#[derive(Debug, Error)]
pub enum SecretError {
    /// The reference is not `env://NAME` or `file://PATH`.
    #[error("secret reference is not env://NAME or file://PATH")]
    Malformed,
    /// The referenced environment variable is not set.
    #[error("secret environment variable is not set")]
    MissingVariable,
    /// The referenced environment variable is not UTF-8. The rejected value is the
    /// secret itself, so it is dropped instead of kept as a source.
    #[error("secret environment variable must contain UTF-8 text")]
    NotUnicode,
    /// The referenced file could not be read.
    #[error("could not read the secret file")]
    Unreadable(#[source] std::io::Error),
    /// The secret resolved to zero bytes.
    #[error("secret must not be empty")]
    Empty,
}

/// A validated `env://NAME` or `file://PATH` secret locator, redacted in diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretReference(SecretLocation);

/// Where a [`SecretReference`] points, kept private so every value is validated.
#[derive(Clone, PartialEq, Eq)]
enum SecretLocation {
    /// Name of the process variable holding the secret.
    Environment(String),
    /// Path of the mounted secret file.
    File(PathBuf),
}
impl SecretReference {
    /// Prefix of environment variable references.
    const ENVIRONMENT_PREFIX: &str = "env://";
    /// Prefix of mounted file references.
    const FILE_PREFIX: &str = "file://";

    /// Parses an `env://NAME` or `file://PATH` secret locator.
    ///
    /// # Errors
    /// Rejects unsupported, empty or whitespace-containing references.
    pub fn parse(value: &str) -> Result<Self, SecretError> {
        value.parse()
    }
    /// Reads the secret without ever logging it.
    ///
    /// # Errors
    /// Reports a missing, non-UTF-8, unreadable or empty secret.
    pub fn resolve(&self) -> Result<SecretBytes, SecretError> {
        let bytes = match &self.0 {
            // var_os keeps the value out of the error, unlike env::var.
            SecretLocation::Environment(name) => env::var_os(name)
                .ok_or(SecretError::MissingVariable)?
                .into_string()
                .map_err(|_| SecretError::NotUnicode)?
                .into_bytes(),
            SecretLocation::File(path) => fs::read(path).map_err(SecretError::Unreadable)?,
        };
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(SecretBytes(bytes))
    }
}
impl FromStr for SecretReference {
    type Err = SecretError;
    /// Accepts a known prefix followed by a nonempty locator without whitespace.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let valid = |locator: &str| !locator.is_empty() && !locator.contains(char::is_whitespace);
        let location = match (
            value.strip_prefix(Self::ENVIRONMENT_PREFIX),
            value.strip_prefix(Self::FILE_PREFIX),
        ) {
            (Some(name), _) if valid(name) => SecretLocation::Environment(name.to_owned()),
            (_, Some(path)) if valid(path) => SecretLocation::File(path.into()),
            _ => return Err(SecretError::Malformed),
        };
        Ok(Self(location))
    }
}

/// Resolved bytes with redacted diagnostic formatting.
pub struct SecretBytes(Vec<u8>);
impl SecretBytes {
    /// Exposes secret bytes to the component that requested them.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
    /// Borrows a text secret without copying it.
    ///
    /// # Errors
    /// Preserves invalid UTF-8 diagnostics without displaying secret bytes.
    pub fn utf8(&self) -> Result<&str, ConfigurationError> {
        Ok(std::str::from_utf8(&self.0)?)
    }
}
impl fmt::Debug for SecretBytes {
    /// Renders a safe diagnostic representation without exposing secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}
impl fmt::Debug for SecretReference {
    /// Renders a safe diagnostic representation without exposing secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretReference(REDACTED)")
    }
}
impl fmt::Display for SecretReference {
    /// Renders a safe diagnostic representation without exposing secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
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

/// Lets `str_enum!` vocabularies decode from `PostgreSQL` text columns, e.g.
/// `status AS "status: AccountStatus"` in a checked query. A value outside the
/// vocabulary fails decoding. This crate's `sqlx` feature selects which
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
/// plus `SQLx` text decoding when the `sqlx` feature is on.
#[macro_export]
macro_rules! str_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($(#[$variant_meta:meta])* $variant:ident = $value:literal),+ $(,)? }) => {
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
            /// Parses the stable spelling and rejects values outside the closed vocabulary.
            fn from_str(value: &str) -> Result<Self, Self::Err> { match value { $($value => Ok(Self::$variant),)+ _ => Err($crate::VocabularyError { vocabulary: stringify!($name) }) } }
        }
        impl $crate::__serde::Serialize for $name {
            /// Writes the stable vocabulary spelling to its wire representation.
            fn serialize<S: $crate::__serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.as_str()) }
        }
        impl<'de> $crate::__serde::Deserialize<'de> for $name {
            /// Parses the wire spelling and rejects values outside the closed vocabulary.
            fn deserialize<D: $crate::__serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = <String as $crate::__serde::Deserialize>::deserialize(deserializer)?;
                value.parse().map_err($crate::__serde::de::Error::custom)
            }
        }
        $crate::__str_enum_sqlx!($name);
    };
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

/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
