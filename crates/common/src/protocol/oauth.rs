//! OAuth 2.0 and `OpenID` Connect wire vocabulary, shared by the OIDC provider, the
//! social-login client and the SDKs so every side spells the protocol identically.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeSet, fmt, str::FromStr};
use thiserror::Error;

crate::str_enum! {
    /// Token endpoint grants (RFC 6749 §4.1.3 and §6).
    pub enum GrantType {
        /// Exchange a single-use authorization code, bound to PKCE.
        AuthorizationCode = "authorization_code",
        /// Rotate a refresh token.
        RefreshToken = "refresh_token",
    }
}

crate::str_enum! {
    /// Authorization response types. Only the code flow is supported.
    pub enum ResponseType {
        /// Return an authorization code to the redirect URI.
        Code = "code",
    }
}

crate::str_enum! {
    /// Authorization response modes. Only the query string is supported.
    pub enum ResponseMode {
        /// Code and state go in the redirect's query string.
        Query = "query",
    }
}

crate::str_enum! {
    /// Client authentication methods at the token and revocation endpoints.
    pub enum ClientAuthMethod {
        /// Public client, identified by its ID alone.
        None = "none",
        /// Confidential client, authenticated by HTTP Basic.
        ClientSecretBasic = "client_secret_basic",
    }
}

crate::str_enum! {
    /// OIDC subject identifier types.
    pub enum SubjectType {
        /// Every client sees the same account ID.
        Public = "public",
    }
}

crate::str_enum! {
    /// PKCE code challenge methods (RFC 7636). `plain` is deliberately absent.
    pub enum CodeChallengeMethod {
        /// The challenge is the base64url SHA-256 of the verifier.
        S256 = "S256",
    }
}

crate::str_enum! {
    /// OIDC `prompt` values controlling browser interaction.
    pub enum Prompt {
        /// Fail instead of showing any page.
        None = "none",
        /// Require a fresh sign-in.
        Login = "login",
        /// Require explicit consent.
        Consent = "consent",
        /// Let the user choose an account.
        SelectAccount = "select_account",
    }
}

crate::str_enum! {
    /// Standard OIDC scopes. Clients may also be granted registered extension scopes.
    pub enum Scope {
        /// Issue an ID token and allow `UserInfo`.
        OpenId = "openid",
        /// Include profile claims.
        Profile = "profile",
        /// Include email claims.
        Email = "email",
        /// Allow refresh tokens when the client permits them.
        OfflineAccess = "offline_access",
    }
}

/// A set of scope tokens (RFC 6749 §3.3), deduplicated and sorted so its space-separated
/// wire form is stable. Holds strings because applications declare their own scopes
/// besides the standard [`Scope`] values.
///
/// ```
/// use piquel_common::protocol::oauth::{InvalidScope, Scopes};
///
/// let granted: Scopes = "profile openid notes:read profile".parse()?;
/// assert_eq!(granted.to_string(), "notes:read openid profile");
/// assert!(granted.contains("notes:read"));
/// assert!("openid".parse::<Scopes>()?.is_subset(&granted));
/// assert_eq!(r#"say"hi""#.parse::<Scopes>(), Err(InvalidScope));
/// # Ok::<(), InvalidScope>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Scopes(BTreeSet<String>);

/// A scope list that breaks RFC 6749 §3.3 syntax.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("scope tokens must be printable ASCII without spaces, `\"` or `\\`")]
pub struct InvalidScope;

impl Scopes {
    /// Whether `scope` is a valid scope token: one or more printable ASCII characters
    /// other than space, `"` and `\`.
    /// A `const fn`, so macros can reject invalid scope names at compile time.
    #[must_use]
    pub const fn is_token(scope: &str) -> bool {
        let bytes = scope.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if !matches!(bytes[index], 0x21 | 0x23..=0x5B | 0x5D..=0x7E) {
                return false;
            }
            index += 1;
        }
        !bytes.is_empty()
    }

    /// Whether the set contains `scope`.
    #[must_use]
    pub fn contains(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }

    /// Whether every scope in `self` is also in `other`.
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }

    /// Number of distinct scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Scopes in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

impl FromStr for Scopes {
    type Err = InvalidScope;
    /// Parses a space-separated list. Repeated whitespace is tolerated, as auth always
    /// has; every token must have valid syntax.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .split_ascii_whitespace()
            .map(|scope| {
                Self::is_token(scope)
                    .then(|| scope.to_owned())
                    .ok_or(InvalidScope)
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl FromIterator<String> for Scopes {
    /// Collects scopes that were validated when they were stored, such as a grant read
    /// back from the database. Untrusted text goes through `parse` instead.
    fn from_iter<I: IntoIterator<Item = String>>(scopes: I) -> Self {
        Self(scopes.into_iter().collect())
    }
}

impl IntoIterator for Scopes {
    type Item = String;
    type IntoIter = std::collections::btree_set::IntoIter<String>;
    /// Yields the scopes in sorted order.
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl fmt::Display for Scopes {
    /// Writes the space-separated wire form.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, scope) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(" ")?;
            }
            formatter.write_str(scope)?;
        }
        Ok(())
    }
}

impl Serialize for Scopes {
    /// Writes the space-separated wire form.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Scopes {
    /// Parses the space-separated wire form, rejecting invalid scope syntax.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

crate::open_str_enum! {
    /// OAuth and OIDC error codes auth returns from its endpoints and in authorization
    /// error redirects (RFC 6749 §4.1.2.1 and §5.2, OIDC Core §3.1.2.6). Open, so an
    /// SDK still reads an error body carrying a code added after it was built.
    pub enum ErrorCode {
        /// Request parameters break the endpoint's contract.
        InvalidRequest = "invalid_request",
        /// Client authentication failed.
        InvalidClient = "invalid_client",
        /// An authorization code or refresh token is unusable.
        InvalidGrant = "invalid_grant",
        /// Requested scopes exceed the grant or the client's policy.
        InvalidScope = "invalid_scope",
        /// The requested audience is not registered for the client.
        InvalidTarget = "invalid_target",
        /// Bearer or browser authentication failed.
        InvalidToken = "invalid_token",
        /// The token endpoint does not support the requested grant.
        UnsupportedGrantType = "unsupported_grant_type",
        /// A `prompt=none` request needs the user to sign in.
        LoginRequired = "login_required",
        /// A `prompt=none` request needs the user's consent.
        ConsentRequired = "consent_required",
        /// Signed `request` objects are not supported.
        RequestNotSupported = "request_not_supported",
        /// A `request_uri` is not one this server pushed, or is expired, already
        /// used or another client's (RFC 9101 §6.2, RFC 9126 §4).
        InvalidRequestUri = "invalid_request_uri",
        /// The user declined consent.
        AccessDenied = "access_denied",
        /// An internal operation failed.
        ServerError = "server_error",
    }
}

/// An `error_description` (RFC 6749 §5.2, RFC 6750 §3): printable ASCII without `"`
/// or `\`. The restriction keeps it valid inside a `WWW-Authenticate` quoted string,
/// so no description can break or inject a header.
///
/// ```
/// use piquel_common::protocol::oauth::ErrorDescription;
///
/// assert!("the code expired".parse::<ErrorDescription>().is_ok());
/// assert!("line\nbreak".parse::<ErrorDescription>().is_err());
/// // Text quoting a library error becomes a valid description.
/// let quoted = ErrorDescription::lossy("expected \"S256\" here\n");
/// assert_eq!(quoted.as_str(), "expected 'S256' here?");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ErrorDescription(String);

/// A description with characters RFC 6749 §5.2 forbids.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("error_description must be printable ASCII without `\"` or `\\`")]
pub struct InvalidDescription;

impl ErrorDescription {
    /// Whether `byte` may appear in a description.
    const fn allowed(byte: u8) -> bool {
        matches!(byte, 0x20 | 0x21 | 0x23..=0x5B | 0x5D..=0x7E)
    }

    /// Makes any text a valid description: `"` becomes `'`, and other forbidden
    /// characters become `?`. For descriptions that quote library errors.
    #[must_use]
    pub fn lossy(text: &str) -> Self {
        Self(
            text.chars()
                .map(|character| match character {
                    '"' => '\'',
                    _ if character.is_ascii() && Self::allowed(character as u8) => character,
                    _ => '?',
                })
                .collect(),
        )
    }

    /// The description text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ErrorDescription {
    type Err = InvalidDescription;
    /// Accepts only the characters RFC 6749 §5.2 allows.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.bytes().all(Self::allowed) {
            Ok(Self(text.to_owned()))
        } else {
            Err(InvalidDescription)
        }
    }
}

impl TryFrom<String> for ErrorDescription {
    type Error = InvalidDescription;
    /// Same as `parse`.
    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<ErrorDescription> for String {
    /// The description text.
    fn from(description: ErrorDescription) -> Self {
        description.0
    }
}

impl fmt::Display for ErrorDescription {
    /// Writes the description.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// JSON error body of auth's OAuth endpoints (RFC 6749 §5.2).
///
/// ```
/// use piquel_common::protocol::oauth::{ErrorCode, ErrorResponse};
///
/// let body: ErrorResponse =
///     serde_json::from_str(r#"{"error":"invalid_grant","error_description":"code expired"}"#)?;
/// assert_eq!(body.error, ErrorCode::InvalidGrant);
/// // A code added after this version is kept rather than failing the body.
/// let newer: ErrorResponse = serde_json::from_str(r#"{"error":"temporarily_unavailable"}"#)?;
/// assert_eq!(newer.error, ErrorCode::Other("temporarily_unavailable".into()));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// What went wrong.
    pub error: ErrorCode,
    /// What the client should fix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<ErrorDescription>,
}

#[cfg(test)]
mod tests {
    //! Scope list syntax.
    use super::*;

    /// Lists are sorted and deduplicated, and tokens outside RFC 6749 §3.3 are rejected.
    #[test]
    fn scopes_follow_rfc_6749_syntax() {
        let scopes: Scopes = "profile  openid profile notes:read"
            .parse()
            .expect("scopes");
        assert_eq!(scopes.to_string(), "notes:read openid profile");
        assert_eq!(
            serde_json::from_str::<Scopes>("\"openid profile\"").expect("deserialize"),
            "profile openid".parse().expect("scopes")
        );
        for invalid in ["say\"hi\"", "back\\slash", "caf\u{e9}"] {
            assert_eq!(invalid.parse::<Scopes>(), Err(InvalidScope), "{invalid}");
        }
    }
}
