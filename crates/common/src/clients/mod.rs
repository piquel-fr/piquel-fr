//! OAuth client registrations. Each field has a type that validates it when built,
//! so a [`ClientRegistration`](crate::clients::ClientRegistration) cannot hold an
//! invalid value, and the repository, which accepts nothing else, never stores one.
//! Every error names the field and the value it rejected, e.g.
//! `redirect URI http://example.com/cb must use https`.
//!
//! ```
//! use piquel_common::clients::{ClientId, InvalidRedirectUri, RedirectUri};
//!
//! let id: ClientId = "notes-web".parse()?;
//! let callback: RedirectUri = "https://notes.example/callback".parse()?;
//! assert_eq!(callback.origin(), "https://notes.example");
//! // Plain HTTP is only for loopback IPs, where native apps listen.
//! assert!("http://127.0.0.1:8080/callback".parse::<RedirectUri>().is_ok());
//! assert!(matches!(
//!     "http://notes.example/callback".parse::<RedirectUri>(),
//!     Err(InvalidRedirectUri::Insecure { .. })
//! ));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::{
    UserId,
    protocol::oauth::{Scope, Scopes},
};
use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref, str::FromStr};
use thiserror::Error;
use url::{Host, Url};

/// Longest client ID and scope, in bytes.
const MAX_IDENTIFIER_LENGTH: usize = 64;
/// Longest display name, in characters.
const MAX_DISPLAY_NAME_CHARS: usize = 80;
/// Starts every client ID auth generates.
const GENERATED_ID_PREFIX: &str = "c_";
/// Characters after [`GENERATED_ID_PREFIX`], 5 random bits each.
const GENERATED_ID_CHARS: usize = 20;
/// The RFC 4648 base32 alphabet, lowercased so generated IDs read well in URLs.
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A registered OAuth client's identifier: 1 to 64 ASCII letters, digits, `.`, `_`
/// or `-`. It is fixed at registration and appears in tokens as `client_id`, `azp`
/// and `aud`, so no other client may ever take it, even after a deletion.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientId(String);

/// A client ID outside `[A-Za-z0-9._-]{1,64}`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("client ID {0:?} must be 1 to 64 characters from A-Z, a-z, 0-9, '.', '_' and '-'")]
pub struct InvalidClientId(String);

impl ClientId {
    /// The identifier as sent on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The ID auth gives a client an account registers: `c_` and 20 base32
    /// characters, one per byte of `random`, 100 bits in all. Only operators and
    /// administrators choose IDs, so an account can never claim a name such as
    /// `piquel-web`.
    #[must_use]
    pub fn generated(random: &[u8; 32]) -> Self {
        let suffix = random
            .iter()
            .take(GENERATED_ID_CHARS)
            .map(|byte| char::from(BASE32[usize::from(byte & 0x1f)]));
        Self(GENERATED_ID_PREFIX.chars().chain(suffix).collect())
    }
}

impl FromStr for ClientId {
    type Err = InvalidClientId;
    /// Accepts `[A-Za-z0-9._-]{1,64}`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let valid = (1..=MAX_IDENTIFIER_LENGTH).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidClientId(value.to_owned()))
        }
    }
}

impl TryFrom<String> for ClientId {
    type Error = InvalidClientId;
    /// Validates owned text, as serde reads it.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<ClientId> for String {
    /// The identifier as sent on the wire.
    fn from(value: ClientId) -> Self {
        value.0
    }
}

impl fmt::Display for ClientId {
    /// Writes the identifier unchanged.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

crate::__str_enum_sqlx!(ClientId);

crate::str_enum! {
    /// Whether a client can keep a secret (RFC 6749 §2.1).
    pub enum ClientKind {
        /// Runs where users can read its code, such as a browser or native app.
        /// It authenticates with PKCE alone, and its redirect origins may call the
        /// token and `UserInfo` endpoints from a browser.
        Public = "public",
        /// Runs on a server. It authenticates with a secret auth generates.
        Confidential = "confidential",
    }
}

/// Who manages a client, fixed when it is registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientOwner {
    /// An operator, with the `client` command. No account manages it, and the
    /// account API never shows it.
    Operator,
    /// The account that registered it through the account API, which alone may
    /// change it there.
    Account(UserId),
}

crate::str_enum! {
    /// How a client was registered, stored beside its owner.
    pub enum CreatedVia {
        /// By an operator, with the `client` command.
        Cli = "cli",
        /// By its owner, through the account API.
        Account = "account",
    }
}

impl ClientOwner {
    /// The managing account, if any.
    #[must_use]
    pub const fn user_id(self) -> Option<UserId> {
        match self {
            Self::Operator => None,
            Self::Account(user_id) => Some(user_id),
        }
    }

    /// How a client with this owner was registered.
    #[must_use]
    pub const fn created_via(self) -> CreatedVia {
        match self {
            Self::Operator => CreatedVia::Cli,
            Self::Account(_) => CreatedVia::Account,
        }
    }
}

crate::open_str_enum! {
    /// A setting of a [`ClientRegistration`], named as the account API's bodies
    /// name it. Errors name the field they reject, and `ClientUpdated` events the
    /// fields that changed. Open, since a newer release adds settings (branding,
    /// #45; back-channel logout, #65) to events this release still reads.
    pub enum ClientField {
        /// [`ClientRegistration::display_name`].
        DisplayName = "display_name",
        /// [`ClientRegistration::redirect_uris`].
        RedirectUris = "redirect_uris",
        /// [`ClientRegistration::post_logout_uris`].
        PostLogoutUris = "post_logout_uris",
        /// [`ClientRegistration::allowed_scopes`].
        AllowedScopes = "allowed_scopes",
        /// [`ClientRegistration::allow_refresh`].
        AllowRefresh = "allow_refresh",
        /// [`ClientRegistration::trusted`].
        Trusted = "trusted",
        /// [`ClientRegistration::require_pushed_authorization_requests`].
        RequirePushedAuthorizationRequests = "require_pushed_authorization_requests",
    }
}

impl ClientField {
    /// Whether changing this field changes where auth may send the browser, which
    /// would let whoever changes it collect authorization codes.
    #[must_use]
    pub const fn redirects(&self) -> bool {
        match self {
            Self::RedirectUris | Self::PostLogoutUris => true,
            Self::DisplayName
            | Self::AllowedScopes
            | Self::AllowRefresh
            | Self::Trusted
            | Self::RequirePushedAuthorizationRequests
            | Self::Other(_) => false,
        }
    }
}

/// The name a consent screen shows: nonblank, at most 80 characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayName(String);

/// A display name that is blank or longer than 80 characters.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error(
    "display name {0:?} must be nonblank, at most 80 characters and have no control characters"
)]
pub struct InvalidDisplayName(String);

impl DisplayName {
    /// The name as shown.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DisplayName {
    type Err = InvalidDisplayName;
    /// Accepts nonblank names of at most 80 characters, without control characters
    /// that could rewrite the terminal or page that shows them.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.trim().is_empty()
            || value.chars().count() > MAX_DISPLAY_NAME_CHARS
            || value.chars().any(char::is_control)
        {
            return Err(InvalidDisplayName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

/// A URI auth may send the browser back to: an authorization callback or a
/// post-logout page. It uses HTTPS, or HTTP on a loopback IP for native apps
/// (RFC 8252 §7.3), and has no user name, password or fragment.
///
/// It must be written exactly as URL parsing normalizes it, e.g.
/// `https://app.example/` rather than `https://APP.example`: clients send it
/// verbatim, and auth compares it as a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectUri(Url);

/// Why a redirect URI was rejected.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum InvalidRedirectUri {
    /// The value is not an absolute URL.
    #[error("redirect URI {uri:?} is not an absolute URL")]
    NotAbsolute {
        /// The rejected value.
        uri: String,
        /// The URL parser's diagnostic.
        #[source]
        source: url::ParseError,
    },
    /// The URL uses another scheme, or HTTP on a host other than a loopback IP.
    #[error(
        "redirect URI {uri} must use https; http is allowed only on a loopback IP, \
         e.g. http://127.0.0.1:8080/callback"
    )]
    Insecure {
        /// The rejected value.
        uri: String,
    },
    /// The URL holds a user name or password. The value is omitted: it may hold a secret.
    #[error("redirect URIs must not contain a user name or password")]
    Credentials,
    /// The URL has a fragment, which authorization responses cannot carry (RFC 6749 §3.1.2).
    #[error("redirect URI {uri} must not contain a fragment")]
    Fragment {
        /// The rejected value.
        uri: String,
    },
    /// The URL is not written in its normalized form.
    #[error("redirect URI {uri} must be written as {canonical}, as clients will send it")]
    NotCanonical {
        /// The rejected value.
        uri: String,
        /// The same URL in its normalized form.
        canonical: String,
    },
}

impl RedirectUri {
    /// The URI as registered and as clients send it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The URI's origin as browsers send it in an `Origin` header, e.g.
    /// `https://app.example`, which may call the token endpoint for a public client.
    #[must_use]
    pub fn origin(&self) -> String {
        self.0.origin().ascii_serialization()
    }
}

impl FromStr for RedirectUri {
    type Err = InvalidRedirectUri;
    /// Applies the rules in [`RedirectUri`]'s description.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uri = || value.to_owned();
        let url = Url::parse(value)
            .map_err(|source| InvalidRedirectUri::NotAbsolute { uri: uri(), source })?;
        let loopback = match url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(_)) | None => false,
        };
        // Special schemes always have a host, so an `https` URL needs no host check.
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback)) {
            return Err(InvalidRedirectUri::Insecure { uri: uri() });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(InvalidRedirectUri::Credentials);
        }
        if url.fragment().is_some() {
            return Err(InvalidRedirectUri::Fragment { uri: uri() });
        }
        if url.as_str() != value {
            return Err(InvalidRedirectUri::NotCanonical {
                uri: uri(),
                canonical: url.into(),
            });
        }
        Ok(Self(url))
    }
}

impl fmt::Display for RedirectUri {
    /// Writes the URI as registered.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A scope a client may request: an RFC 6749 §3.3 scope token of at most 64
/// characters, such as `openid` or an application's own `notes:read`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeName(String);

/// A scope that is not a scope token of at most 64 characters.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("scope {0:?} must be 1 to 64 printable ASCII characters other than space, '\"' and '\\'")]
pub struct InvalidScopeName(String);

impl ScopeName {
    /// The scope as requested on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ScopeName {
    type Err = InvalidScopeName;
    /// Accepts scope tokens of at most 64 characters.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_IDENTIFIER_LENGTH || !Scopes::is_token(value) {
            return Err(InvalidScopeName(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }
}

impl From<Scope> for ScopeName {
    /// A standard scope is always a valid scope name.
    fn from(scope: Scope) -> Self {
        Self(scope.as_str().to_owned())
    }
}

/// Distinct values, at least `MIN` and at most `MAX` of them, in the order given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedVec<T, const MIN: usize, const MAX: usize>(Vec<T>);

/// A list with too few or too many distinct values. The caller names the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("must list {min} to {max} distinct values, not {found}")]
pub struct InvalidCount {
    /// The fewest values allowed.
    pub min: usize,
    /// The most values allowed.
    pub max: usize,
    /// How many distinct values were given.
    pub found: usize,
}

impl<T: PartialEq, const MIN: usize, const MAX: usize> BoundedVec<T, MIN, MAX> {
    /// Drops repeated values, keeping the first, then checks the count.
    ///
    /// # Errors
    /// Returns [`InvalidCount`] for fewer than `MIN` or more than `MAX` distinct values.
    pub fn new(values: impl IntoIterator<Item = T>) -> Result<Self, InvalidCount> {
        const { assert!(MIN <= MAX, "a BoundedVec needs MIN <= MAX") };
        let mut distinct = Vec::new();
        for value in values {
            if !distinct.contains(&value) {
                distinct.push(value);
            }
        }
        if !(MIN..=MAX).contains(&distinct.len()) {
            return Err(InvalidCount {
                min: MIN,
                max: MAX,
                found: distinct.len(),
            });
        }
        Ok(Self(distinct))
    }
}

impl<T, const MIN: usize, const MAX: usize> Deref for BoundedVec<T, MIN, MAX> {
    type Target = [T];
    /// Reads the values as a slice.
    fn deref(&self) -> &[T] {
        &self.0
    }
}

/// 1 to 16 authorization callbacks.
pub type RedirectUris = BoundedVec<RedirectUri, 1, 16>;
/// Up to 16 pages the browser may return to after logout.
pub type PostLogoutUris = BoundedVec<RedirectUri, 0, 16>;
/// 1 to 32 scopes a client may request.
pub type AllowedScopes = BoundedVec<ScopeName, 1, 32>;

/// Everything an operator decides about a client. Every field is valid by
/// construction, so storing one needs no further checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRegistration {
    /// The client's identifier.
    pub id: ClientId,
    /// The name consent screens show.
    pub display_name: DisplayName,
    /// Public, or confidential with a secret.
    pub kind: ClientKind,
    /// Where authorization responses may be sent, matched exactly.
    pub redirect_uris: RedirectUris,
    /// Where the browser may return after logout, matched exactly.
    pub post_logout_uris: PostLogoutUris,
    /// The scopes the client may request.
    pub allowed_scopes: AllowedScopes,
    /// Whether the client may receive refresh tokens, with `offline_access`.
    pub allow_refresh: bool,
    /// Whether the client skips the consent screen. Only for first-party clients.
    pub trusted: bool,
    /// Whether the client must push its authorization requests (RFC 9126 §6), so
    /// none of its parameters travel through the browser.
    pub require_pushed_authorization_requests: bool,
}

/// Focused tests for each field's rules.
#[cfg(test)]
mod tests;
