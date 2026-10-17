//! Signed token and `UserInfo` claims. Auth serializes these structs to issue tokens
//! and the SDKs deserialize the same structs, so issuer and verifier cannot disagree
//! on the wire format. Times are whole Unix seconds (RFC 7519 `NumericDate`).

use crate::{ClientId, SessionId, TokenId, known, known_one, oauth::Scopes};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

piquel_common::str_enum! {
    /// `amr` values (RFC 8176): how the user authenticated. This is the wire view,
    /// separate from [`crate::AuthenticationMethod`], which auth stores on sessions.
    pub enum Amr {
        /// Proof of possession of a key, such as a passkey.
        Pop = "pop",
        /// More than one factor.
        Mfa = "mfa",
        /// User presence and verification, such as a passkey's PIN or biometric.
        User = "user",
        /// An external identity provider. RFC 8176 registers no such value; this is
        /// Piquel's documented spelling.
        Fed = "fed",
    }
}

piquel_common::str_enum! {
    /// `acr` values: the authentication context class a session reached, strongest first.
    ///
    /// ```
    /// use piquel_auth_protocol::claims::Acr;
    ///
    /// // A passkey meets a social requirement, but not the other way around.
    /// assert!(Acr::PhishingResistant.satisfies(Acr::Social));
    /// assert!(!Acr::Social.satisfies(Acr::PhishingResistant));
    ///
    /// // The target of `acr_values` is the first value this version knows.
    /// assert_eq!(Acr::select("phrh phr"), Some(Acr::PhishingResistant));
    /// ```
    pub enum Acr {
        /// Phishing-resistant authentication, such as a passkey with user
        /// verification (OpenID Connect EAP ACR Values).
        PhishingResistant = "phr",
        /// Sign-in through an external identity provider.
        Social = "urn:piquel:acr:social",
    }
}

impl Acr {
    /// Whether a session at this class meets `required`. Phishing-resistant
    /// authentication meets every class.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::PhishingResistant, _) | (Self::Social, Self::Social)
        )
    }

    /// The class an authorization targets from its space-separated `acr_values`, in
    /// the client's order of preference (OIDC Core §3.1.2.1): the first known value.
    /// Unknown values are skipped, and with none known there is no target.
    ///
    /// Every active account keeps a passkey, and a passkey meets every class, so any
    /// account can reach the first known value; no later value needs considering.
    #[must_use]
    pub fn select(acr_values: &str) -> Option<Self> {
        acr_values
            .split_ascii_whitespace()
            .find_map(|value| value.parse().ok())
    }
}

/// `aud`: one string or an array (RFC 7519 §4.1.3). Auth always sends one string.
///
/// ```
/// use piquel_auth_protocol::claims::Audience;
///
/// let one: Audience = serde_json::from_str(r#""notes-api""#)?;
/// let many: Audience = serde_json::from_str(r#"["notes-api", "files-api"]"#)?;
/// assert!(one.contains("notes-api") && many.contains("files-api"));
/// assert_eq!(many.iter().count(), 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single recipient.
    One(String),
    /// Several recipients.
    Many(Vec<String>),
}

impl Audience {
    /// Whether `value` is one of the recipients.
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.iter().any(|audience| audience == value)
    }

    /// Every recipient.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        match self {
            Self::One(value) => std::slice::from_ref(value).iter(),
            Self::Many(values) => values.iter(),
        }
        .map(String::as_str)
    }
}

/// `act` (RFC 8693 §4.1): who is acting for the subject. Nested for delegation chains,
/// the outermost actor being the most recent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The acting party.
    pub sub: String,
    /// The actor before this one, if the token was exchanged more than once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<Actor>>,
}

/// `cnf` (RFC 7800): the key a sender-constrained token is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// SHA-256 JWK thumbprint of the `DPoP` key (RFC 9449 §6.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
}

/// How and when the browser session behind a token authenticated. Shared by access
/// and ID tokens, and what step-up checks read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationClaims {
    /// Browser session that authorized the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
    /// When the session signed in.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "chrono::serde::ts_seconds_option"
    )]
    pub auth_time: Option<DateTime<Utc>>,
    /// How the session signed in. Values this version does not know are dropped.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "known"
    )]
    pub amr: Vec<Amr>,
    /// Authentication context class the session reached. A class this version does
    /// not know reads as none, so it meets no requirement.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "known_one"
    )]
    pub acr: Option<Acr>,
}

/// Profile and email claims, present only when the matching scope was granted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileClaims {
    /// Username, with the profile scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Display name, with the profile scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bumped when profile claims change, so clients can tell cached data is stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_version: Option<u64>,
    /// Primary email, with the email scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Always true when present: only verified emails are released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// Claims of an access token (RFC 9068), signed with `typ: at+jwt`. `X` holds
/// application claims; auth issues none, so it uses `()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims<X = ()> {
    /// Issuer, exactly as in discovery.
    pub iss: String,
    /// The user's account ID, or the client ID when no user is involved.
    pub sub: String,
    /// The resource the token is for.
    pub aud: Audience,
    /// Client that requested the token.
    pub client_id: ClientId,
    /// Unique token ID.
    pub jti: TokenId,
    /// Granted scopes.
    pub scope: Scopes,
    /// Issue time.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub iat: DateTime<Utc>,
    /// Expiry time.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
    /// Time before which the token must not be accepted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "chrono::serde::ts_seconds_option"
    )]
    pub nbf: Option<DateTime<Utc>>,
    /// How the user authenticated.
    #[serde(flatten)]
    pub authentication: AuthenticationClaims,
    /// Delegation chain, for exchanged tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    /// Proof-of-possession binding, for sender-constrained tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
    /// Profile and email claims allowed by the granted scopes.
    #[serde(flatten)]
    pub profile: ProfileClaims,
    /// Application claims.
    #[serde(flatten)]
    pub extra: X,
}

/// Claims of an ID token (OIDC Core §2), signed with `typ: JWT`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer, exactly as in discovery.
    pub iss: String,
    /// The user's account ID.
    pub sub: String,
    /// The client the token is for.
    pub aud: Audience,
    /// The client the token was issued to, when `aud` names several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<ClientId>,
    /// Issue time.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub iat: DateTime<Utc>,
    /// Expiry time.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
    /// Time before which the token must not be accepted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "chrono::serde::ts_seconds_option"
    )]
    pub nbf: Option<DateTime<Utc>>,
    /// The client's nonce from the authorization request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// How the user authenticated.
    #[serde(flatten)]
    pub authentication: AuthenticationClaims,
    /// Profile and email claims allowed by the granted scopes.
    #[serde(flatten)]
    pub profile: ProfileClaims,
}

/// The `UserInfo` response (OIDC Core §5.3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// The user's account ID.
    pub sub: String,
    /// Profile and email claims allowed by the access token's scopes.
    #[serde(flatten)]
    pub profile: ProfileClaims,
}

/// The `events` member a logout token must carry (OIDC Back-Channel Logout 1.0 §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// An event's payload: a JSON object, empty for back-channel logout. Members are
/// ignored, but anything other than an object is refused.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Event {}

impl<'de> Deserialize<'de> for Event {
    /// Requires an object.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        BTreeMap::<String, serde::de::IgnoredAny>::deserialize(deserializer).map(|_| Self {})
    }
}

/// A claim whose presence alone matters, whatever its value, such as a logout
/// token's forbidden `nonce`. Present even as `null`; serialized as `null`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Present;

impl Present {
    /// Reads a claim as present whenever it appears.
    fn some<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Self>, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer).map(|_| Some(Self))
    }
}

impl Serialize for Present {
    /// Writes `null`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

/// Claims of a back-channel logout token (OIDC Back-Channel Logout 1.0 §2.4), signed
/// with `typ: logout+jwt`. It ends one session (`sid`) or every session of a user at
/// one client (`sub` alone).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    /// Issuer, exactly as in discovery.
    pub iss: String,
    /// The client being told.
    pub aud: Audience,
    /// Issue time.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub iat: DateTime<Utc>,
    /// Expiry time.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
    /// Unique token ID, for replay detection.
    pub jti: String,
    /// The user whose sessions end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The session that ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
    /// Must contain [`BACKCHANNEL_LOGOUT_EVENT`].
    #[expect(
        clippy::zero_sized_map_values,
        reason = "The wire format is a JSON object of event URIs to empty objects."
    )]
    pub events: BTreeMap<String, Event>,
    /// Must be absent, even as `null`, so an ID token can never pass as a logout
    /// token.
    #[serde(
        default,
        deserialize_with = "Present::some",
        skip_serializing_if = "Option::is_none"
    )]
    pub nonce: Option<Present>,
}

#[cfg(test)]
mod tests {
    //! Class ordering and `acr_values` selection.
    use super::*;

    /// Phishing-resistant authentication meets both classes; social meets only itself.
    #[test]
    fn stronger_classes_satisfy_weaker_ones() {
        assert!(Acr::PhishingResistant.satisfies(Acr::PhishingResistant));
        assert!(Acr::PhishingResistant.satisfies(Acr::Social));
        assert!(Acr::Social.satisfies(Acr::Social));
        assert!(!Acr::Social.satisfies(Acr::PhishingResistant));
    }

    /// The client's order wins, unknown values are skipped, and nothing known means
    /// no target.
    #[test]
    fn selection_takes_the_first_known_value() {
        assert_eq!(Acr::select("urn:piquel:acr:social phr"), Some(Acr::Social));
        assert_eq!(
            Acr::select("phr urn:piquel:acr:social"),
            Some(Acr::PhishingResistant)
        );
        assert_eq!(
            Acr::select("urn:example:gold  phr"),
            Some(Acr::PhishingResistant)
        );
        assert_eq!(Acr::select("urn:example:gold 2"), None);
        assert_eq!(Acr::select(""), None);
    }
}
