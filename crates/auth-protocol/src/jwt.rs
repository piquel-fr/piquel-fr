//! JWT claims and JOSE metadata shared by token issuers and verifiers.

use serde::{Deserialize, Serialize};

piquel_common::str_enum! {
    /// JWT `typ` headers. Distinct types stop an ID token being accepted as an access token.
    pub enum TokenType {
        /// Access token (RFC 9068).
        Access = "at+jwt",
        /// ID token, also accepted back as an `id_token_hint`.
        Id = "JWT",
        /// Back-channel logout token (OIDC Back-Channel Logout 1.0 §2.4).
        Logout = "logout+jwt",
    }
}
piquel_common::str_enum! {
    /// JWT claim names shared by token issuance, verification and `UserInfo`.
    pub enum Claim {
        /// Issuer that signed the token.
        Issuer = "iss",
        /// Account ID.
        Subject = "sub",
        /// Who the token is for: the resource for access tokens, the client for ID tokens.
        Audience = "aud",
        /// Issue time, in Unix seconds.
        IssuedAt = "iat",
        /// Expiry time, in Unix seconds.
        ExpiresAt = "exp",
        /// Time before which the token must not be accepted, in Unix seconds.
        NotBefore = "nbf",
        /// Browser session that authorized the grant.
        Session = "sid",
        /// When the browser session last authenticated at its `acr`.
        AuthTime = "auth_time",
        /// How the browser session authenticated (RFC 8176 values).
        Methods = "amr",
        /// Authentication context class the browser session reached.
        AuthenticationClass = "acr",
        /// Delegation chain of a token-exchange token (RFC 8693 §4.1).
        Actor = "act",
        /// Proof-of-possession key binding (RFC 7800), such as a `DPoP` key thumbprint.
        Confirmation = "cnf",
        /// Client an ID token was issued to, when its audience names several.
        AuthorizedParty = "azp",
        /// Display name, with the profile scope.
        Name = "name",
        /// Username, with the profile scope.
        Username = "preferred_username",
        /// Primary email, with the email scope.
        Email = "email",
        /// Always true: only verified emails are released.
        EmailVerified = "email_verified",
        /// Profile version, so clients can tell when cached profile data is stale.
        ProfileVersion = "profile_version",
        /// Client that requested the access token.
        Client = "client_id",
        /// Unique access token ID.
        TokenId = "jti",
        /// Granted scopes, space-separated.
        Scope = "scope",
        /// Client nonce, echoed in the ID token.
        Nonce = "nonce",
    }
}
piquel_common::str_enum! {
    /// Signing algorithms accepted by this workspace.
    pub enum Algorithm {
        /// RSA PKCS#1 v1.5 with SHA-256.
        Rs256 = "RS256",
    }
}
piquel_common::str_enum! {
    /// JWK key families accepted for signing.
    pub enum KeyType {
        /// RSA modulus and exponent.
        Rsa = "RSA",
    }
}
piquel_common::str_enum! {
    /// JWK purposes accepted for signing keys.
    pub enum KeyUse {
        /// Digital signatures.
        Signature = "sig",
    }
}

/// A JSON Web Key Set (RFC 7517 §5). Auth publishes `JwkSet<Jwk>`. Verifiers read the
/// keys as raw JSON and parse each one alone, because RFC 7517 §5 says a key of an
/// unknown `kty` is skipped rather than failing the whole set.
///
/// ```
/// use piquel_auth_protocol::jwt::{Jwk, JwkSet, KeyType};
///
/// let set: JwkSet<serde_json::Value> = serde_json::from_str(r#"{"keys": [
///     {"kty": "RSA", "kid": "key-2026", "use": "sig", "alg": "RS256", "n": "AQAB", "e": "AQAB"},
///     {"kty": "OKP", "kid": "future", "crv": "Ed25519", "x": "AQAB"}
/// ]}"#)?;
/// let usable: Vec<Jwk> = set
///     .keys
///     .into_iter()
///     .filter_map(|key| serde_json::from_value(key).ok())
///     .collect();
/// assert_eq!(usable.len(), 1);
/// assert_eq!((usable[0].kid.as_str(), usable[0].kty), ("key-2026", KeyType::Rsa));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet<K = Jwk> {
    /// Published keys.
    pub keys: Vec<K>,
}

/// One public RSA signing key. Fields are in sorted order, so auth's JWKS keeps the
/// byte layout it had when it was built with `json!`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Algorithm the key signs with. Auth always sends it; other issuers may not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<Algorithm>,
    /// Base64url RSA public exponent.
    pub e: String,
    /// Key identifier, matching the token header's `kid`.
    pub kid: String,
    /// Key family; any value but `RSA` fails parsing.
    pub kty: KeyType,
    /// Base64url RSA modulus.
    pub n: String,
    /// Key purpose. Auth always sends it; other issuers may not.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,
}
