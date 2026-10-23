//! Stable, framework-independent documents exchanged by authentication participants:
//! auth itself, its first-party apps and the SDKs. Auth issues tokens and documents by
//! serializing these types, and the SDKs read them back with the same types.
//!
//! Most applications use these types through the `piquel-auth` SDK, which validates
//! tokens before decoding them. Used directly, they describe the wire format:
//!
//! ```
//! use piquel_common::protocol::{
//!     challenge::{BearerChallenge, BearerError},
//!     claims::{AccessTokenClaims, Amr},
//! };
//!
//! // The claims of a token, once its signature has been checked.
//! let claims: AccessTokenClaims = serde_json::from_str(r#"{
//!     "iss": "https://auth.piquel.fr",
//!     "sub": "01936f3e-8c00-7000-8000-000000000001",
//!     "aud": "notes-api",
//!     "client_id": "notes-web",
//!     "jti": "01936f3e-8c00-7000-8000-000000000003",
//!     "scope": "openid notes:read",
//!     "iat": 1767225540,
//!     "exp": 1767225840,
//!     "amr": ["pop", "user"]
//! }"#)?;
//! assert!(claims.scope.contains("notes:read"));
//! assert_eq!(claims.authentication.amr, [Amr::Pop, Amr::User]);
//!
//! // The challenge a resource server answers with when the scope is missing.
//! let challenge = BearerChallenge {
//!     scope: Some("notes:write".parse()?),
//!     ..BearerChallenge::error(BearerError::InsufficientScope)
//! };
//! assert_eq!(challenge.status(), 403);
//! assert_eq!(
//!     challenge.to_string(),
//!     r#"Bearer error="insufficient_scope", scope="notes:write""#
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

/// Bodies shared by auth's account settings and admin APIs.
pub mod api;
/// `WWW-Authenticate: Bearer` challenges sent by resource servers.
pub mod challenge;
/// Access token, ID token and `UserInfo` claims, and the `acr` and `amr` values they report.
pub mod claims;
/// JWT claim and JOSE field vocabulary shared by token issuers and verifiers.
pub mod jwt;
/// Authorization server metadata, as published at both well-known discovery paths.
pub mod metadata;
/// OAuth and OpenID Connect vocabulary shared by clients and the provider.
pub mod oauth;
/// Whether a browser request comes from a site's own pages.
pub mod same_origin;
/// Error codes shared by the SDKs and their test vectors.
pub mod sdk;
/// What a protected operation needs from the user's authentication (RFC 9470).
pub mod step_up;

use serde::{Deserialize, Deserializer};
use std::str::FromStr;

/// Reads a vocabulary list, dropping values this version does not know, so the
/// issuer can add values without breaking older readers.
fn known<'de, D: Deserializer<'de>, T: FromStr>(deserializer: D) -> Result<Vec<T>, D::Error> {
    Ok(Vec::<String>::deserialize(deserializer)?
        .iter()
        .filter_map(|value| value.parse().ok())
        .collect())
}

/// Reads one optional vocabulary value, as none when this version does not know it.
fn known_one<'de, D: Deserializer<'de>, T: FromStr>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.and_then(|value| value.parse().ok()))
}
