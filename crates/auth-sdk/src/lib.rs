//! Rust SDK for auth.piquel.fr.
//!
//! - **Resource servers** validate access tokens with a [`ResourceValidator`], and
//!   declare their scopes as types with [`scopes!`], so a misspelled scope does not
//!   compile.
//! - **Applications** sign users in with a [`Client`]: the authorization code flow
//!   with PKCE, `state`, `nonce` and RFC 9207 issuer checks.
//! - [`KeyCache`] verifies JWS signatures against any JWKS URL, refetching on key
//!   rotation without letting unknown key IDs flood the issuer.
//!
//! Everything starts from a discovered [`Issuer`]:
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use piquel_auth::{Issuer, Resource, Subject};
//!
//! piquel_auth::scopes! {
//!     /// Scopes of the notes API.
//!     pub mod notes {
//!         Read = "notes:read",
//!         Write = "notes:write",
//!     }
//! }
//!
//! let issuer = Issuer::discover("https://auth.piquel.fr").await?;
//! let notes = issuer.resource(Resource::new("notes-api")?);
//! let token = notes.validate::<notes::Read>("eyJ...").await?;
//! if let Subject::User(user) = token.subject {
//!     println!("{user} may read notes");
//! }
//! # Ok(()) }
//! ```
//!
//! The behavior follows `docs/architecture/sdk.md` in the piquel-fr repository, and is
//! tested against the shared vectors in `tests/sdk-vectors`.

/// Login: authorization, callbacks, refresh, revocation and logout.
mod client;
/// HTTP requests with bounded bodies.
mod http;
/// Discovery and the shared issuer handle.
mod issuer;
/// JWS parsing and signing key caching.
mod keys;
/// Resource identifiers and access token validation.
mod resource;
/// Typed scopes.
mod scope;
/// Validated tokens and their errors.
mod token;

#[cfg(test)]
mod tests;

pub use client::{
    AuthorizeRequest, BearerToken, CallbackParams, Client, ClientConfig, Credentials, LoginError,
    OAuthError, PendingLogin, RefreshToken, Tokens,
};
pub use http::NetworkError;
pub use issuer::{DiscoveryError, Issuer, IssuerBuilder};
pub use keys::{Jws, JwsHeader, KeyCache, KeyError, KeySet};
pub use resource::{Resource, ResourceError, ResourceValidator};
pub use scope::{Scope, ScopeSet};
pub use token::{AccessToken, IdToken, Subject, TokenError};

/// The wire types this SDK reads, shared with auth itself.
pub use piquel_auth_protocol as protocol;
pub use piquel_auth_protocol::{
    ClientId, SessionId, TokenId, UserId,
    claims::{Acr, Actor, Amr, Confirmation, IdTokenClaims, ProfileClaims, UserInfo},
    oauth::Scopes,
    sdk::SdkError,
};

use chrono::{DateTime, TimeDelta, Utc};

/// Clock skew tolerated on `exp`, `nbf`, `iat` and `auth_time`, matching auth's own.
const LEEWAY: TimeDelta = TimeDelta::seconds(30);

/// The time source for every expiry and cache check. Inject one with
/// [`IssuerBuilder::clock`] to pin time in tests.
pub trait Clock: Send + Sync + 'static {
    /// The current time.
    fn now(&self) -> DateTime<Utc>;
}

/// The system clock, used unless another is injected.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Items the exported macros expand to; not part of the public API.
#[doc(hidden)]
pub mod __private {
    pub use piquel_auth_protocol::oauth::Scopes;
}
