//! Rust SDK for auth.sourceorigin.dev.
//!
//! - **Resource servers** validate access tokens with a [`ResourceValidator`], and
//!   declare their scopes as types with [`scopes!`], so a misspelled scope does not
//!   compile.
//! - **Applications** sign users in with a [`Client`]: the authorization code flow
//!   with PKCE, `state`, `nonce` and RFC 9207 issuer checks.
//! - [`KeyCache`] verifies JWS signatures against any JWKS URL, refetching on key
//!   rotation without letting unknown key IDs flood the issuer.
//!
//! The user guide shows how to use it, with the `axum` feature:
//! [signing in with Rust](https://docs.sourceorigin.dev/user/apps/sign-in-rust.html) and
//! [protecting an API](https://docs.sourceorigin.dev/user/apps/protect-an-api.html).
//!
//! Everything starts from a discovered [`Issuer`]:
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use sourceorigin_auth::{Issuer, Resource, Subject};
//!
//! sourceorigin_auth::scopes! {
//!     /// Scopes of the notes API.
//!     pub mod notes {
//!         Read = "notes:read",
//!         Write = "notes:write",
//!     }
//! }
//!
//! let issuer = Issuer::discover("https://auth.sourceorigin.dev").await?;
//! let notes = issuer.resource(Resource::new("notes-api")?);
//! let token = notes.validate::<notes::Read>("eyJ...").await?;
//! if let Subject::User(user) = token.subject() {
//!     println!("{user} may read notes");
//! }
//! # Ok(()) }
//! ```
//!
//! # Quick start
//!
//! Add the SDK with its axum integration:
//!
//! ```sh
//! cargo add sourceorigin-auth --features axum
//! ```
//!
//! This notes service, the crate's `notes` example, protects an API with access
//! tokens and signs users in to its page:
//!
#![cfg_attr(feature = "axum", doc = concat!("```no_run\n", include_str!("../examples/notes.rs"), "\n```"))]
//!
//! # Validating access tokens
//!
//! A resource server builds one [`ResourceValidator`] per API from its [`Resource`]
//! identifier, the `aud` its tokens carry. [`ResourceValidator::validate`] runs every
//! check of the SDK design, in order: framing, `crit`, `typ`, algorithm, key,
//! signature, claims, issuer, audience and times, with a 30-second leeway. It returns
//! an [`AccessToken`] whose `S` parameter proves the scopes it holds. Declare scopes
//! with [`scopes!`]; [`AccessToken::require`] checks more later.
//!
//! An operation that needs a stronger or more recent sign-in checks a
//! [`StepUpRequirement`] with [`AccessToken::require_authentication`], by the same rule
//! auth applies. The resulting error's challenge asks the client to step up (RFC 9470),
//! and a client reads the requirement back from the challenge into its next
//! [`AuthorizeRequest`].
//!
//! # Signing users in
//!
//! [`Client`] runs the authorization code flow with PKCE:
//!
//! 1. [`Client::authorize`] gives the URL to redirect to, pushing the request first
//!    when auth advertises pushed authorization requests (RFC 9126), and a
//!    [`PendingLogin`] to keep server-side.
//! 2. [`Client::complete`] checks the callback, `state` then the RFC 9207 `iss`,
//!    before the code goes anywhere. It then validates the ID token against the
//!    pending login.
//! 3. [`Client::refresh`], [`Client::revoke`], [`Client::userinfo`] and
//!    [`Client::logout_url`] cover the rest of a session.
//!
//! When auth ends a session, it posts a logout token to the client's back-channel
//! logout URI; [`Client::logout_token`] validates it. The axum login routes receive
//! it and end the matching sessions.
//!
//! # Signing keys
//!
//! [`KeyCache`] caches a JWKS for any issuer. An unknown `kid` triggers one refetch,
//! fetches happen at most every 30 seconds, and the last good keys survive an outage
//! until 15 minutes past their freshness.
//! Each [`Issuer`] holds one for its own keys, and [`KeyCache::fixed`] holds a
//! [`KeySet`] that is never fetched, for pinned keys. [`Jws`] parses a token so it
//! can be checked by hand, as for Google ID tokens.
//!
//! # Errors
//!
//! Every error type has a `code()` returning the [`SdkError`] every SDK shares: a
//! category, and for most categories the check that failed. A resource server answers
//! a [`TokenError`] with [`TokenError::challenge`], the RFC 6750 or RFC 9470
//! `WWW-Authenticate` value.
//!
//! # Time and HTTP
//!
//! [`IssuerBuilder::clock`] injects a [`Clock`], so tests can pin time.
//! [`IssuerBuilder::http_client`] takes a `reqwest::ClientBuilder`, for proxies or
//! extra trusted roots. Whatever it sets, the SDK's transport policy holds: every
//! request is `https`, follows no redirect, and gives up after 10 seconds.
//!
//! Each request runs in an `http.client` `tracing` span, at `info` under the
//! `sourceorigin_common` target, with its method, host and status only, as OpenTelemetry's
//! HTTP client conventions name them.
//!
//! The behavior follows `docs/dev/architecture/sdk.md` in the sourceorigin repository, and is
//! tested against the shared vectors in `tests/sdk-vectors`.
// docs.rs labels feature-gated items with the features they need.
#![cfg_attr(docsrs, feature(doc_cfg))]

// Documented by its own inner docs, so their links resolve inside the module.
#[cfg(feature = "axum")]
pub mod axum;
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
pub use keys::{Jws, JwsHeader, KeyCache, KeyDefect, KeyError, KeySet};
pub use resource::{Resource, ResourceError, ResourceValidator};
pub use scope::{Scope, ScopeSet};
pub use token::{
    AccessToken, AuthenticationPolicy, IdToken, LogoutScope, LogoutToken, Subject, TokenError,
};

/// The wire types this SDK reads, shared with auth itself. Each item is re-exported
/// by name, so this list is the SDK's contract.
pub mod protocol {
    pub use sourceorigin_common::protocol::{
        challenge, claims, jwt, metadata, oauth, sdk, step_up,
    };
    pub use sourceorigin_common::{ClientId, DeliveryId, InvalidValue, SessionId, TokenId, UserId};
}
pub use protocol::{
    ClientId, SessionId, TokenId, UserId,
    claims::{
        Acr, Actor, Amr, Confirmation, IdTokenClaims, LogoutTokenClaims, ProfileClaims, UserInfo,
    },
    oauth::Scopes,
    sdk::SdkError,
    step_up::StepUpRequirement,
};

use chrono::{DateTime, TimeDelta, Utc};

/// Clock skew tolerated on `exp`, `nbf`, `iat` and `auth_time`. Auth tolerates the
/// same on `iat` alone, and none on `exp` or `max_age`.
const LEEWAY: TimeDelta = TimeDelta::seconds(30);

/// The time source for every expiry and cache check. Inject one with
/// [`IssuerBuilder::clock`] to pin time in tests.
///
/// ```
/// use chrono::{DateTime, TimeDelta, Utc};
/// use sourceorigin_auth::Clock;
///
/// /// A clock pinned to one instant, for tests.
/// struct Fixed(DateTime<Utc>);
///
/// impl Clock for Fixed {
///     fn now(&self) -> DateTime<Utc> {
///         self.0
///     }
/// }
///
/// let start = Utc::now();
/// let clock = Fixed(start + TimeDelta::minutes(5));
/// assert_eq!(clock.now() - start, TimeDelta::minutes(5));
/// // Inject it with `Issuer::builder().clock(clock)`.
/// ```
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
    pub use crate::{protocol::oauth::Scopes, scope::Declared};
}
