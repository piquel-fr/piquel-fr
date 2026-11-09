//! axum integration, behind the `axum` feature.
//!
//! **Resource servers** add a [`BearerLayer`], then take [`Authenticated`],
//! [`Scoped`] or [`RequireAuthentication`] in handlers. Rejections answer with the
//! RFC 6750 or RFC 9470 challenge for what the handler enforces.
//!
//! ```no_run
//! use axum::{Json, Router, routing::get};
//! use sourceorigin_auth::axum::{BearerLayer, Scoped};
//! # use sourceorigin_auth::{Issuer, Resource};
//!
//! sourceorigin_auth::scopes! {
//!     /// Scopes of the notes API.
//!     pub mod notes {
//!         Read = "notes:read",
//!         Write = "notes:write",
//!     }
//! }
//!
//! async fn list(Scoped(token): Scoped<notes::Read>) -> Json<Vec<String>> {
//!     Json(vec![format!("notes of {:?}", token.subject())])
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let issuer = Issuer::discover("https://auth.sourceorigin.dev").await?;
//! let app: Router = Router::new()
//!     .route("/notes", get(list))
//!     .layer(BearerLayer::new(issuer.resource(Resource::new("notes-api")?)));
//! # Ok(()) }
//! ```
//!
//! **Apps that sign users in** mount [`LoginRoutes`] and its layer, then take
//! [`SignedIn`] or [`MaybeSignedIn`]. The session lives in the browser, in a cookie
//! sealed with the app's [`CookieKey`], so the app stores nothing and implements
//! nothing; the layer refreshes the access token and sets the new cookie. Both refuse
//! a request that is not `GET`, `HEAD`, `OPTIONS` or `TRACE` unless it comes from
//! the app's own pages, so handlers need no CSRF token; [`CrossOrigin`] opts an
//! endpoint out.
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use sourceorigin_auth::axum::{CookieKey, LoginRoutes, SignedIn};
//! # use sourceorigin_auth::{ClientConfig, Credentials, Issuer};
//!
//! async fn home(user: SignedIn) -> String {
//!     format!("Hello {}", user.name())
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! # let issuer = Issuer::discover("https://auth.sourceorigin.dev").await?;
//! # let config = ClientConfig {
//! #     client_id: "notes-web".parse()?,
//! #     credentials: Credentials::Secret(std::env::var("NOTES_CLIENT_SECRET")?.into()),
//! #     redirect_uri: "https://notes.sourceorigin.dev/auth/callback".parse()?,
//! # };
//! // The same key on every replica: `openssl rand -base64 32`.
//! let key = CookieKey::from_base64(&std::env::var("NOTES_COOKIE_KEY")?)?;
//! let auth = LoginRoutes::new(issuer.client(config), key)?
//!     .scopes("profile".parse()?)
//!     .after_login("/notes".parse()?);
//! let app: Router = Router::new()
//!     .route("/", get(home))
//!     .nest("/auth", auth.router())
//!     .layer(auth.layer());
//! # Ok(()) }
//! ```
//!
//! **Logout.** Auth revokes an app's refresh token when the user signs out there,
//! removes the app, or loses the account, and the session ends at its next refresh,
//! within an access token's 5 minutes. An app that must end sessions sooner handles
//! back-channel logout with [`LoginRoutes::on_backchannel_logout`].
//!
//! **Step-up.** A page that needs a stronger or more recent sign-in returns the
//! [`StepUp`] from [`SignedIn::require`], and one calling an API answers the API's
//! `insufficient_user_authentication` challenge with [`SignedIn::step_up`]. The layer
//! redirects a browser's navigation through login with what is needed and back to
//! the same page, which retries once: a login that falls short fails, and a step-up
//! asked for again on the return answers 403 instead of another redirect. Any other
//! request, a `fetch` included, gets the 401, as it does without a session.

/// Bearer token validation for resource servers.
mod bearer;
/// Server-side login routes and session extractors.
mod login;
/// Sealing the browser's cookies.
mod seal;
/// What the browser's cookies hold.
mod session;
#[cfg(test)]
mod tests;

pub use bearer::{
    AuthRejection, Authenticated, BearerLayer, BearerService, RequireAuthentication, Scoped,
};
pub use login::{
    CrossOrigin, InvalidReturnTo, LoginLayer, LoginRoutes, LoginService, MaybeSignedIn,
    PublicClient, ReturnTo, SignedIn, StepUp,
};
pub use seal::{CookieKey, CookieKeyError};
pub use session::StoredLogin;

use std::{future::Future, pin::Pin};

/// A boxed, sendable future, as the layers' services return.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
