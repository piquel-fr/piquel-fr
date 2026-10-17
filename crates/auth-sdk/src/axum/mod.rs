//! axum integration, behind the `axum` feature.
//!
//! **Resource servers** add a [`BearerLayer`], then take [`Authenticated`],
//! [`Scoped`] or [`RequireAuthentication`] in handlers. Rejections answer with the
//! RFC 6750 or RFC 9470 challenge for what the handler enforces.
//!
//! ```no_run
//! use axum::{Json, Router, routing::get};
//! use piquel_auth::axum::{BearerLayer, Scoped};
//! # use piquel_auth::{Issuer, Resource};
//!
//! piquel_auth::scopes! {
//!     /// Scopes of the notes API.
//!     pub mod notes {
//!         Read = "notes:read",
//!         Write = "notes:write",
//!     }
//! }
//!
//! async fn list(Scoped(token): Scoped<notes::Read>) -> Json<Vec<String>> {
//!     Json(vec![format!("notes of {:?}", token.subject)])
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let issuer = Issuer::discover("https://auth.piquel.fr").await?;
//! let app: Router = Router::new()
//!     .route("/notes", get(list))
//!     .layer(BearerLayer::new(issuer.resource(Resource::new("notes-api")?)));
//! # Ok(()) }
//! ```
//!
//! **Apps that sign users in** mount [`LoginRoutes`] and its layer, then take
//! [`SignedIn`] or [`MaybeSignedIn`]. Tokens stay in a server-side
//! [`SessionStore`]; the browser holds only a random session key.
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use piquel_auth::axum::{LoginRoutes, MemorySessions, SignedIn};
//! # use piquel_auth::{ClientConfig, ClientId, Credentials, Issuer};
//!
//! async fn home(user: SignedIn) -> String {
//!     format!("Hello {}", user.name())
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! # let issuer = Issuer::discover("https://auth.piquel.fr").await?;
//! # let config = ClientConfig {
//! #     client_id: ClientId::new("notes-web"),
//! #     credentials: Credentials::None,
//! #     redirect_uri: "https://notes.piquel.fr/auth/callback".parse()?,
//! # };
//! let auth = LoginRoutes::new(issuer.client(config), MemorySessions::default())
//!     .scopes("profile".parse()?)
//!     .after_login("/notes".parse()?);
//! let app: Router = Router::new()
//!     .route("/", get(home))
//!     .nest("/auth", auth.router())
//!     .layer(auth.layer());
//! # Ok(()) }
//! ```

/// Bearer token validation for resource servers.
mod bearer;
/// Server-side login routes and session extractors.
mod login;
/// The PostgreSQL session store.
#[cfg(feature = "postgres")]
mod postgres;
/// Session storage.
mod session;
#[cfg(test)]
mod tests;

pub use bearer::{
    AuthRejection, Authenticated, BearerLayer, BearerService, RequireAuthentication, Scoped,
};
pub use login::{
    InvalidReturnTo, LoginLayer, LoginRoutes, LoginService, MaybeSignedIn, ReturnTo, SignedIn,
    StepUp,
};
#[cfg(feature = "postgres")]
pub use postgres::PostgresSessions;
pub use session::{
    BackchannelLogout, Lease, LeaseId, LogoutTarget, MemorySessions, PendingAuthorization,
    SessionKey, SessionStore, StoredLogin, Versioned,
};

use std::{future::Future, pin::Pin};

/// A boxed, sendable future, as the layers' services return.
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
