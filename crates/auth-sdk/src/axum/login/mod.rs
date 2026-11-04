//! Server-side login: the `/login`, `/callback`, `/logout` and `/backchannel-logout`
//! routes, the session layer, and the session extractors.

/// The extractors handlers take, and the step-up response.
mod extract;
/// The layer around the app's routes.
mod layer;
/// Reading the session, refreshing its access token.
mod refresh;
/// The `/login`, `/callback`, `/logout` and `/backchannel-logout` handlers.
mod routes;

pub use extract::{CrossOrigin, MaybeSignedIn, SignedIn, StepUp};
pub use layer::{LoginLayer, LoginService};

use super::{
    CookieKey, SessionBackend,
    bearer::ErrorChain,
    session::{BackendError, Sessions},
};
use crate::{Client, ClientId, Scopes, StepUpRequirement};
use axum::{
    Router,
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, TimeDelta, Utc};
use piquel_common::protocol::same_origin::BrowserRequest;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr, sync::Arc};
use url::Url;

/// How long the browser has to follow the redirect back after a step-up login.
const STEP_UP_RETURN: TimeDelta = TimeDelta::minutes(1);
/// How long a login may take at auth.
const PENDING_LIFETIME: TimeDelta = TimeDelta::minutes(10);
/// Default session lifetime.
const DEFAULT_SESSION_LIFETIME: TimeDelta = TimeDelta::hours(12);
/// Most bytes in a `return_to` path.
const MAX_RETURN_TO_BYTES: usize = 2048;
/// Most logins one browser may have in progress, one cookie each. A login started
/// beyond it drops the oldest.
const MAX_PENDING_LOGINS: usize = 3;
/// Most bytes in a pending login cookie's name and value. Browsers keep cookies of
/// up to 4096 bytes, attributes included; a login whose `return_to` would outgrow it
/// returns to the home page instead.
const MAX_PENDING_COOKIE_BYTES: usize = 4000;
/// Most bytes in all of a browser's pending login cookies together, the new one
/// included: common proxies refuse a `Cookie` header over 8 KiB, which the session
/// and the app's own cookies share. A login started beyond it drops the oldest.
const MAX_PENDING_BYTES: usize = 6000;
/// Longest `state` a pending login's cookie is named for; the SDK's are 43 bytes.
const MAX_STATE_BYTES: usize = 64;

/// The names of the login routes' cookies. Each carries the client ID, so apps
/// sharing a host keep their own. `__Host-` makes browsers require `Secure`,
/// `Path=/` and no `Domain`, so no other host can set or read them.
#[derive(Clone, Debug)]
struct CookieNames {
    /// Holds the session key.
    session: String,
    /// Names, in base64url, the page a step-up login returns to, so that page's
    /// request is known to be the retry.
    step_up: String,
    /// Starts the name of each pending login's cookie, which ends with its `state`,
    /// so logins started together in several tabs do not overwrite each other.
    pending: String,
}

impl CookieNames {
    /// The names for `client`, whose IDs are letters, digits, `.`, `_` and `-`, all
    /// valid in a cookie name.
    fn new(client: &ClientId) -> Self {
        let prefix = format!("__Host-piquel-{client}");
        Self {
            session: format!("{prefix}-session"),
            step_up: format!("{prefix}-step-up"),
            pending: format!("{prefix}-login-"),
        }
    }

    /// The name of the cookie holding the login started with `state`, if `state` has
    /// the shape the SDK sends: base64url, at most 64 bytes.
    fn pending(&self, state: &str) -> Option<String> {
        let valid = (1..=MAX_STATE_BYTES).contains(&state.len())
            && state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        valid.then(|| format!("{}{state}", self.pending))
    }
}

/// A path on this app to send the user back to: same-origin and relative, so login
/// cannot be turned into an open redirect. It starts with one `/` (not `//` or
/// `/\`), and has no `\`, `#` or control characters.
///
/// ```
/// use piquel_auth::axum::ReturnTo;
///
/// assert!("/notes?page=2".parse::<ReturnTo>().is_ok());
/// // Another site, protocol-relative or not, is refused.
/// assert!("https://evil.example".parse::<ReturnTo>().is_err());
/// assert!("//evil.example".parse::<ReturnTo>().is_err());
/// assert!("/\\evil.example".parse::<ReturnTo>().is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReturnTo(String);

/// A `return_to` that is not a same-origin relative path.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("return_to must be a same-origin path")]
pub struct InvalidReturnTo;

impl ReturnTo {
    /// The site root.
    #[must_use]
    pub fn root() -> Self {
        Self("/".into())
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ReturnTo {
    type Err = InvalidReturnTo;
    /// Accepts only same-origin relative paths.
    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let local = path.len() <= MAX_RETURN_TO_BYTES
            && path.starts_with('/')
            && !path[1..].starts_with(['/', '\\'])
            && !path
                .chars()
                .any(|character| matches!(character, '\\' | '#') || character.is_control());
        local.then(|| Self(path.to_owned())).ok_or(InvalidReturnTo)
    }
}

impl TryFrom<String> for ReturnTo {
    type Error = InvalidReturnTo;
    /// Same as `parse`.
    fn try_from(path: String) -> Result<Self, Self::Error> {
        path.parse()
    }
}

impl From<ReturnTo> for String {
    /// The path.
    fn from(path: ReturnTo) -> Self {
        path.0
    }
}

/// Everything the routes, the layer and the extractors share.
#[derive(Clone)]
struct Login {
    /// The client users sign in with.
    client: Client,
    /// Where sessions live.
    sessions: Sessions,
    /// Seals the pending logins the browser keeps.
    cookie_key: Arc<CookieKey>,
    /// The cookies' names.
    cookies: CookieNames,
    /// Scopes requested besides `openid`.
    scopes: Scopes,
    /// Where users go after login when no `return_to` was given, and after logout
    /// without a session.
    home: ReturnTo,
    /// Where auth sends users after logout; must be registered for the client.
    after_logout: Option<Url>,
    /// Where [`LoginRoutes::router`] is nested.
    mount: String,
    /// How long a session lasts.
    lifetime: TimeDelta,
}

/// Server-side login for apps: the routes, and the layer the session extractors need.
///
/// - `GET /login?return_to=…` keeps a pending login in a cookie named for its
///   `state`, sealed with the [`CookieKey`], and redirects to auth, pushing the
///   request first when auth advertises it ([`Client::authorize`]). It writes
///   nothing to the backend, and answers 502 if the push fails. Each tab's login has
///   its own cookie, so logins started together all complete; a browser keeps at
///   most three, dropping the oldest.
/// - `GET /callback` completes the login its `state` names, then starts a session
///   under a fresh random key, ending any session the browser already had.
/// - `POST /logout` deletes the session and redirects to RP-initiated logout.
/// - `POST /backchannel-logout` receives auth's logout tokens (OIDC Back-Channel
///   Logout 1.0) and deletes the sessions they name: every session started under the
///   token's `sid`, or without one, every session of its `sub`. Register
///   `https://<app><mount>/backchannel-logout` as the client's back-channel logout
///   URI. It answers 200 once the sessions are gone, also for a token it applied
///   before, which auth sends again when it lost the answer; 400 with
///   `{"error":"invalid_request"}` for an invalid token; 503 when auth's keys cannot
///   be fetched and 500 when the backend fails, so auth retries those.
///
/// Mount the router at `/auth`, or tell [`Self::mounted_at`], and add
/// [`Self::layer`] around every route that uses [`SignedIn`] or [`MaybeSignedIn`].
///
/// ```no_run
/// # async fn run(issuer: piquel_auth::Issuer, backend: piquel_auth::axum::MemoryBackend) -> Result<(), Box<dyn std::error::Error>> {
/// use axum::{Router, routing::get};
/// use chrono::TimeDelta;
/// use piquel_auth::{
///     ClientConfig, Credentials,
///     axum::{CookieKey, LoginRoutes, SignedIn},
/// };
///
/// async fn home(user: SignedIn) -> String {
///     format!("Hello {}", user.name())
/// }
///
/// let client = issuer.client(ClientConfig {
///     client_id: "notes-web".parse()?,
///     credentials: Credentials::Secret(std::env::var("NOTES_CLIENT_SECRET")?.into()),
///     // The callback route below, as registered with auth.
///     redirect_uri: "https://notes.piquel.fr/account/callback".parse()?,
/// });
/// // The same key on every replica, kept like the client secret.
/// let key = CookieKey::from_base64(&std::env::var("NOTES_COOKIE_KEY")?)?;
/// let auth = LoginRoutes::new(client, backend, key)
///     .scopes("profile offline_access".parse()?)
///     .after_login("/notes".parse()?)
///     .after_logout("https://notes.piquel.fr/".parse()?)
///     .mounted_at("/account")
///     .session_lifetime(TimeDelta::days(7));
/// let app: Router = Router::new()
///     .route("/notes", get(home))
///     .nest("/account", auth.router())
///     .layer(auth.layer());
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct LoginRoutes(Login);

impl fmt::Debug for LoginRoutes {
    /// Names the client and mount point.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRoutes")
            .field("client", &self.0.client)
            .field("mount", &self.0.mount)
            .finish_non_exhaustive()
    }
}

impl LoginRoutes {
    /// Login with `client`, keeping sessions in `backend` and sealing pending logins
    /// with `cookie_key`.
    #[must_use]
    pub fn new(client: Client, backend: impl SessionBackend, cookie_key: CookieKey) -> Self {
        let id = &client.config().client_id;
        Self(Login {
            sessions: Sessions::new(backend, id.clone()),
            cookie_key: Arc::new(cookie_key),
            cookies: CookieNames::new(id),
            client,
            scopes: Scopes::default(),
            home: ReturnTo::root(),
            after_logout: None,
            mount: "/auth".into(),
            lifetime: DEFAULT_SESSION_LIFETIME,
        })
    }

    /// Requests `scopes` besides `openid`. Add `offline_access` to refresh access
    /// tokens in the session.
    #[must_use]
    pub fn scopes(mut self, scopes: Scopes) -> Self {
        self.0.scopes = scopes;
        self
    }

    /// Where users go after login when they came from no page; `/` by default.
    #[must_use]
    pub fn after_login(mut self, path: ReturnTo) -> Self {
        self.0.home = path;
        self
    }

    /// Where auth sends users after logout. It must be a registered post-logout URI
    /// of the client; without one, auth shows its own page.
    #[must_use]
    pub fn after_logout(mut self, url: Url) -> Self {
        self.0.after_logout = Some(url);
        self
    }

    /// Where [`Self::router`] is nested; `/auth` by default.
    #[must_use]
    pub fn mounted_at(mut self, path: impl Into<String>) -> Self {
        self.0.mount = path.into();
        self
    }

    /// How long a session lasts; 12 hours by default.
    #[must_use]
    pub fn session_lifetime(mut self, lifetime: TimeDelta) -> Self {
        self.0.lifetime = lifetime;
        self
    }

    /// The routes, to nest at the mount point.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/login", get(Login::start))
            .route("/callback", get(Login::callback))
            .route("/logout", post(Login::logout))
            .route("/backchannel-logout", post(Login::backchannel_logout))
            .with_state(Arc::new(self.0.clone()))
    }

    /// The layer [`SignedIn`] and [`MaybeSignedIn`] need, which also turns
    /// [`StepUp`] responses into redirects through login.
    #[must_use]
    pub fn layer(&self) -> LoginLayer {
        LoginLayer(Arc::new(self.0.clone()))
    }
}

impl Login {
    /// The request's cookies, as name and value.
    fn cookies(headers: &HeaderMap) -> impl Iterator<Item = (&str, &str)> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
    }

    /// Reads a cookie from the request.
    fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
        Self::cookies(headers).find_map(|(key, value)| (key == name).then_some(value))
    }

    /// A `Set-Cookie` value for a host-only, script-inaccessible cookie; zero
    /// `max_age` deletes it.
    fn set_cookie(name: &str, value: &str, max_age: TimeDelta) -> HeaderValue {
        let cookie = format!(
            "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            max_age.num_seconds().max(0)
        );
        // Names are made of client ID and base64url characters, and values are
        // base64url, so the header is always valid.
        HeaderValue::try_from(cookie).unwrap_or(HeaderValue::from_static(""))
    }

    /// Logs a backend failure and answers 500.
    fn store_failure(error: &BackendError) -> Response {
        tracing::error!(error = %ErrorChain(error.as_ref()), "session backend failed");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }

    /// The current time by the issuer's clock.
    fn now(&self) -> DateTime<Utc> {
        self.client.issuer().now()
    }

    /// The login route's URL, returning to `return_to`, and stepping up for
    /// `step_up` when given.
    fn login_url(
        &self,
        return_to: Option<&ReturnTo>,
        step_up: Option<StepUpRequirement>,
    ) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(path) = return_to {
            query.append_pair("return_to", path.as_str());
        }
        if let Some(requirement) = step_up {
            for (name, value) in requirement.authorize_params() {
                query.append_pair(name, &value);
            }
            query.append_pair("step_up", "true");
        }
        format!(
            "{}/login?{}",
            self.mount.trim_end_matches('/'),
            query.finish()
        )
    }

    /// Whether a browser request comes from this app's own pages, whose origin is the
    /// client's redirect URI's ([`BrowserRequest::is_same_origin`]).
    fn same_origin(&self, headers: &HeaderMap) -> bool {
        let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
        BrowserRequest {
            fetch_site: text("sec-fetch-site"),
            origin: text(header::ORIGIN.as_str()),
        }
        .is_same_origin(&self.client.config().redirect_uri.origin())
    }

    /// The 403 for a request that is not a safe method (`GET`, `HEAD`, `OPTIONS`,
    /// `TRACE`) from another origin's pages, so no other site, not even a sibling the
    /// `SameSite=Lax` cookie reaches, acts as the user. `None` lets the request
    /// through; without [`LoginLayer`], reading the session answers 500 instead.
    fn refuse_other_origin(parts: &Parts) -> Option<Response> {
        let login = parts.extensions.get::<Arc<Self>>()?;
        (!parts.method.is_safe() && !login.same_origin(&parts.headers)).then(|| {
            (
                StatusCode::FORBIDDEN,
                "This request must come from this site's own pages.",
            )
                .into_response()
        })
    }
}
