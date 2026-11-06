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

use super::{BoxFuture, CookieKey, bearer::ErrorChain, seal::SealError, session::StoredLogin};
use crate::{Client, ClientId, Credentials, LogoutToken, Scopes, StepUpRequirement};
use axum::{
    Router,
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use layer::RequestSession;
use piquel_common::protocol::same_origin::BrowserRequest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future, str::FromStr, sync::Arc};
use url::Url;

/// How long the browser has to follow the redirect back after a step-up login.
const STEP_UP_RETURN: TimeDelta = TimeDelta::minutes(1);
/// How long a login may take at auth.
const PENDING_LIFETIME: TimeDelta = TimeDelta::minutes(10);
/// Default session lifetime.
const DEFAULT_SESSION_LIFETIME: TimeDelta = TimeDelta::hours(12);
/// Most bytes in a `return_to` path.
const MAX_RETURN_TO_BYTES: usize = 2048;
/// Most bytes in a cookie's name, `=` and value: browsers drop larger cookies.
const MAX_COOKIE_BYTES: usize = 4096;
/// Cookie slots for logins in progress: each login waits in the slot its `state`
/// hashes to, replacing any login there. Responses to logins started at once cannot
/// see each other's cookies, so only fixed slots bound how many a browser keeps.
const PENDING_SLOTS: u8 = 3;
/// Most bytes in one pending login cookie's name and value, so all slots together
/// take at most 3000 bytes. Common proxies refuse a `Cookie` header over 8 KiB, which
/// they share with the session, up to 4 KiB, and the app's own cookies. A login
/// whose `return_to` would outgrow it returns to the home page instead.
const MAX_PENDING_COOKIE_BYTES: usize = 1000;

/// The names of the login routes' cookies. Each carries the client ID, so apps
/// sharing a host keep their own. `__Host-` makes browsers require `Secure`,
/// `Path=/` and no `Domain`, so no other host can set or read them.
#[derive(Clone, Debug)]
struct CookieNames {
    /// Holds the sealed session.
    session: String,
    /// Names the page a step-up login returns to, by the base64url of its SHA-256 so
    /// it stays small, so that page's request is known to be the retry.
    step_up: String,
    /// Starts the name of each pending login's cookie, which ends with its slot.
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

    /// The name of the cookie holding the login started with `state`: its slot, by
    /// the first byte of the `state`'s SHA-256.
    fn pending(&self, state: &str) -> String {
        let slot = Sha256::digest(state)[0] % PENDING_SLOTS;
        format!("{}{slot}", self.pending)
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

/// The login routes were given a public client.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "the login routes need a confidential client: every copy of the session cookie \
     redeems the same refresh token, which only a confidential client's keeps"
)]
pub struct PublicClient;

/// Any failure a back-channel logout handler reports.
type HandlerError = Box<dyn std::error::Error + Send + Sync>;
/// The app's back-channel logout handler, once erased.
type LogoutHandler = Arc<dyn Fn(LogoutToken) -> BoxFuture<Result<(), HandlerError>> + Send + Sync>;

/// Everything the routes, the layer and the extractors share.
#[derive(Clone)]
pub(super) struct Login {
    /// The client users sign in with.
    client: Client,
    /// Seals the session and the pending logins the browser keeps.
    cookie_key: Arc<CookieKey>,
    /// The cookies' names.
    cookies: CookieNames,
    /// Scopes requested besides `openid` and `offline_access`.
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
    /// What receives back-channel logouts, if the app handles them.
    on_logout: Option<LogoutHandler>,
}

/// Server-side login for apps: the routes, and the layer the session extractors need.
/// Sessions live in the browser, in a cookie sealed with the [`CookieKey`], so the app
/// stores nothing.
///
/// - `GET /login?return_to=…` keeps a pending login in a cookie named for its
///   `state`, sealed with the [`CookieKey`], and redirects to auth, pushing the
///   request first when auth advertises it ([`Client::authorize`]). It answers 502 if
///   the push fails. A browser keeps up to three logins at once, in slots chosen by
///   their `state`; a login that lands in a taken slot replaces the one there.
/// - `GET /callback` completes the login its `state` names and starts a session,
///   first revoking the refresh token of the session it replaces.
/// - `POST /logout` revokes the session's refresh token at auth, clears the cookie,
///   and redirects to RP-initiated logout.
/// - `POST /backchannel-logout`, only with [`Self::on_backchannel_logout`].
///
/// The routes always request `offline_access`: a session learns that auth ended it,
/// at a logout, an app removal or an account suspension, when its next refresh is
/// refused, within an access token's 5 minutes. A sign-in auth gives no refresh token
/// lasts as long as its access token.
///
/// Mount the router at `/auth`, or tell [`Self::mounted_at`], and add
/// [`Self::layer`] around every route that uses [`SignedIn`] or [`MaybeSignedIn`].
///
/// ```no_run
/// # async fn run(issuer: piquel_auth::Issuer) -> Result<(), Box<dyn std::error::Error>> {
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
/// let auth = LoginRoutes::new(client, key)?
///     .scopes("profile".parse()?)
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
pub struct LoginRoutes(pub(super) Login);

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
    /// Login with `client`, sealing the browser's cookies with `cookie_key`.
    ///
    /// # Errors
    /// [`PublicClient`] if `client` has no secret: a public client's refresh token
    /// rotates, so two requests refreshing the same session would revoke it.
    pub fn new(client: Client, cookie_key: CookieKey) -> Result<Self, PublicClient> {
        if matches!(client.config().credentials, Credentials::None) {
            return Err(PublicClient);
        }
        Ok(Self(Login {
            cookies: CookieNames::new(&client.config().client_id),
            client,
            cookie_key: Arc::new(cookie_key),
            scopes: Scopes::default(),
            home: ReturnTo::root(),
            after_logout: None,
            mount: "/auth".into(),
            lifetime: DEFAULT_SESSION_LIFETIME,
            on_logout: None,
        }))
    }

    /// Requests `scopes` besides `openid` and `offline_access`, which every login
    /// requests.
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

    /// How long a session lasts at most; 12 hours by default. Auth may end it sooner.
    #[must_use]
    pub fn session_lifetime(mut self, lifetime: TimeDelta) -> Self {
        self.0.lifetime = lifetime;
        self
    }

    /// Receives auth's back-channel logouts (OIDC Back-Channel Logout 1.0) at
    /// `POST <mount>/backchannel-logout`, for an app that must end sessions sooner
    /// than their next refresh. Register `https://<app><mount>/backchannel-logout` as
    /// the client's back-channel logout URI.
    ///
    /// The route validates the logout token and hands it to `handler`. The SDK keeps
    /// no sessions, so the handler records what the token names, its
    /// [`scope`](LogoutToken::scope), where every replica sees it, and the app
    /// refuses those sessions itself: by [`SignedIn::sid`] for an auth session, or for
    /// a logout naming only the user, every session of [`SignedIn::subject`] whose
    /// sign-in (`auth_time`) came before the token was issued. A record can go once
    /// no session it names can still be live, a [session
    /// lifetime](Self::session_lifetime) after the token.
    ///
    /// The handler must be idempotent and return only once its record is durable:
    /// auth retries a delivery until it is answered 200, so a token can arrive twice,
    /// and an error answers 500 for auth to retry. The route answers 200 once the
    /// handler succeeds; 400 with `{"error":"invalid_request"}` for an invalid token;
    /// and 503 when auth's keys cannot be fetched.
    ///
    /// ```no_run
    /// # fn run(auth: piquel_auth::axum::LoginRoutes) {
    /// use piquel_auth::{LogoutScope, SessionId};
    /// use std::{collections::HashSet, convert::Infallible, sync::{Arc, Mutex}};
    ///
    /// // Kept in the app's database in practice, so every replica sees it.
    /// let ended: Arc<Mutex<HashSet<SessionId>>> = Arc::default();
    /// let recorded = ended.clone();
    /// let auth = auth.on_backchannel_logout(move |logout| {
    ///     if let LogoutScope::Session(sid) = logout.scope() {
    ///         recorded.lock().unwrap().insert(*sid);
    ///     }
    ///     async { Ok::<_, Infallible>(()) }
    /// });
    /// // Then refuse `user.sid()` in `ended`, for example in a middleware.
    /// # }
    /// ```
    #[must_use]
    pub fn on_backchannel_logout<F, Fut, E>(mut self, handler: F) -> Self
    where
        F: Fn(LogoutToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.0.on_logout = Some(Arc::new(move |token| {
            let logged_out = handler(token);
            Box::pin(async move { logged_out.await.map_err(Into::into) })
        }));
        self
    }

    /// The routes, to nest at the mount point.
    pub fn router(&self) -> Router {
        let mut router = Router::new()
            .route("/login", get(Login::start))
            .route("/callback", get(Login::callback))
            .route("/logout", post(Login::logout));
        if self.0.on_logout.is_some() {
            router = router.route("/backchannel-logout", post(Login::backchannel_logout));
        }
        router.with_state(Arc::new(self.0.clone()))
    }

    /// The layer [`SignedIn`] and [`MaybeSignedIn`] need. It sets the refreshed
    /// session's cookie on the response, and turns [`StepUp`] responses into
    /// redirects through login.
    #[must_use]
    pub fn layer(&self) -> LoginLayer {
        LoginLayer(Arc::new(self.0.clone()))
    }
}

/// What the request's session cookie holds.
pub(super) enum SessionCookie {
    /// No session cookie.
    Absent,
    /// A cookie that does not open, perhaps sealed under an older key, or whose
    /// session ended: the response should clear it.
    Ended,
    /// A live session.
    Open(Box<StoredLogin>),
}

/// A session that could not be put in its cookie.
#[derive(Debug, thiserror::Error)]
pub(super) enum SessionCookieError {
    /// The session did not seal.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// The sealed session is larger than browsers keep.
    #[error("the session cookie would be {0} bytes; browsers keep {MAX_COOKIE_BYTES} at most")]
    TooLarge(usize),
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

    /// The step-up marker naming the page at `path`.
    fn step_up_marker(path: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(path))
    }

    /// The `Set-Cookie` value deleting cookie `name`.
    fn clear_cookie(name: &str) -> HeaderValue {
        Self::set_cookie(name, "", TimeDelta::zero())
    }

    /// The associated data of cookie `name`: the client ID and the name, so a cookie
    /// opens only as the cookie it was sealed as, and only for this client, even when
    /// another app on the host shares the cookie key.
    fn context(&self, name: &str) -> String {
        format!("{}\0{name}", self.client.config().client_id)
    }

    /// The session the request's cookie holds.
    pub(super) fn open_session(&self, headers: &HeaderMap) -> SessionCookie {
        let name = &self.cookies.session;
        let Some(sealed) = Self::cookie(headers, name) else {
            return SessionCookie::Absent;
        };
        let opened = self.cookie_key.session.open(sealed, &self.context(name));
        match opened.map(StoredLogin) {
            Some(login) if login.ends_at() > self.now() => SessionCookie::Open(Box::new(login)),
            _ => SessionCookie::Ended,
        }
    }

    /// The `Set-Cookie` value holding `login`, sealed, until the session ends.
    pub(super) fn session_cookie(
        &self,
        login: &StoredLogin,
    ) -> Result<HeaderValue, SessionCookieError> {
        let name = &self.cookies.session;
        let sealed = self
            .cookie_key
            .session
            .seal(&login.0, &self.context(name))?;
        let size = name.len() + 1 + sealed.len();
        if size > MAX_COOKIE_BYTES {
            return Err(SessionCookieError::TooLarge(size));
        }
        Ok(Self::set_cookie(
            name,
            &sealed,
            login.ends_at() - self.now(),
        ))
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
        let request = parts.extensions.get::<Arc<RequestSession>>()?;
        (!parts.method.is_safe() && !request.login.same_origin(&parts.headers)).then(|| {
            (
                StatusCode::FORBIDDEN,
                "This request must come from this site's own pages.",
            )
                .into_response()
        })
    }

    /// Logs `error` and answers 500.
    fn failure(error: &dyn std::error::Error, message: &'static str) -> Response {
        tracing::error!(error = %ErrorChain(error), "{message}");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}
