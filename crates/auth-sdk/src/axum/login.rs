//! Server-side login: the `/login`, `/callback` and `/logout` routes, the session
//! layer, and the session extractors.

use super::{
    BoxFuture, SessionBackend, StoredLogin,
    bearer::ErrorChain,
    session::{BackendError, Lease, LeaseId, PendingAuthorization, Session, SessionKey, Sessions},
};
use crate::{
    Acr, AuthenticationPolicy, AuthorizeRequest, CallbackParams, Client, IdToken, Scopes,
    TokenError, UserId,
};
use axum::{
    Extension, Router,
    extract::{FromRequestParts, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tower::{Layer, Service};
use url::Url;

/// Cookie holding the session key. `__Host-` makes browsers require `Secure`,
/// `Path=/` and no `Domain`, so no other host can set or read it.
const SESSION_COOKIE: &str = "__Host-piquel-session";
/// Cookie holding the pending login's key while the browser is at auth.
const LOGIN_COOKIE: &str = "__Host-piquel-login";
/// How long a login may take at auth.
const PENDING_LIFETIME: TimeDelta = TimeDelta::minutes(10);
/// Default session lifetime.
const DEFAULT_SESSION_LIFETIME: TimeDelta = TimeDelta::hours(12);
/// Access tokens this close to expiry are refreshed first.
const REFRESH_MARGIN: TimeDelta = TimeDelta::seconds(30);
/// Longest a refresh may take, auth's response and its ID token check included.
/// Shorter than the lease, so a lease never expires while its holder still refreshes.
const REFRESH_DEADLINE: Duration = Duration::from_secs(20);
/// How long a refresh lease lasts if its holder never releases it.
const REFRESH_LEASE: Duration = Duration::from_secs(60);
/// How long a request waits for another's refresh before using what it has.
const REFRESH_WAIT: Duration = Duration::from_secs(25);
/// How often a request waiting for another's refresh reloads the session.
const REFRESH_POLL: Duration = Duration::from_millis(50);
/// Most bytes in a `return_to` path.
const MAX_RETURN_TO_BYTES: usize = 2048;

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
/// - `GET /login?return_to=…` stores a pending login under a fresh random key and
///   redirects to auth.
/// - `GET /callback` completes it, then starts a session under another fresh key,
///   ending any session the browser already had.
/// - `POST /logout` deletes the session and redirects to RP-initiated logout.
///
/// Mount the router at `/auth`, or tell [`Self::mounted_at`], and add
/// [`Self::layer`] around every route that uses [`SignedIn`] or [`MaybeSignedIn`].
///
/// ```no_run
/// # async fn run(issuer: piquel_auth::Issuer, backend: piquel_auth::axum::MemoryBackend) -> Result<(), Box<dyn std::error::Error>> {
/// use axum::{Router, routing::get};
/// use chrono::TimeDelta;
/// use piquel_auth::{
///     ClientConfig, ClientId, Credentials,
///     axum::{LoginRoutes, SignedIn},
/// };
///
/// async fn home(user: SignedIn) -> String {
///     format!("Hello {}", user.name())
/// }
///
/// let client = issuer.client(ClientConfig {
///     client_id: ClientId::new("notes-web"),
///     credentials: Credentials::Secret(std::env::var("NOTES_CLIENT_SECRET")?.into()),
///     // The callback route below, as registered with auth.
///     redirect_uri: "https://notes.piquel.fr/account/callback".parse()?,
/// });
/// let auth = LoginRoutes::new(client, backend)
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
    /// Login with `client`, keeping sessions in `backend`.
    #[must_use]
    pub fn new(client: Client, backend: impl SessionBackend) -> Self {
        Self(Login {
            client,
            sessions: Sessions::new(backend),
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
            .with_state(Arc::new(self.0.clone()))
    }

    /// The layer [`SignedIn`] and [`MaybeSignedIn`] need, which also turns
    /// [`StepUp`] responses into redirects through login.
    #[must_use]
    pub fn layer(&self) -> LoginLayer {
        LoginLayer(Arc::new(self.0.clone()))
    }
}

/// The query of `GET /login`.
#[derive(Deserialize)]
struct StartQuery {
    /// Where to go once signed in.
    return_to: Option<String>,
    /// Longest acceptable time since the user authenticated, for step-up.
    max_age: Option<u64>,
    /// Required authentication context classes, for step-up.
    acr_values: Option<String>,
}

impl Login {
    /// Reads a cookie from the request.
    fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .find_map(|pair| {
                let (key, value) = pair.trim().split_once('=')?;
                (key == name).then_some(value)
            })
    }

    /// A `Set-Cookie` value for a host-only, script-inaccessible cookie; zero
    /// `max_age` deletes it.
    fn set_cookie(name: &str, value: &str, max_age: TimeDelta) -> HeaderValue {
        let cookie = format!(
            "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            max_age.num_seconds().max(0)
        );
        // Names are constants and values base64url, so the header is always valid.
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

    /// The login route's URL, returning to `return_to`, and asking for `step_up`.
    fn login_url(&self, return_to: Option<&ReturnTo>, step_up: Option<&StepUp>) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(path) = return_to {
            query.append_pair("return_to", path.as_str());
        }
        if let Some(step_up) = step_up {
            if let Some(max_age) = step_up.max_age {
                query.append_pair("max_age", &max_age.to_string());
            }
            if let Some(acr) = &step_up.acr {
                query.append_pair("acr_values", acr.as_str());
            }
        }
        format!(
            "{}/login?{}",
            self.mount.trim_end_matches('/'),
            query.finish()
        )
    }

    /// `GET /login`: stores a pending login and redirects to auth.
    async fn start(State(login): State<Arc<Self>>, Query(query): Query<StartQuery>) -> Response {
        let return_to = query
            .return_to
            .and_then(|path| path.parse().ok())
            .unwrap_or_else(|| login.home.clone());
        let request = AuthorizeRequest {
            scopes: login.scopes.clone(),
            max_age: query.max_age,
            acr_values: query
                .acr_values
                .iter()
                .flat_map(|values| values.split_ascii_whitespace())
                .map(Acr::from)
                .collect(),
            ..AuthorizeRequest::default()
        };
        let (Ok((url, pending)), Ok(key)) =
            (login.client.authorize(&request), SessionKey::generate())
        else {
            tracing::error!("operating system randomness is unavailable");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let pending = PendingAuthorization {
            login: pending,
            return_to,
        };
        let expires = login.now() + PENDING_LIFETIME;
        if let Err(error) = login.sessions.insert_pending(&key, &pending, expires).await {
            return Self::store_failure(&error);
        }
        let mut response = Redirect::to(url.as_str()).into_response();
        response.headers_mut().append(
            header::SET_COOKIE,
            Self::set_cookie(LOGIN_COOKIE, key.as_cookie(), PENDING_LIFETIME),
        );
        response
    }

    /// `GET /callback`: completes the pending login and starts a session.
    async fn callback(
        State(login): State<Arc<Self>>,
        headers: HeaderMap,
        Query(callback): Query<CallbackParams>,
    ) -> Response {
        let Some(key) = Self::cookie(&headers, LOGIN_COOKIE).and_then(SessionKey::parse) else {
            return (
                StatusCode::BAD_REQUEST,
                "This sign-in has no pending login; start again.",
            )
                .into_response();
        };
        let pending = match login.sessions.take_pending(&key, login.now()).await {
            Ok(Some(pending)) => pending,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "This sign-in expired or was already used; start again.",
                )
                    .into_response();
            }
            Err(error) => return Self::store_failure(&error),
        };
        let tokens = match login.client.complete(pending.login, &callback).await {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::debug!(error = %ErrorChain(&error), "sign-in failed");
                let status = if error.code().code == crate::protocol::sdk::ErrorCategory::Network {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::BAD_REQUEST
                };
                return (status, format!("Sign-in failed: {error}.")).into_response();
            }
        };
        let issuer = login.client.issuer().issuer().to_owned();
        let (Some(stored), Ok(session)) =
            (StoredLogin::new(issuer, tokens), SessionKey::generate())
        else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        // A fresh key on every sign-in: a key planted before login is worthless after.
        if let Some(previous) = Self::cookie(&headers, SESSION_COOKIE).and_then(SessionKey::parse)
            && let Err(error) = login.sessions.delete(&previous).await
        {
            return Self::store_failure(&error);
        }
        let expires = login.now() + login.lifetime;
        if let Err(error) = login.sessions.insert(&session, &stored, expires).await {
            return Self::store_failure(&error);
        }
        let mut response = Redirect::to(pending.return_to.as_str()).into_response();
        let cookies = response.headers_mut();
        cookies.append(
            header::SET_COOKIE,
            Self::set_cookie(SESSION_COOKIE, session.as_cookie(), login.lifetime),
        );
        cookies.append(
            header::SET_COOKIE,
            Self::set_cookie(LOGIN_COOKIE, "", TimeDelta::zero()),
        );
        response
    }

    /// Whether a browser request comes from this app's own pages: its `Origin` is the
    /// app's, whose callback is the client's redirect URI, or, without `Origin`,
    /// `Sec-Fetch-Site` says same-origin. `SameSite=Lax` alone would still let a
    /// sibling site under the same domain post with the cookie.
    fn same_origin(&self, headers: &HeaderMap) -> bool {
        let text =
            |name: header::HeaderName| headers.get(name).and_then(|value| value.to_str().ok());
        match text(header::ORIGIN) {
            Some(origin) => {
                origin
                    == self
                        .client
                        .config()
                        .redirect_uri
                        .origin()
                        .ascii_serialization()
            }
            None => text(header::HeaderName::from_static("sec-fetch-site")) == Some("same-origin"),
        }
    }

    /// `POST /logout`: deletes the session and redirects to RP-initiated logout.
    /// `POST` only, and only from the app's own pages, so another site cannot sign
    /// the user out.
    async fn logout(State(login): State<Arc<Self>>, headers: HeaderMap) -> Response {
        if !login.same_origin(&headers) {
            return (
                StatusCode::FORBIDDEN,
                "Sign out from this site's own pages.",
            )
                .into_response();
        }
        let mut destination = login.home.as_str().to_owned();
        if let Some(key) = Self::cookie(&headers, SESSION_COOKIE).and_then(SessionKey::parse) {
            match login.sessions.load(&key, login.now()).await {
                Ok(Some(session)) => {
                    destination = login
                        .client
                        .logout_url(&session.login.id_token, login.after_logout.as_ref())
                        .into();
                }
                Ok(None) => {}
                Err(error) => return Self::store_failure(&error),
            }
            if let Err(error) = login.sessions.delete(&key).await {
                return Self::store_failure(&error);
            }
        }
        let mut response = Redirect::to(&destination).into_response();
        response.headers_mut().append(
            header::SET_COOKIE,
            Self::set_cookie(SESSION_COOKIE, "", TimeDelta::zero()),
        );
        response
    }

    /// The signed-in session the request's cookie names, its access token refreshed
    /// when it is about to expire.
    async fn session(&self, headers: &HeaderMap) -> Result<Option<SignedIn>, BackendError> {
        let Some(key) = Self::cookie(headers, SESSION_COOKIE).and_then(SessionKey::parse) else {
            return Ok(None);
        };
        let Some(mut current) = self.sessions.load(&key, self.now()).await? else {
            return Ok(None);
        };
        let login = &current.login;
        if login.refresh_token.is_some() && login.expires_at <= self.now() + REFRESH_MARGIN {
            match self.refresh(&key, current).await? {
                Some(refreshed) => current = refreshed,
                None => return Ok(None),
            }
        }
        Ok(Some(SignedIn {
            login: current.login,
            checked_at: self.now(),
        }))
    }

    /// Refreshes the session's access token, serialized through the lease the SDK
    /// keeps in the session record: only the lease holder calls auth, and other
    /// requests wait for its result. Returns `None` once the session is gone.
    ///
    /// Auth rotates the refresh token as it answers, so once a refresh may have
    /// reached auth without its answer being saved, the stored token may be spent and
    /// is never redeemed again: the session ends instead, and the user signs in anew.
    async fn refresh(
        &self,
        key: &SessionKey,
        current: Session,
    ) -> Result<Option<Session>, BackendError> {
        let Ok(lease) = LeaseId::generate() else {
            tracing::error!("operating system randomness is unavailable");
            return Ok(Some(current));
        };
        match self
            .sessions
            .lease(key, current.version, &lease, REFRESH_LEASE, self.now())
            .await?
        {
            Lease::Missing => Ok(None),
            Lease::Abandoned => {
                tracing::warn!("a refresh never finished; ending the session");
                self.end(key).await
            }
            // Another request refreshed since this one read the session, or is
            // refreshing now: use its result.
            Lease::Changed | Lease::Busy => self.wait(key, current).await,
            Lease::Acquired => self.refresh_leased(key, &lease, current).await,
        }
    }

    /// Waits for another request's refresh to finish, then returns its result. After
    /// [`REFRESH_WAIT`], the session as last read is the best known.
    async fn wait(
        &self,
        key: &SessionKey,
        current: Session,
    ) -> Result<Option<Session>, BackendError> {
        let deadline = tokio::time::Instant::now() + REFRESH_WAIT;
        loop {
            match self.sessions.load(key, self.now()).await? {
                Some(reloaded) if reloaded.leased => {}
                other => return Ok(other),
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(Some(current));
            }
            tokio::time::sleep(REFRESH_POLL).await;
        }
    }

    /// Refreshes while holding `lease`, then saves the result or gives the lease back.
    async fn refresh_leased(
        &self,
        key: &SessionKey,
        lease: &LeaseId,
        current: Session,
    ) -> Result<Option<Session>, BackendError> {
        let Some(refresh) = &current.login.refresh_token else {
            return self.save(key, lease, current.login).await;
        };
        let Ok(refreshed) =
            tokio::time::timeout(REFRESH_DEADLINE, self.client.refresh(refresh)).await
        else {
            tracing::warn!("session refresh timed out; ending the session");
            return self.end(key).await;
        };
        match refreshed {
            Ok(tokens) => {
                let Some(refreshed) = current.login.refreshed(tokens) else {
                    tracing::warn!("refresh returned an ID token for another user");
                    return self.end(key).await;
                };
                self.save(key, lease, refreshed).await
            }
            // Auth refused the refresh token: the grant is over.
            Err(
                error @ crate::OAuthError::Rejected {
                    response:
                        crate::protocol::oauth::ErrorResponse {
                            error: crate::protocol::oauth::ErrorCode::InvalidGrant,
                            ..
                        },
                    ..
                },
            ) => {
                tracing::debug!(error = %ErrorChain(&error), "session refresh rejected");
                self.end(key).await
            }
            // Auth answered with another error, so it rotated nothing: keep the
            // session and give the lease back.
            Err(error @ crate::OAuthError::Rejected { .. }) => {
                tracing::warn!(error = %ErrorChain(&error), "session refresh failed");
                self.save(key, lease, current.login).await
            }
            // No usable answer: auth may have rotated the token.
            Err(error) => {
                tracing::warn!(error = %ErrorChain(&error), "session refresh failed; ending the session");
                self.end(key).await
            }
        }
    }

    /// Saves `login` under `lease`, giving the lease back. If the session no longer
    /// holds the lease, it was logged out meanwhile and must stay that way.
    async fn save(
        &self,
        key: &SessionKey,
        lease: &LeaseId,
        login: StoredLogin,
    ) -> Result<Option<Session>, BackendError> {
        self.sessions.save(key, lease, login, self.now()).await
    }

    /// Ends the session.
    async fn end(&self, key: &SessionKey) -> Result<Option<Session>, BackendError> {
        self.sessions.delete(key).await?;
        Ok(None)
    }

    /// Turns a [`StepUp`] response to a `GET` into a redirect through login that
    /// comes back to `path`.
    fn step_up(&self, response: Response, method: &Method, path: &str) -> Response {
        match response.extensions().get::<StepUp>() {
            Some(step_up) if method == Method::GET => {
                Redirect::to(&self.login_url(path.parse().ok().as_ref(), Some(step_up)))
                    .into_response()
            }
            _ => response,
        }
    }
}

/// The layer [`LoginRoutes::layer`] builds.
#[derive(Clone)]
pub struct LoginLayer(Arc<Login>);

impl fmt::Debug for LoginLayer {
    /// Names the layer.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginLayer")
    }
}

impl<S> Layer<S> for LoginLayer {
    type Service = LoginService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoginService {
            inner,
            login: self.0.clone(),
        }
    }
}

/// The service [`LoginLayer`] wraps around a router.
#[derive(Clone)]
pub struct LoginService<S> {
    /// The wrapped service.
    inner: S,
    /// Shared login state.
    login: Arc<Login>,
}

impl<S> fmt::Debug for LoginService<S> {
    /// Names the service.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoginService")
    }
}

impl<S> Service<Request> for LoginService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<Result<Response, S::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        // The clone that was polled ready handles this request.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let login = self.login.clone();
        let method = request.method().clone();
        let path = request
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string);
        request.extensions_mut().insert(login.clone());
        Box::pin(async move {
            let response = inner.call(request).await?;
            Ok(login.step_up(response, &method, &path))
        })
    }
}

/// The signed-in user. Without a session, a `GET` is redirected through login and
/// back; other methods get 401. Needs [`LoginRoutes::layer`].
///
/// ```no_run
/// use piquel_auth::axum::SignedIn;
///
/// async fn home(user: SignedIn) -> String {
///     format!("Hello {}", user.name())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct SignedIn {
    /// The stored login, its access token fresh.
    login: StoredLogin,
    /// When the session was read, by the issuer's clock.
    checked_at: DateTime<Utc>,
}

impl SignedIn {
    /// The user's name: the display name, else the username, else the account ID.
    #[must_use]
    pub fn name(&self) -> &str {
        let claims = self.login.id_token.claims();
        claims
            .profile
            .name
            .as_deref()
            .or(claims.profile.preferred_username.as_deref())
            .unwrap_or(&claims.sub)
    }

    /// The user's account ID.
    ///
    /// # Errors
    /// [`TokenError::InvalidSubject`] if `sub` is not an account ID.
    pub fn user_id(&self) -> Result<UserId, TokenError> {
        self.login.id_token.user_id()
    }

    /// The ID token of the sign-in.
    #[must_use]
    pub const fn id_token(&self) -> &IdToken {
        &self.login.id_token
    }

    /// The stored login, with the access token to call APIs for the user.
    #[must_use]
    pub const fn login(&self) -> &StoredLogin {
        &self.login
    }

    /// Requires the sign-in to meet `P`, or returns the [`StepUp`] that sends the
    /// user through login again and back to the same page.
    ///
    /// ```no_run
    /// use piquel_auth::{Acr, AuthenticationPolicy, axum::{SignedIn, StepUp}};
    ///
    /// struct RecentLogin;
    /// impl AuthenticationPolicy for RecentLogin {
    ///     const MAX_AGE: Option<u64> = Some(300);
    /// }
    ///
    /// async fn settings(user: SignedIn) -> Result<String, StepUp> {
    ///     user.require::<RecentLogin>()?;
    ///     Ok("settings".into())
    /// }
    /// ```
    ///
    /// # Errors
    /// The [`StepUp`] meeting `P`.
    pub fn require<P: AuthenticationPolicy>(&self) -> Result<(), StepUp> {
        self.login
            .id_token
            .require_authentication::<P>(self.checked_at)
            .map_err(|_| StepUp::required::<P>())
    }
}

impl<St: Send + Sync> FromRequestParts<St> for SignedIn {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, Response> {
        if let Some(user) = MaybeSignedIn::from_request_parts(parts, state).await?.0 {
            return Ok(user);
        }
        if parts.method != Method::GET {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
        let login = parts
            .extensions
            .get::<Arc<Login>>()
            .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        let return_to = parts
            .uri
            .path_and_query()
            .and_then(|path| path.as_str().parse().ok());
        Err(Redirect::to(&login.login_url(return_to.as_ref(), None)).into_response())
    }
}

/// The signed-in user, if any. Never rejects, except with 500 when the session
/// backend fails or [`LoginRoutes::layer`] is missing.
///
/// ```no_run
/// use piquel_auth::axum::MaybeSignedIn;
///
/// async fn landing(MaybeSignedIn(user): MaybeSignedIn) -> String {
///     match user {
///         Some(user) => format!("Welcome back, {}", user.name()),
///         None => "Welcome! Sign in at /auth/login".into(),
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct MaybeSignedIn(pub Option<SignedIn>);

impl<St: Send + Sync> FromRequestParts<St> for MaybeSignedIn {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &St) -> Result<Self, Response> {
        let Some(login) = parts.extensions.get::<Arc<Login>>() else {
            tracing::error!("SignedIn needs LoginRoutes::layer around the route");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        };
        login
            .session(&parts.headers)
            .await
            .map(Self)
            .map_err(|error| Login::store_failure(&error))
    }
}

/// A response asking the user to sign in again, more strongly or more recently. With
/// [`LoginRoutes::layer`] around the route, a `GET` is redirected through login with
/// `max_age` and `acr_values`, and comes back to the same page; other requests get
/// 401.
///
/// ```no_run
/// use piquel_auth::{
///     Acr, AuthenticationPolicy,
///     axum::{SignedIn, StepUp},
/// };
///
/// /// A passkey sign-in within the last five minutes.
/// struct RecentPasskey;
///
/// impl AuthenticationPolicy for RecentPasskey {
///     const ACR: Option<Acr> = Some(Acr::PhishingResistant);
///     const MAX_AGE: Option<u64> = Some(300);
/// }
///
/// async fn delete_account(user: SignedIn) -> Result<&'static str, StepUp> {
///     // Equivalent to `user.require::<RecentPasskey>()?`.
///     if user.require::<RecentPasskey>().is_err() {
///         return Err(StepUp::required::<RecentPasskey>());
///     }
///     Ok("deleted")
/// }
/// ```
#[derive(Clone, Debug)]
pub struct StepUp {
    /// The authentication context class required.
    acr: Option<Acr>,
    /// The longest acceptable time since authentication, in seconds.
    max_age: Option<u64>,
}

impl StepUp {
    /// The step-up meeting `P`.
    #[must_use]
    pub fn required<P: AuthenticationPolicy>() -> Self {
        Self {
            acr: P::ACR,
            max_age: P::MAX_AGE,
        }
    }
}

impl IntoResponse for StepUp {
    /// 401, marked for the layer to redirect.
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Extension(self)).into_response()
    }
}
