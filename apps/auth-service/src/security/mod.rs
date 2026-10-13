//! Shared browser-session, management authorization, and HTTP trust boundaries.

use crate::routes::{ACCOUNT_PREFIX, LOGIN_PREFIX, oidc, passkey, service};
use axum::{
    Json,
    extract::{ConnectInfo, FromRef, FromRequestParts, MatchedPath, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{self, InvalidHeaderValue},
        request::Parts,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use ipnet::IpNet;
use piquel_auth_protocol::{AuthenticationMethod, SessionId, UserId};
use piquel_common::ErrorChain;
use piquel_crypto::{CryptoError, Digest, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertSession, StoredSession,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};
use thiserror::Error;

/// Name of the browser proof required on non-protocol mutations.
pub(crate) const CSRF_HEADER: &str = "x-piquel-csrf";
/// Trusted ingress must overwrite this header with exactly one client address.
const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
/// Request budget per category and client in the repository's one-minute window.
const REQUESTS_PER_MINUTE: i32 = 120;
/// Retry delay matching the request-limit window.
const RETRY_AFTER_SECONDS: &str = "60";
/// Deadline includes origin checks, rate-limit persistence and the handler.
const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(30);
/// Browser session lifetime, also used by its host cookie.
const SESSION_LIFETIME_DAYS: u32 = 30;
/// Browser flow cookies slightly outlive their server-side ceremonies.
const FLOW_COOKIE_MAX_AGE: u32 = 600;

/// Browser JSON error `{"error": message}`; internal causes only reach the logs.
#[derive(Debug)]
pub(crate) struct ApiError {
    /// Status code of the error response.
    status: StatusCode,
    /// Fixed, non-sensitive explanation shown to the user.
    message: &'static str,
}

impl ApiError {
    /// Logs a failure with every preserved cause, once, at the HTTP boundary.
    pub(crate) fn log_error(error: &dyn std::error::Error) {
        tracing::error!(error = %ErrorChain(error), "authentication operation failed");
    }

    /// Rejects invalid browser input with its fixed explanation.
    pub(crate) fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    /// Reports a missing browser resource with a fixed public explanation.
    pub(crate) fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
        }
    }

    /// Requires the browser to sign in.
    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "Sign in to continue.",
        }
    }

    /// Rejects an unauthorized operation with its fixed explanation.
    pub(crate) fn forbidden(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message,
        }
    }

    /// Logs an internal source chain and returns a generic browser message.
    pub(crate) fn internal(error: impl std::error::Error) -> Self {
        Self::log_error(&error);

        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "The request could not be completed. Please try again.",
        }
    }
}

impl From<DatabaseError> for ApiError {
    /// Missing rows and conflicts get their own message; other failures are logged 500s.
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::NotFound => {
                Self::bad_request("This request has expired or is no longer available.")
            }
            DatabaseError::Conflict(_) => Self {
                status: StatusCode::CONFLICT,
                message: "This information is already in use.",
            },
            error @ (DatabaseError::Timeout(_)
            | DatabaseError::InvalidStoredData { .. }
            | DatabaseError::Operation(_)) => Self::internal(error),
        }
    }
}

impl IntoResponse for ApiError {
    /// Serializes the fixed browser error and adds the retry delay for rate limits.
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response();
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_static(RETRY_AFTER_SECONDS),
            );
        }
        response
    }
}

piquel_common::str_enum! {
    /// Host-only cookies binding server-side state to a browser secret.
    pub(crate) enum BrowserCookie {
        /// Central sign-in session.
        Session = "__Host-piquel_session",
        /// In-progress WebAuthn ceremony.
        Ceremony = "__Host-piquel_ceremony",
        /// Provider redirect awaiting its callback.
        Federation = "__Host-piquel_federation",
        /// Verified identity awaiting signup or linking.
        FederationPending = "__Host-piquel_federation_pending",
    }
}

impl BrowserCookie {
    /// Lifetime in seconds. Flow cookies outlive their server-side state slightly.
    const fn max_age(self) -> u32 {
        match self {
            Self::Session => SESSION_LIFETIME_DAYS * 24 * 60 * 60,
            Self::Ceremony | Self::Federation | Self::FederationPending => FLOW_COOKIE_MAX_AGE,
        }
    }

    /// Reads this cookie's secret. A malformed or duplicated cookie counts as absent,
    /// so an injected value can never shadow the browser's own.
    pub(crate) fn read(self, headers: &HeaderMap) -> Option<Secret> {
        let mut values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|part| part.trim().strip_prefix(self.as_str())?.strip_prefix('='));
        let value = values.next()?;
        if values.next().is_some() {
            return None;
        }
        Secret::parse(value).ok()
    }

    /// Adds a `Set-Cookie` header storing `secret`, keeping any other cookies being set.
    pub(crate) fn set_on(
        self,
        response: &mut Response,
        secret: &Secret,
    ) -> Result<(), InvalidHeaderValue> {
        self.append(response, &secret.encoded(), self.max_age())
    }

    /// Adds a `Set-Cookie` header deleting this cookie.
    pub(crate) fn clear_on(self, response: &mut Response) -> Result<(), InvalidHeaderValue> {
        self.append(response, "", 0)
    }

    /// Appends a host-only, `Secure`, `HttpOnly`, `SameSite=Lax` cookie header.
    fn append(
        self,
        response: &mut Response,
        value: &str,
        max_age: u32,
    ) -> Result<(), InvalidHeaderValue> {
        let cookie = format!(
            "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            self.as_str()
        );
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_str(&cookie)?);
        Ok(())
    }
}

/// Browser session failures before they are mapped to an HTTP response.
#[derive(Debug, Error)]
pub(crate) enum SessionError {
    /// No active sign-in session exists.
    #[error("active browser session required")]
    Missing,
    /// Settings authorization has expired or was never granted.
    #[error("active passkey management authorization required")]
    ManagementRequired,
    /// Session persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// Secure session material could not be generated.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<SessionError> for ApiError {
    /// A missing session is 401 and an expired management window 403.
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::Missing => Self::unauthorized(),
            SessionError::ManagementRequired => {
                Self::forbidden("Confirm with a passkey to unlock settings for two minutes.")
            }
            SessionError::Database(error) => error.into(),
            error @ SessionError::Crypto(_) => Self::internal(error),
        }
    }
}

impl Session {
    /// Looks up a session, treating missing or malformed cookies as anonymous.
    pub(crate) async fn optional(
        database: &Database,
        headers: &HeaderMap,
    ) -> Result<Option<StoredSession>, SessionError> {
        let Some(secret) = BrowserCookie::Session.read(headers) else {
            return Ok(None);
        };
        Ok(database
            .sessions()
            .find_active_by_browser_secret(secret.digest().as_bytes())
            .await?)
    }

    /// Requires a live browser session.
    pub(crate) async fn required(
        database: &Database,
        headers: &HeaderMap,
    ) -> Result<StoredSession, SessionError> {
        Self::optional(database, headers)
            .await?
            .ok_or(SessionError::Missing)
    }

    /// Requires the session's short passkey management window.
    pub(crate) async fn management(
        database: &Database,
        headers: &HeaderMap,
    ) -> Result<StoredSession, SessionError> {
        let session = Self::required(database, headers).await?;
        Self::authorize_management(database, session).await
    }

    /// Applies management authorization to an already extracted session.
    pub(crate) async fn authorize_management(
        database: &Database,
        session: StoredSession,
    ) -> Result<StoredSession, SessionError> {
        if !database.sessions().management_active(session.id).await? {
            return Err(SessionError::ManagementRequired);
        }
        Ok(session)
    }

    /// Creates a session inside the caller's transaction and returns the secret for
    /// its cookie. Callers set the cookie only after the transaction commits.
    pub(crate) async fn create(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        method: AuthenticationMethod,
    ) -> Result<Secret, SessionError> {
        let now = Utc::now();
        let id = SessionId::new();
        tx.sessions()
            .insert(&InsertSession {
                id,
                user_id,
                authentication_methods: vec![method],
                authenticated_at: now,
                expires_at: now + Duration::days(i64::from(SESSION_LIFETIME_DAYS)),
                user_agent_family: None,
            })
            .await?;
        let secret = Secret::generate()?;
        tx.sessions()
            .insert_browser_secret(id, secret.digest().as_bytes())
            .await?;
        Ok(secret)
    }
}

/// Required active browser session extracted before the handler runs.
pub(crate) struct Session(pub StoredSession);
/// Optional browser session for anonymous or signed-in requests.
pub(crate) struct OptionalSession(pub Option<StoredSession>);
/// Browser session with a live passkey management window.
pub(crate) struct ManagementSession(pub StoredSession);

/// Implements the common database-backed extraction contract for session variants.
macro_rules! session_extractor {
    ($name:ident, $lookup:ident) => {
        impl<S> FromRequestParts<S> for $name
        where
            Database: FromRef<S>,
            S: Send + Sync,
        {
            type Rejection = ApiError;
            /// Extracts the requested session policy using the application database state.
            async fn from_request_parts(
                parts: &mut Parts,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                Ok(Self(
                    Session::$lookup(&Database::from_ref(state), &parts.headers).await?,
                ))
            }
        }
    };
}
session_extractor!(Session, required);
session_extractor!(OptionalSession, optional);
session_extractor!(ManagementSession, management);

/// How the HTTP boundary treats a route. Origin, CSRF and rate policy all read this one
/// classification, so it must list every route that differs from `Other`.
#[derive(Clone, Copy)]
enum Endpoint {
    /// Token and revocation, authenticated by client credentials.
    OAuthBackChannel,
    /// Bearer-authenticated `UserInfo`.
    UserInfo,
    /// Public discovery and signing keys.
    Discovery,
    /// Authorization requests, including cross-site form navigation.
    Authorize,
    /// RP-initiated logout, validated by its own hint and same-origin checks.
    Logout,
    /// Account and session APIs shared with the settings site.
    Account,
    /// Social sign-in, also started from the settings site.
    Login,
    /// Auth-origin pages and ceremonies.
    Other,
}

impl Endpoint {
    /// Classifies exact protocol paths and the settings/login route families.
    fn classify(path: &str) -> Self {
        match path {
            oidc::TOKEN | oidc::REVOKE => Self::OAuthBackChannel,
            oidc::USERINFO => Self::UserInfo,
            oidc::DISCOVERY | oidc::JWKS => Self::Discovery,
            oidc::AUTHORIZE => Self::Authorize,
            oidc::LOGOUT => Self::Logout,
            service::CONFIG | passkey::SESSION | passkey::SESSION_LOGOUT => Self::Account,
            _ if path.starts_with(ACCOUNT_PREFIX) => Self::Account,
            _ if path.starts_with(LOGIN_PREFIX) => Self::Login,
            _ => Self::Other,
        }
    }

    /// Protocol handlers enforce their own credentials and navigation checks.
    const fn is_protocol(self) -> bool {
        match self {
            Self::OAuthBackChannel | Self::UserInfo | Self::Authorize | Self::Logout => true,
            Self::Discovery | Self::Account | Self::Login | Self::Other => false,
        }
    }

    /// Selects a request budget. Safe reads only count on login flows and the token endpoint.
    fn rate_category(self, mutation: bool) -> Option<RateCategory> {
        match self {
            Self::OAuthBackChannel => Some(RateCategory::Token),
            Self::Login | Self::Authorize => Some(RateCategory::Login),
            Self::Account => mutation.then_some(RateCategory::Account),
            Self::UserInfo | Self::Discovery | Self::Logout | Self::Other => {
                mutation.then_some(RateCategory::Login)
            }
        }
    }
}

piquel_common::str_enum! {
    /// Independent request budgets persisted under stable category names.
    enum RateCategory {
        /// OAuth credential exchanges and revocation.
        Token = "token",
        /// Settings mutations.
        Account = "account",
        /// Login navigation and other mutations.
        Login = "login",
    }
}

/// Failures in shared HTTP trust checks, preserving actionable internal sources.
#[derive(Debug, Error)]
enum HttpSecurityError {
    /// The listener did not attach its peer connection metadata.
    #[error("HTTP peer address missing")]
    MissingPeer,
    /// A browser preflight came from an unapproved origin.
    #[error("preflight origin is not allowed")]
    ForbiddenPreflight,
    /// A browser request violates the endpoint's origin policy.
    #[error("request origin is not allowed")]
    ForbiddenOrigin,
    /// An approved browser mutation omitted its CSRF proof.
    #[error("browser mutation requires CSRF header")]
    MissingCsrf,
    /// The trusted proxy omitted its header or supplied more than one.
    #[error("trusted proxy must supply exactly one forwarded address")]
    ForwardedAddressCount,
    /// The forwarded header is not valid HTTP text.
    #[error("forwarded address is not HTTP text")]
    ForwardedHeader(#[from] axum::http::header::ToStrError),
    /// The forwarded header does not contain a single IP address.
    #[error("forwarded address is not a single IP address")]
    ForwardedAddress(#[from] std::net::AddrParseError),
    /// This client's category budget is exhausted.
    #[error("request budget exhausted")]
    RateLimited,
    /// The complete request exceeded its deadline.
    #[error("HTTP request timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
    /// Rate-limit persistence failed.
    #[error("HTTP security persistence failed")]
    Database(#[from] DatabaseError),
}

impl From<HttpSecurityError> for ApiError {
    /// Maps trust-boundary failures to stable public statuses and messages.
    fn from(error: HttpSecurityError) -> Self {
        match error {
            HttpSecurityError::ForbiddenPreflight => Self::forbidden("Origin is not allowed."),
            HttpSecurityError::ForbiddenOrigin | HttpSecurityError::MissingCsrf => {
                Self::forbidden("This request must originate from an approved Piquel page.")
            }
            HttpSecurityError::ForwardedAddressCount
            | HttpSecurityError::ForwardedHeader(_)
            | HttpSecurityError::ForwardedAddress(_) => {
                Self::bad_request("Trusted proxy must supply one X-Forwarded-For address.")
            }
            HttpSecurityError::RateLimited => Self {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "Too many requests. Please wait a minute.",
            },
            HttpSecurityError::Timeout(_) => Self {
                status: StatusCode::GATEWAY_TIMEOUT,
                message: "Request timed out.",
            },
            HttpSecurityError::Database(error) => error.into(),
            error @ HttpSecurityError::MissingPeer => Self::internal(error),
        }
    }
}

/// Shared origin, proxy, timeout and request-limit policy.
#[derive(Clone)]
pub(crate) struct HttpSecurity {
    /// Stores the rate-limit counters.
    pub database: Database,
    /// Peers allowed to report the client IP in `X-Forwarded-For`.
    pub trusted_proxies: Arc<Vec<IpNet>>,
    /// Deadline for the whole request, handler included.
    pub request_timeout: StdDuration,
    /// Origin of the auth frontend, allowed on every endpoint.
    pub auth_origin: String,
    /// Origin of the settings site, allowed on account and login endpoints.
    pub settings_origin: String,
    /// Public OIDC client origins permitted on protocol endpoints.
    pub client_origins: Arc<Vec<String>>,
}

impl HttpSecurity {
    /// Derives the shared HTTP policy from validated startup configuration.
    pub(crate) fn new(config: &crate::AuthConfig, database: Database) -> Self {
        Self {
            database,
            trusted_proxies: Arc::new(config.trusted_proxies.clone()),
            request_timeout: REQUEST_TIMEOUT,
            auth_origin: config.passkey.origin.serialized(),
            settings_origin: config
                .federation
                .settings_url
                .as_url()
                .origin()
                .ascii_serialization(),
            client_origins: Arc::new(
                config
                    .oidc
                    .public_redirects
                    .iter()
                    .map(|uri| uri.origin().ascii_serialization())
                    .collect(),
            ),
        }
    }

    /// A trusted edge must overwrite `X-Forwarded-For` with one validated client address.
    fn client_ip(&self, request: &Request) -> Result<IpAddr, HttpSecurityError> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .ok_or(HttpSecurityError::MissingPeer)?
            .0
            .ip();
        if !self
            .trusted_proxies
            .iter()
            .any(|proxy| proxy.contains(&peer))
        {
            return Ok(peer);
        }
        Self::forwarded_ip(request.headers())
    }

    /// Parses the one address an explicitly trusted ingress must supply.
    fn forwarded_ip(headers: &HeaderMap) -> Result<IpAddr, HttpSecurityError> {
        let mut forwarded = headers.get_all(FORWARDED_FOR_HEADER).iter();
        let header = forwarded
            .next()
            .ok_or(HttpSecurityError::ForwardedAddressCount)?;
        if forwarded.next().is_some() {
            return Err(HttpSecurityError::ForwardedAddressCount);
        }
        Ok(header.to_str()?.parse()?)
    }

    /// Determines whether an exact browser origin may access this endpoint family.
    fn allowed_origin(&self, endpoint: Endpoint, origin: &str) -> bool {
        origin == self.auth_origin
            || (origin == self.settings_origin
                && matches!(endpoint, Endpoint::Account | Endpoint::Login))
            || (matches!(
                endpoint,
                Endpoint::OAuthBackChannel | Endpoint::UserInfo | Endpoint::Discovery
            ) && self.client_origins.iter().any(|v| v == origin))
    }

    /// Middleware: runs the trust checks and the handler under one deadline, then adds the
    /// cache, isolation and CORS headers to every response, errors included.
    pub(crate) async fn protect(
        State(policy): State<Self>,
        request: Request,
        next: Next,
    ) -> Response {
        // Reuse the original header for CORS so decoration cannot fail during re-parsing.
        let origin = request.headers().get(header::ORIGIN).cloned();
        let endpoint = Endpoint::classify(request.uri().path());
        let allowed = origin
            .as_ref()
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| policy.allowed_origin(endpoint, value));
        let mut response = tokio::time::timeout(
            policy.request_timeout,
            policy.dispatch(request, next, endpoint, allowed),
        )
        .await
        .map_err(HttpSecurityError::from)
        .flatten()
        .unwrap_or_else(|error| ApiError::from(error).into_response());
        Self::decorate(&mut response, origin.filter(|_| allowed));
        response
    }

    /// Answers preflights, then checks browser proof and the request budget before the route.
    async fn dispatch(
        &self,
        request: Request,
        next: Next,
        endpoint: Endpoint,
        allowed: bool,
    ) -> Result<Response, HttpSecurityError> {
        if request.method() == Method::OPTIONS {
            return if allowed {
                Ok(StatusCode::NO_CONTENT.into_response())
            } else {
                Err(HttpSecurityError::ForbiddenPreflight)
            };
        }
        let mutation = !matches!(*request.method(), Method::GET | Method::HEAD);
        Self::check_browser(endpoint, request.headers(), allowed, mutation)?;
        // Unknown paths have no `MatchedPath`: they never consume a budget or need peer metadata.
        if request.extensions().get::<MatchedPath>().is_some()
            && let Some(category) = endpoint.rate_category(mutation)
        {
            let bucket =
                Digest::sha256(format!("{category}:{}", self.client_ip(&request)?).as_bytes());
            if !self
                .database
                .security()
                .allow_request(bucket.as_bytes(), REQUESTS_PER_MINUTE)
                .await?
            {
                return Err(HttpSecurityError::RateLimited);
            }
        }
        Ok(next.run(request).await)
    }

    /// Rejects unapproved browser origins and mutations without CSRF proof. Protocol
    /// endpoints are exempt: their handlers check credentials and navigation themselves.
    fn check_browser(
        endpoint: Endpoint,
        headers: &HeaderMap,
        allowed: bool,
        mutation: bool,
    ) -> Result<(), HttpSecurityError> {
        if endpoint.is_protocol() {
            return Ok(());
        }
        let origin_present = headers
            .get(header::ORIGIN)
            .is_some_and(|origin| origin.to_str().is_ok());
        if (origin_present || mutation) && !allowed {
            return Err(HttpSecurityError::ForbiddenOrigin);
        }
        if mutation && !headers.contains_key(CSRF_HEADER) {
            return Err(HttpSecurityError::MissingCsrf);
        }
        Ok(())
    }

    /// Adds cache and browser isolation headers, plus an exact-origin CORS grant when
    /// `allowed_origin` is set.
    fn decorate(response: &mut Response, allowed_origin: Option<HeaderValue>) {
        let headers = response.headers_mut();
        // Private by default; static assets set their own cache policy.
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
        for (name, value) in [
            // No MIME sniffing.
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // Navigation must not leak authentication URLs.
            (header::REFERRER_POLICY, "no-referrer"),
            // Authentication pages must never be framed.
            (header::X_FRAME_OPTIONS, "DENY"),
            // Keep later visits on HTTPS for a year.
            (header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        let Some(origin) = allowed_origin else {
            return;
        };
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        for (name, value) in [
            // Approved origins may send the browser's host cookies.
            (header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"),
            (
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "content-type, x-piquel-csrf, authorization",
            ),
            (
                header::ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, PATCH, DELETE, OPTIONS",
            ),
            (header::VARY, "Origin"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
}

/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
