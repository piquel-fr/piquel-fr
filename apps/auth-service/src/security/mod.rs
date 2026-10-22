//! Shared browser-session, passkey confirmation and HTTP trust boundaries.

use crate::config::FrontendOrigins;
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
use piquel_common::{
    AuthenticationMethod, ClientId, ErrorChain, SessionId, UserId,
    events::{
        Actor, DomainEvent, EventContext, RequestOrigin, RevocationReason, SignInFailure,
        UserAgentFamily,
    },
    protocol::{
        api::{ErrorBody, ErrorCode},
        step_up::StepUpRequirement,
    },
};
use piquel_crypto::{CryptoError, Digest, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertSession, SessionAuthentication,
    StoredSession,
};
use std::{
    borrow::Cow,
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
pub(crate) use piquel_common::protocol::step_up::CONFIRMATION_MAX_AGE;

/// Browser JSON error `{"error": message}`, plus a machine-readable `code` when the
/// frontend can resolve it. Internal causes only reach the logs.
#[derive(Debug)]
pub(crate) struct ApiError {
    /// Status code of the error response.
    status: StatusCode,
    /// Non-sensitive explanation shown to the user, specific enough to act on.
    message: Cow<'static, str>,
    /// Stable reason a frontend can react to, serialized next to the message.
    code: Option<ErrorCode>,
}

impl ApiError {
    /// An error without a machine-readable code.
    fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            message: message.into(),
            code: None,
        }
    }

    /// Logs a failure with every preserved cause, once, at the HTTP boundary.
    pub(crate) fn log_error(error: &dyn std::error::Error) {
        tracing::error!(error = %ErrorChain(error), "authentication operation failed");
    }

    /// Rejects invalid browser input, explaining what is wrong.
    pub(crate) fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// Reports a missing browser resource.
    pub(crate) fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// Requires the browser to sign in, explaining why its current sign-in is not enough.
    pub(crate) fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    /// Rejects an operation the browser is not allowed to perform, explaining why.
    pub(crate) fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// Rejects a write that collides with existing data, naming what is already in use.
    pub(crate) fn conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    /// Logs an internal source chain and returns a generic browser message.
    pub(crate) fn internal(error: impl std::error::Error) -> Self {
        Self::log_error(&error);
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be completed. Please try again.",
        )
    }
}

impl From<DatabaseError> for ApiError {
    /// Missing rows and conflicts get their own message; other failures are logged 500s.
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::NotFound => {
                Self::bad_request("This request has expired or is no longer available.")
            }
            DatabaseError::Conflict(_) => Self::conflict("This information is already in use."),
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
            Json(ErrorBody {
                error: self.message.into_owned(),
                code: self.code,
            }),
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
    /// The session has no passkey confirmation at most `max_age` seconds old.
    #[error("passkey confirmation at most {max_age} seconds old required")]
    StepUpRequired {
        /// Maximum confirmation age the action accepts, in seconds.
        max_age: u32,
    },
    /// A social sign-in tried to re-authenticate a session a passkey confirmed,
    /// which would lower its `acr`.
    #[error("this session was confirmed with a passkey; sign in again with a passkey")]
    PasskeyRequired,
    /// Session persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// Secure session material could not be generated.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<SessionError> for ApiError {
    /// A missing session is 401. A stale confirmation is 403 with `step_up_required`.
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::Missing => Self::unauthorized("Sign in to continue."),
            SessionError::StepUpRequired { max_age } => Self {
                code: Some(ErrorCode::StepUpRequired { max_age }),
                ..Self::forbidden("Confirm with your passkey to continue.")
            },
            SessionError::PasskeyRequired => {
                Self::forbidden("Sign in with your passkey to continue.")
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

    /// Locks the account, then the session row, and returns the session as it is now.
    /// A concurrent logout or revocation either commits first or waits. Expiry is
    /// checked after the locks, since the lookup compares it with the transaction's start.
    pub(crate) async fn lock(
        tx: &mut DatabaseTransaction<'_>,
        session: &StoredSession,
    ) -> Result<StoredSession, SessionError> {
        tx.users()
            .find_active_by_id_for_update(session.user_id)
            .await?
            .ok_or(SessionError::Missing)?;
        tx.sessions()
            .find_active_by_id_for_update(session.id)
            .await?
            .filter(|session| session.expires_at > Utc::now())
            .ok_or(SessionError::Missing)
    }

    /// Signs `user_id` in on this browser inside the caller's transaction, records the
    /// sign-in, and returns the secret for its session cookie. Callers set the cookie
    /// only after the transaction commits. Locks the account first, so sign-in
    /// serializes with its disablement and with other changes to its sessions.
    ///
    /// A browser already signed in as `user_id` re-authenticates that session (see
    /// [`Self::reauthenticate`]). A browser signed in as someone else has that session
    /// revoked, then gets a new one.
    pub(crate) async fn sign_in(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        headers: &HeaderMap,
        user_id: UserId,
        method: AuthenticationMethod,
    ) -> Result<Secret, SessionError> {
        tx.users()
            .find_active_by_id_for_update(user_id)
            .await?
            .ok_or(SessionError::Missing)?;
        let current = match BrowserCookie::Session.read(headers) {
            Some(cookie) => {
                tx.sessions()
                    .find_active_by_browser_secret(cookie.digest().as_bytes())
                    .await?
            }
            None => None,
        };
        match current {
            Some(current) if current.user_id == user_id => {
                let secret = Self::reauthenticate(tx, &current, method).await?;
                tx.record(
                    &context.user(&current),
                    Some(user_id),
                    DomainEvent::SignedIn {
                        session_id: current.id,
                        method,
                    },
                )
                .await?;
                Ok(secret)
            }
            Some(other) => {
                if tx.sessions().revoke(other.id).await? {
                    tx.record(
                        &context.user(&other),
                        Some(other.user_id),
                        DomainEvent::SessionRevoked {
                            session_id: other.id,
                            reason: RevocationReason::AccountSwitched,
                        },
                    )
                    .await?;
                }
                Self::create(tx, context, user_id, method).await
            }
            None => Self::create(tx, context, user_id, method).await,
        }
    }

    /// Records a new authentication of `session` with `method` inside the caller's
    /// transaction, keeping its `sid`, and returns the secret for its new cookie. A
    /// passkey confirms the session. A social sign-in renews it unless a passkey
    /// confirmed it, since that would lower its `acr`. Callers record the event that
    /// says why.
    ///
    /// The old cookie stops working, so a copy of it never gains the new
    /// authentication. Callers set the new cookie only after the transaction commits.
    pub(crate) async fn reauthenticate(
        tx: &mut DatabaseTransaction<'_>,
        session: &StoredSession,
        method: AuthenticationMethod,
    ) -> Result<Secret, SessionError> {
        let now = Utc::now();
        match method {
            AuthenticationMethod::Passkey => tx.sessions().confirm_passkey(session.id, now).await?,
            AuthenticationMethod::Federation => {
                if session.passkey_confirmed_at.is_some() {
                    return Err(SessionError::PasskeyRequired);
                }
                tx.sessions().reauthenticate_social(session.id, now).await?;
            }
        }
        let secret = Secret::generate()?;
        tx.sessions()
            .replace_browser_secret(session.id, secret.digest().as_bytes())
            .await?;
        Ok(secret)
    }

    /// Creates a session inside the caller's transaction, records the sign-in, and
    /// returns the secret for its cookie. A passkey sign-in also confirms the session,
    /// so an action right after it prompts no more.
    pub(crate) async fn create(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
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
                passkey_confirmed_at: matches!(method, AuthenticationMethod::Passkey)
                    .then_some(now),
            })
            .await?;
        let secret = Secret::generate()?;
        tx.sessions()
            .insert_browser_secret(id, secret.digest().as_bytes())
            .await?;
        tx.record(
            &context.actor(Actor::User {
                user_id,
                session_id: Some(id),
            }),
            Some(user_id),
            DomainEvent::SignedIn {
                session_id: id,
                method,
            },
        )
        .await?;
        Ok(secret)
    }

    /// Revokes every other session of `session`'s account inside the caller's
    /// transaction, recording one revocation per session.
    pub(crate) async fn revoke_other(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        session: &StoredSession,
        reason: RevocationReason,
    ) -> Result<(), DatabaseError> {
        let context = context.user(session);
        for revoked in tx
            .sessions()
            .revoke_other(session.user_id, session.id)
            .await?
        {
            tx.record(
                &context,
                Some(session.user_id),
                DomainEvent::SessionRevoked {
                    session_id: revoked,
                    reason: reason.clone(),
                },
            )
            .await?;
        }
        Ok(())
    }
}

/// Where a request came from, attached by [`HttpSecurity::protect`] to every
/// rate-limited route and extracted by handlers that record events.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestContext(RequestOrigin);

impl RequestContext {
    /// The client IP and the coarse browser family of its `User-Agent` header.
    fn new(client_ip: IpAddr, headers: &HeaderMap) -> Self {
        Self(RequestOrigin {
            client_ip: Some(client_ip),
            user_agent_family: Some(
                headers
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .map_or(UserAgentFamily::Other, UserAgentFamily::classify),
            ),
        })
    }

    /// Attributes events of this request to `actor`.
    pub(crate) fn actor(self, actor: Actor) -> EventContext {
        EventContext {
            actor,
            origin: self.0,
        }
    }

    /// Attributes events of this request to the user signed in with `session`.
    pub(crate) fn user(self, session: &StoredSession) -> EventContext {
        self.actor(Actor::User {
            user_id: session.user_id,
            session_id: Some(session.id),
        })
    }

    /// Attributes events of this request to an authenticated client.
    pub(crate) fn client(self, client_id: &ClientId) -> EventContext {
        self.actor(Actor::Client {
            client_id: client_id.clone(),
        })
    }

    /// Records a rejected authentication in a transaction of its own, since the
    /// attempt changed nothing. `subject` is the account it targeted, when known.
    pub(crate) async fn record_sign_in_failure(
        self,
        database: &Database,
        actor: Actor,
        subject: Option<UserId>,
        method: AuthenticationMethod,
        reason: SignInFailure,
    ) -> Result<(), DatabaseError> {
        let mut tx = database.begin().await?;
        tx.record(
            &self.actor(actor),
            subject,
            DomainEvent::SignInFailed { method, reason },
        )
        .await?;
        tx.commit().await
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = ApiError;
    /// Reads the context [`HttpSecurity::protect`] attached.
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Self>()
                .copied()
                .ok_or_else(|| HttpSecurityError::MissingContext.into()),
        )
    }
}

/// Required active browser session extracted before the handler runs.
pub(crate) struct Session(pub StoredSession);
/// Optional browser session for anonymous or signed-in requests.
pub(crate) struct OptionalSession(pub Option<StoredSession>);
/// Browser session whose passkey confirmation is at most `MAX_AGE` seconds old: it
/// meets [`StepUpRequirement::passkey_within`], checked against the `acr` and
/// `auth_time` tokens would report, as bearer-protected resources check them. The
/// age counts from the confirmation itself, so using it never extends it. Handlers
/// re-check it with [`Self::lock`] inside their transaction.
pub(crate) struct Confirmed<const MAX_AGE: u32 = CONFIRMATION_MAX_AGE>(pub StoredSession);

impl<const MAX_AGE: u32> Confirmed<MAX_AGE> {
    /// What the session's authentication must meet.
    const REQUIREMENT: StepUpRequirement = StepUpRequirement::passkey_within(MAX_AGE);

    /// Rejects a session without a recent enough passkey confirmation.
    fn check(session: &StoredSession) -> Result<(), SessionError> {
        let authentication = SessionAuthentication::from(session);
        Self::REQUIREMENT
            .check(
                Some(&authentication.acr),
                Some(authentication.auth_time),
                Utc::now(),
            )
            .map_err(|_| SessionError::StepUpRequired { max_age: MAX_AGE })
    }

    /// Re-checks the confirmation inside `tx` under [`Session::lock`].
    pub(crate) async fn lock(&self, tx: &mut DatabaseTransaction<'_>) -> Result<(), SessionError> {
        Self::check(&Session::lock(tx, &self.0).await?)
    }
}

impl<S, const MAX_AGE: u32> FromRequestParts<S> for Confirmed<MAX_AGE>
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// Extracts the active session, then requires its recent passkey confirmation.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Session(session) = Session::from_request_parts(parts, state).await?;
        Self::check(&session)?;
        Ok(Self(session))
    }
}

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

/// How the HTTP boundary treats a route. Origin, CSRF and rate policy all read this one
/// classification, so it must list every route that differs from `Other`.
#[derive(Clone, Copy)]
enum Endpoint {
    /// Token, revocation and pushed authorization requests, authenticated by client
    /// credentials.
    OAuthBackChannel,
    /// Bearer-authenticated `UserInfo`.
    UserInfo,
    /// Public metadata and signing keys, served from memory and readable from any origin.
    Discovery,
    /// Liveness and readiness probes polled by the orchestrator.
    Health,
    /// Authorization requests, including cross-site form navigation.
    Authorize,
    /// RP-initiated logout, validated by its own hint and same-origin checks.
    Logout,
    /// Account and session APIs shared with the first-party frontends.
    Account,
    /// Social sign-in, also started from the first-party frontends.
    Login,
    /// Auth-origin pages and ceremonies.
    Other,
}

impl Endpoint {
    /// Classifies exact protocol paths and the settings/login route families.
    fn classify(path: &str) -> Self {
        match path {
            oidc::TOKEN | oidc::REVOKE | oidc::PAR => Self::OAuthBackChannel,
            oidc::USERINFO => Self::UserInfo,
            oidc::DISCOVERY | oidc::OAUTH_METADATA | oidc::JWKS => Self::Discovery,
            service::LIVE | service::READY => Self::Health,
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
            Self::Discovery | Self::Health | Self::Account | Self::Login | Self::Other => false,
        }
    }

    /// Selects the budget of a matched route, reads included: they verify token
    /// signatures or hold a connection from the small database pool. Only routes that
    /// do neither are free. Discovery is served from memory and cacheable, and a
    /// throttled health probe would take the service out of rotation; readiness costs
    /// one `SELECT 1`, no more than the budget's own upsert would.
    const fn rate_category(self) -> Option<RateCategory> {
        match self {
            Self::OAuthBackChannel => Some(RateCategory::Token),
            Self::UserInfo => Some(RateCategory::UserInfo),
            Self::Account => Some(RateCategory::Account),
            Self::Login | Self::Authorize | Self::Logout | Self::Other => Some(RateCategory::Login),
            Self::Discovery | Self::Health => None,
        }
    }
}

piquel_common::str_enum! {
    /// Independent request budgets persisted under stable category names, so one kind of
    /// traffic from a client cannot exhaust another: a relying party's `UserInfo` calls
    /// never block its code exchanges, and settings reads never block a sign-in.
    enum RateCategory {
        /// OAuth credential exchanges and revocation.
        Token = "token",
        /// Bearer-token claim lookups by relying parties.
        UserInfo = "userinfo",
        /// Settings and browser-session reads and mutations.
        Account = "account",
        /// Sign-in, authorization, logout and the other auth-origin routes.
        Login = "login",
    }
}

/// The CORS headers a response carries.
enum CorsGrant {
    /// Public, credential-free documents that any origin may read.
    Public,
    /// An approved origin, which may send the browser's cookies.
    Credentialed(HeaderValue),
}

/// Failures in shared HTTP trust checks, preserving actionable internal sources.
#[derive(Debug, Error)]
enum HttpSecurityError {
    /// The listener did not attach its peer connection metadata.
    #[error("HTTP peer address missing")]
    MissingPeer,
    /// A handler that records events runs on a route without a rate budget, so the
    /// middleware attached no request context.
    #[error("request context missing")]
    MissingContext,
    /// A browser preflight came from an unapproved origin.
    #[error("preflight origin is not allowed")]
    ForbiddenPreflight,
    /// A browser request comes from an origin this endpoint does not serve.
    #[error("request origin is not allowed")]
    ForbiddenOrigin,
    /// A mutation carries no `Origin` header, so its page cannot be checked.
    #[error("mutation has no Origin header")]
    MissingOrigin,
    /// An approved browser mutation omitted its CSRF proof.
    #[error("browser mutation requires CSRF header")]
    MissingCsrf,
    /// The trusted proxy sent no forwarded address.
    #[error("trusted proxy sent no forwarded address")]
    MissingForwardedAddress,
    /// The trusted proxy sent several forwarded headers instead of overwriting them.
    #[error("trusted proxy sent several forwarded address headers")]
    MultipleForwardedHeaders,
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
            HttpSecurityError::ForbiddenPreflight | HttpSecurityError::ForbiddenOrigin => {
                Self::forbidden("This endpoint does not accept requests from this origin.")
            }
            HttpSecurityError::MissingOrigin => {
                Self::forbidden("This request must come from a Piquel page, with an Origin header.")
            }
            HttpSecurityError::MissingCsrf => Self::forbidden(format!(
                "This request must come from a Piquel page, with the {CSRF_HEADER} header."
            )),
            HttpSecurityError::MissingForwardedAddress => {
                Self::bad_request("The proxy must send the client address in X-Forwarded-For.")
            }
            HttpSecurityError::MultipleForwardedHeaders => Self::bad_request(
                "The proxy must send exactly one X-Forwarded-For header, overwriting any other.",
            ),
            HttpSecurityError::ForwardedHeader(_) => {
                Self::bad_request("The proxy's X-Forwarded-For header is not valid text.")
            }
            HttpSecurityError::ForwardedAddress(_) => Self::bad_request(
                "The proxy's X-Forwarded-For header must hold exactly one IP address.",
            ),
            HttpSecurityError::RateLimited => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests. Please wait a minute.",
            ),
            HttpSecurityError::Timeout(_) => {
                Self::new(StatusCode::GATEWAY_TIMEOUT, "Request timed out.")
            }
            HttpSecurityError::Database(error) => error.into(),
            error @ (HttpSecurityError::MissingPeer | HttpSecurityError::MissingContext) => {
                Self::internal(error)
            }
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
    /// First-party frontend origins, allowed on account and login endpoints.
    pub frontends: FrontendOrigins,
}

impl HttpSecurity {
    /// Derives the shared HTTP policy from validated startup configuration.
    pub(crate) fn new(config: &crate::AuthConfig, database: Database) -> Self {
        Self {
            database,
            trusted_proxies: Arc::new(config.trusted_proxies.clone()),
            request_timeout: REQUEST_TIMEOUT,
            auth_origin: config.passkey.origin.serialized(),
            frontends: config.federation.frontends.clone(),
        }
    }

    /// Middleware for routers outside [`Self::protect`], such as the admin API:
    /// runs the request, body reads included, under the same deadline.
    pub(crate) async fn deadline(request: Request, next: Next) -> Response {
        tokio::time::timeout(REQUEST_TIMEOUT, next.run(request))
            .await
            .unwrap_or_else(|elapsed| {
                ApiError::from(HttpSecurityError::from(elapsed)).into_response()
            })
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
            .ok_or(HttpSecurityError::MissingForwardedAddress)?;
        if forwarded.next().is_some() {
            return Err(HttpSecurityError::MultipleForwardedHeaders);
        }
        Ok(header.to_str()?.parse()?)
    }

    /// Determines whether an exact browser origin may access this endpoint family.
    /// The back-channel and `UserInfo` endpoints also serve the redirect origins
    /// of enabled public clients. Those are looked up per request, so registration
    /// changes apply at once; same-origin and first-party requests skip the query.
    async fn allowed_origin(
        &self,
        endpoint: Endpoint,
        origin: &str,
    ) -> Result<bool, HttpSecurityError> {
        if matches!(endpoint, Endpoint::Discovery)
            || origin == self.auth_origin
            || (self.frontends.contains(origin)
                && matches!(endpoint, Endpoint::Account | Endpoint::Login))
        {
            return Ok(true);
        }
        if !matches!(endpoint, Endpoint::OAuthBackChannel | Endpoint::UserInfo) {
            return Ok(false);
        }
        Ok(self.database.oidc().public_client_origin(origin).await?)
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
        // Set by the origin check, which runs under the deadline; an error response
        // still carries CORS headers once the origin is known to be allowed.
        let mut allowed = false;
        let mut response = tokio::time::timeout(policy.request_timeout, async {
            if let Some(value) = origin.as_ref().and_then(|value| value.to_str().ok()) {
                allowed = policy.allowed_origin(endpoint, value).await?;
            }
            policy.dispatch(request, next, endpoint, allowed).await
        })
        .await
        .map_err(HttpSecurityError::from)
        .flatten()
        .unwrap_or_else(|error| ApiError::from(error).into_response());
        let grant = match endpoint {
            Endpoint::Discovery => Some(CorsGrant::Public),
            _ => origin.filter(|_| allowed).map(CorsGrant::Credentialed),
        };
        Self::decorate(&mut response, grant);
        response
    }

    /// Answers preflights, then checks browser proof and the request budget before the
    /// route, and attaches the [`RequestContext`] of rate-limited routes.
    async fn dispatch(
        &self,
        mut request: Request,
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
            && let Some(category) = endpoint.rate_category()
        {
            let client_ip = self.client_ip(&request)?;
            let bucket = Digest::sha256(format!("{category}:{client_ip}").as_bytes());
            if !self
                .database
                .security()
                .allow_request(bucket.as_bytes(), REQUESTS_PER_MINUTE)
                .await?
            {
                return Err(HttpSecurityError::RateLimited);
            }
            let context = RequestContext::new(client_ip, request.headers());
            request.extensions_mut().insert(context);
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
        if origin_present && !allowed {
            return Err(HttpSecurityError::ForbiddenOrigin);
        }
        if mutation && !allowed {
            return Err(HttpSecurityError::MissingOrigin);
        }
        if mutation && !headers.contains_key(CSRF_HEADER) {
            return Err(HttpSecurityError::MissingCsrf);
        }
        Ok(())
    }

    /// Adds cache and browser isolation headers, plus the CORS `grant` when set.
    fn decorate(response: &mut Response, grant: Option<CorsGrant>) {
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
        let origin = match grant {
            None => return,
            Some(CorsGrant::Public) => {
                for (name, value) in [
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    (header::ACCESS_CONTROL_ALLOW_HEADERS, "*"),
                    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"),
                ] {
                    headers.insert(name, HeaderValue::from_static(value));
                }
                return;
            }
            Some(CorsGrant::Credentialed(origin)) => origin,
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

/// Focused tests for this module and its security contracts, plus shared assertions.
#[cfg(test)]
pub(crate) mod tests;
