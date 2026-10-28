//! Shared browser-session, passkey confirmation and HTTP trust boundaries.

use crate::recovery::ProbationPasskey;
use crate::routes::{ACCOUNT_PREFIX, oidc, page, service};
use axum::{
    Json,
    extract::{ConnectInfo, FromRef, FromRequestParts, MatchedPath, Request, State},
    http::{
        Extensions, HeaderMap, HeaderValue, Method, StatusCode,
        header::{self, InvalidHeaderValue},
        request::Parts,
        uri::Authority,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use ipnet::IpNet;
use piquel_common::{
    AuthenticationMethod, ClientId, ErrorChain, HandleError, PasskeyId, SessionId, UserId,
    config::Origin,
    events::{
        Actor, DomainEvent, EventContext, RequestOrigin, RevocationReason, SignInFailure,
        UserAgentFamily,
    },
    protocol::{
        api::{ErrorBody, ErrorCode},
        same_origin::BrowserRequest,
        step_up::StepUpRequirement,
    },
};
use piquel_crypto::{CryptoError, Digest, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertSession, LAST_SEEN_INTERVAL,
    SessionAuthentication, SessionScope, StoredSession,
};
use piquel_telemetry::{Counter, HttpTelemetry, Label};
use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};
use thiserror::Error;

/// Name of the browser proof required on non-protocol mutations.
pub(crate) const CSRF_HEADER: &str = "x-piquel-csrf";
/// Fetch metadata header naming how a request's initiator relates to its target.
const FETCH_SITE_HEADER: &str = "sec-fetch-site";
/// Trusted ingress must overwrite this header with exactly one client address.
const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
/// Request budget per category and client in each [`RATE_WINDOW`].
const REQUESTS_PER_MINUTE: i32 = 120;
/// Requests refused because their client's budget was exhausted, by category.
static THROTTLED: Counter<[Label; 1]> = Counter::new(
    "piquel.auth.throttled",
    "{request}",
    "Requests refused by rate limits, by rate category.",
);
/// The fixed window request budgets count in.
const RATE_WINDOW: StdDuration = StdDuration::from_mins(1);
/// Deadline includes origin checks, rate-limit persistence and the handler.
const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(30);
/// Browser session lifetime, also used by its host cookie.
pub(crate) const SESSION_LIFETIME_DAYS: u32 = 30;
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
    /// When a rate-limited client may try again, sent as `Retry-After`.
    retry_after: Option<StdDuration>,
}

impl ApiError {
    /// An error without a machine-readable code.
    fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            message: message.into(),
            code: None,
            retry_after: None,
        }
    }

    /// Adds the machine-readable `code` a frontend can resolve the error with.
    pub(crate) fn with_code(mut self, code: ErrorCode) -> Self {
        self.code = Some(code);
        self
    }

    /// What the user is told: the status and the message, as a page shows them.
    pub(crate) fn public(&self) -> (StatusCode, &str) {
        (self.status, &self.message)
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

    /// Rejects a request over its rate limit until its window ends.
    pub(crate) fn too_many_requests(
        message: impl Into<Cow<'static, str>>,
        window: StdDuration,
    ) -> Self {
        Self {
            retry_after: Some(window),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, message)
        }
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

impl From<HandleError> for ApiError {
    /// Says how to fix a refused handle, with `handle_invalid` or `handle_reserved`.
    fn from(error: HandleError) -> Self {
        let code = match error {
            HandleError::Length | HandleError::Charset => ErrorCode::HandleInvalid,
            HandleError::Reserved(_) => ErrorCode::HandleReserved,
        };
        Self::bad_request(format!("Choose another handle: {error}.")).with_code(code)
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
        if let Some(retry_after) = self.retry_after {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(retry_after.as_secs()),
            );
        }
        response
    }
}

piquel_common::str_enum! {
    /// Host-only cookies: browser secrets binding server-side state, and the notice
    /// of an account page's change just made.
    pub(crate) enum BrowserCookie {
        /// Central sign-in session.
        Session = "__Host-piquel_session",
        /// In-progress WebAuthn ceremony.
        Ceremony = "__Host-piquel_ceremony",
        /// Provider redirect awaiting its callback.
        Federation = "__Host-piquel_federation",
        /// Verified identity awaiting signup or linking.
        FederationPending = "__Host-piquel_federation_pending",
        /// What an account page's change just did, which the page it goes to says once.
        Notice = "__Host-piquel_notice",
        /// The admin dashboard's session, on the dashboard's own origin.
        Dashboard = "__Host-piquel_dashboard",
        /// A sign-in to the admin dashboard awaiting auth's handoff, on the
        /// dashboard's origin.
        DashboardState = "__Host-piquel_dashboard_state",
    }
}

impl BrowserCookie {
    /// Lifetime in seconds. Flow cookies outlive their server-side state slightly; a
    /// notice is shown on the page its change goes to, at once.
    const fn max_age(self) -> u32 {
        match self {
            Self::Session | Self::Dashboard => SESSION_LIFETIME_DAYS * 24 * 60 * 60,
            Self::Ceremony | Self::Federation | Self::FederationPending | Self::DashboardState => {
                FLOW_COOKIE_MAX_AGE
            }
            Self::Notice => 60,
        }
    }

    /// Reads this cookie's value. A duplicated cookie counts as absent, so an
    /// injected value can never shadow the browser's own.
    fn value(self, headers: &HeaderMap) -> Option<&str> {
        let mut values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|part| part.trim().strip_prefix(self.as_str())?.strip_prefix('='));
        let value = values.next()?;
        values.next().is_none().then_some(value)
    }

    /// Reads this cookie's secret, as [`Self::value`] reads it. A malformed one
    /// counts as absent too.
    pub(crate) fn read(self, headers: &HeaderMap) -> Option<Secret> {
        Secret::parse(self.value(headers)?).ok()
    }

    /// Adds a `Set-Cookie` header storing `secret` to an axum response or a page's,
    /// keeping any other cookies being set.
    pub(crate) fn set_on<B>(
        self,
        response: &mut axum::http::Response<B>,
        secret: &Secret,
    ) -> Result<(), InvalidHeaderValue> {
        self.append(response, &secret.encoded(), self.max_age())
    }

    /// The notice [`Self::Notice`] carries, of the change just made. An unknown or
    /// duplicated one counts as absent.
    pub(crate) fn read_notice(headers: &HeaderMap) -> Option<piquel_ui::Notice> {
        Self::Notice.value(headers)?.parse().ok()
    }

    /// Adds a `Set-Cookie` header storing `notice` in [`Self::Notice`], to the
    /// answer of the change it says was made.
    pub(crate) fn set_notice_on<B>(
        response: &mut axum::http::Response<B>,
        notice: piquel_ui::Notice,
    ) -> Result<(), InvalidHeaderValue> {
        Self::Notice.append(response, notice.as_str(), Self::Notice.max_age())
    }

    /// Adds a `Set-Cookie` header deleting this cookie, to an axum response or a page's.
    pub(crate) fn clear_on<B>(
        self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), InvalidHeaderValue> {
        self.append(response, "", 0)
    }

    /// Appends a host-only, `Secure`, `HttpOnly`, `SameSite=Lax` cookie header.
    fn append<B>(
        self,
        response: &mut axum::http::Response<B>,
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

/// What a browser proved who it is with, signing in or confirming its session: a
/// passkey, named so the session records which one, or a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Credential {
    /// This passkey's assertion, which confirms the session.
    Passkey(PasskeyId),
    /// The assertion of a recovery's passkey during its probation. It signs in
    /// like a provider does, without confirming the session, so no step-up
    /// requirement accepts it until the recovery settles.
    Probation(ProbationPasskey),
    /// A provider's verified identity.
    Federation,
}

impl Credential {
    /// The method sessions and events record.
    pub(crate) const fn method(self) -> AuthenticationMethod {
        match self {
            Self::Passkey(_) | Self::Probation(_) => AuthenticationMethod::Passkey,
            Self::Federation => AuthenticationMethod::Federation,
        }
    }

    /// The passkey, if one was used.
    const fn passkey(self) -> Option<PasskeyId> {
        match self {
            Self::Passkey(passkey) => Some(passkey),
            Self::Probation(probation) => Some(probation.passkey()),
            Self::Federation => None,
        }
    }

    /// The passkey, if one confirms the session.
    const fn confirming(self) -> Option<PasskeyId> {
        match self {
            Self::Passkey(passkey) => Some(passkey),
            Self::Probation(_) | Self::Federation => None,
        }
    }
}

/// For fixtures signing in without a real ceremony: a passkey sign-in names a
/// fresh passkey that is never stored.
#[cfg(test)]
impl From<AuthenticationMethod> for Credential {
    fn from(method: AuthenticationMethod) -> Self {
        match method {
            AuthenticationMethod::Passkey => Self::Passkey(PasskeyId::new()),
            AuthenticationMethod::Federation => Self::Federation,
        }
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
    /// A recovery's passkey during its probation tried to sign in to a browser
    /// whose session another passkey confirmed, which would lower its `acr`: the
    /// browser signs out first.
    #[error("a recovery's passkey cannot sign in to a session another passkey confirmed")]
    SignOutFirst,
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
            SessionError::StepUpRequired { max_age } => {
                Self::forbidden("Confirm with your passkey to continue.")
                    .with_code(ErrorCode::StepUpRequired { max_age })
            }
            SessionError::PasskeyRequired => {
                Self::forbidden("Sign in with your passkey to continue.")
                    .with_code(ErrorCode::PasskeyRequired)
            }
            SessionError::SignOutFirst => Self::forbidden(
                "This passkey was added by a recent recovery, so it can’t sign in to a browser that’s signed in with another passkey. Sign out first.",
            )
            .with_code(ErrorCode::PasskeyRequired),
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

    /// Looks up the browser's session like [`Self::optional`] and records its activity.
    /// The session extractors and authorization requests resolve sessions this way,
    /// so a browser that only signs in to applications still shows as active.
    pub(crate) async fn resolve(
        database: &Database,
        context: RequestContext,
        headers: &HeaderMap,
    ) -> Result<Option<StoredSession>, SessionError> {
        let session = Self::optional(database, headers).await?;
        if let Some(session) = &session {
            Self::touch(database, context, session).await?;
        }
        Ok(session)
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
        credential: Credential,
    ) -> Result<Secret, SessionError> {
        match Self::browser_session(tx, headers, user_id).await? {
            Some(current) if current.user_id == user_id => {
                let secret = Self::reauthenticate(tx, &current, credential).await?;
                tx.record(
                    &context.user(&current),
                    Some(user_id),
                    DomainEvent::SignedIn {
                        session_id: current.id,
                        method: credential.method(),
                    },
                )
                .await?;
                Ok(secret)
            }
            current => Self::replace(tx, context, current, user_id, credential).await,
        }
    }

    /// Signs `user_id` in on this browser with a new session, as [`Self::sign_in`]
    /// does, but never re-authenticates the browser's session: whatever session it
    /// had, of this account or another, is revoked first. A recovery link signs in
    /// this way, so an existing session can neither make it fail nor carry over.
    pub(crate) async fn sign_in_anew(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        headers: &HeaderMap,
        user_id: UserId,
        credential: Credential,
    ) -> Result<Secret, SessionError> {
        let current = Self::browser_session(tx, headers, user_id).await?;
        Self::replace(tx, context, current, user_id, credential).await
    }

    /// Locks `user_id`'s active account, then reads the session of the browser's
    /// cookie, if it has a live one.
    async fn browser_session(
        tx: &mut DatabaseTransaction<'_>,
        headers: &HeaderMap,
        user_id: UserId,
    ) -> Result<Option<StoredSession>, SessionError> {
        tx.users()
            .find_active_by_id_for_update(user_id)
            .await?
            .ok_or(SessionError::Missing)?;
        Ok(match BrowserCookie::Session.read(headers) {
            Some(cookie) => {
                tx.sessions()
                    .find_active_by_browser_secret(cookie.digest().as_bytes())
                    .await?
            }
            None => None,
        })
    }

    /// Revokes the browser's `current` session, if any, then creates `user_id`'s
    /// new one.
    async fn replace(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        current: Option<StoredSession>,
        user_id: UserId,
        credential: Credential,
    ) -> Result<Secret, SessionError> {
        if let Some(current) = current {
            Self::revoke(
                tx,
                context,
                &current,
                SessionScope::One(current.id),
                RevocationReason::AccountSwitched,
            )
            .await?;
        }
        Self::create(tx, context, user_id, credential).await
    }

    /// Records a new authentication of `session` with `credential` inside the
    /// caller's transaction, keeping its `sid`, and returns the secret for its new
    /// cookie. A passkey confirms the session, which records it. A social sign-in,
    /// or a recovery's passkey during its probation, renews it unless a passkey
    /// confirmed it, since that would lower its `acr`; a probation passkey is
    /// recorded too. Callers record the event that says why.
    ///
    /// The old cookie stops working, so a copy of it never gains the new
    /// authentication. Callers set the new cookie only after the transaction commits.
    pub(crate) async fn reauthenticate(
        tx: &mut DatabaseTransaction<'_>,
        session: &StoredSession,
        credential: Credential,
    ) -> Result<Secret, SessionError> {
        let now = Utc::now();
        match credential {
            Credential::Passkey(passkey) => {
                tx.sessions()
                    .confirm_passkey(session.id, passkey, now)
                    .await?;
            }
            Credential::Probation(probation) => {
                if session.passkey_confirmed_at.is_some() {
                    return Err(SessionError::SignOutFirst);
                }
                tx.sessions()
                    .reauthenticate_unconfirmed(session.id, Some(probation.passkey()), now)
                    .await?;
            }
            Credential::Federation => {
                if session.passkey_confirmed_at.is_some() {
                    return Err(SessionError::PasskeyRequired);
                }
                tx.sessions()
                    .reauthenticate_unconfirmed(session.id, None, now)
                    .await?;
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
    /// so an action right after it prompts no more, unless it is a recovery's
    /// passkey during its probation. The session records which passkey it was.
    pub(crate) async fn create(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        user_id: UserId,
        credential: Credential,
    ) -> Result<Secret, SessionError> {
        let method = credential.method();
        let now = Utc::now();
        let id = SessionId::new();
        tx.sessions()
            .insert(&InsertSession {
                id,
                user_id,
                authentication_methods: vec![method],
                authenticated_at: now,
                expires_at: now + Duration::days(i64::from(SESSION_LIFETIME_DAYS)),
                user_agent_family: context.user_agent_family,
                ip: context.client_ip,
                passkey_confirmed_at: credential.confirming().map(|_| now),
                passkey_id: credential.passkey(),
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

    /// Revokes the `scope` sessions of `session`'s account inside the caller's
    /// transaction, with their refresh grants, recording one revocation per session,
    /// attributed to `session`, which tells their clients. Returns the revoked sessions.
    pub(crate) async fn revoke(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        session: &StoredSession,
        scope: SessionScope,
        reason: RevocationReason,
    ) -> Result<Vec<SessionId>, DatabaseError> {
        tx.revoke_sessions(&context.user(session), session.user_id, scope, &reason)
            .await
    }

    /// Records the session's activity from `context`, at most once every
    /// [`LAST_SEEN_INTERVAL`]: a session seen more recently is not written.
    async fn touch(
        database: &Database,
        context: RequestContext,
        session: &StoredSession,
    ) -> Result<(), DatabaseError> {
        if session.last_seen_at > Utc::now() - LAST_SEEN_INTERVAL {
            return Ok(());
        }
        database
            .sessions()
            .touch(session.id, context.client_ip)
            .await
    }
}

/// Where a request came from, attached by [`HttpSecurity::protect`] to every
/// rate-limited route and extracted by handlers that record events and by the
/// session extractors. The raw `User-Agent` header is classified, never kept.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestContext {
    /// The client's IP address.
    pub client_ip: IpAddr,
    /// The coarse browser and platform of its `User-Agent` header.
    pub user_agent_family: UserAgentFamily,
}

impl RequestContext {
    /// The client IP and the coarse family of its `User-Agent` header.
    fn new(client_ip: IpAddr, headers: &HeaderMap) -> Self {
        Self {
            client_ip,
            user_agent_family: UserAgentFamily::classify(
                headers
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default(),
            ),
        }
    }

    /// Attributes events of this request to `actor`.
    pub(crate) fn actor(self, actor: Actor) -> EventContext {
        EventContext {
            actor,
            origin: RequestOrigin {
                client_ip: Some(self.client_ip),
                user_agent_family: Some(self.user_agent_family),
            },
            reason: None,
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

impl RequestContext {
    /// The context [`HttpSecurity::protect`] attached to a request's `extensions`. Only
    /// routes with a rate budget have one.
    pub(crate) fn of(extensions: &Extensions) -> Result<Self, HttpSecurityError> {
        extensions
            .get::<Self>()
            .copied()
            .ok_or(HttpSecurityError::MissingContext)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = ApiError;
    /// Reads the context [`HttpSecurity::protect`] attached.
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::of(&parts.extensions).map_err(ApiError::from))
    }
}

/// Required active browser session extracted before the handler runs.
pub(crate) struct Session(pub StoredSession);
/// Optional browser session for anonymous or signed-in requests.
pub(crate) struct OptionalSession(pub Option<StoredSession>);
/// Browser session whose passkey confirmation is at most `MAX_AGE` seconds old: it
/// meets [`StepUpRequirement::passkey_within`], checked against the `acr` and
/// `auth_time` tokens would report, as bearer-protected resources check them. The
/// age counts from the confirmation itself, so using it never extends it. Account
/// operations check it again under the account lock (`Owner::lock_confirmed`).
pub(crate) struct Confirmed<const MAX_AGE: u32 = CONFIRMATION_MAX_AGE>(pub StoredSession);

impl<const MAX_AGE: u32> Confirmed<MAX_AGE> {
    /// What the session's authentication must meet.
    const REQUIREMENT: StepUpRequirement = StepUpRequirement::passkey_within(MAX_AGE);

    /// Rejects a session without a recent enough passkey confirmation. Handlers
    /// that need one only for some changes call it on the session they locked.
    pub(crate) fn check(session: &StoredSession) -> Result<(), SessionError> {
        let authentication = SessionAuthentication::from(session);
        Self::REQUIREMENT
            .check(
                Some(&authentication.acr),
                Some(authentication.auth_time),
                Utc::now(),
            )
            .map_err(|_| SessionError::StepUpRequired { max_age: MAX_AGE })
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

impl<S> FromRequestParts<S> for OptionalSession
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// Resolves the browser's session with [`Session::resolve`], so no handler
    /// records its activity by hand.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = RequestContext::from_request_parts(parts, state).await?;
        Ok(Self(
            Session::resolve(&Database::from_ref(state), context, &parts.headers).await?,
        ))
    }
}

impl<S> FromRequestParts<S> for Session
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// Extracts the [`OptionalSession`], requiring that there is one.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let OptionalSession(session) = OptionalSession::from_request_parts(parts, state).await?;
        Ok(Self(session.ok_or(SessionError::Missing)?))
    }
}

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
    /// RP-initiated logout, validated by its own hint, which only sends the browser to
    /// confirm on the logout page.
    Logout,
    /// The account's JSON APIs, which browsers may call only from auth's own pages.
    Account,
    /// Auth's server-rendered pages, sign-in included, which anyone may navigate to,
    /// and the forms they post.
    Page,
    /// The admin dashboard's pages, the admin listener's only routes, and the forms
    /// they post.
    Dashboard,
    /// Passkey ceremonies, the providers' callbacks and the other auth-origin
    /// routes.
    Other,
}

impl Endpoint {
    /// Classifies `request` by the template of the route it matched, so that a page
    /// whose path names an app is a page, or by its path when no route matched.
    fn of(request: &Request) -> Self {
        Self::classify(
            request
                .extensions()
                .get::<MatchedPath>()
                .map_or(request.uri().path(), MatchedPath::as_str),
        )
    }

    /// Classifies a route's template, or an unmatched path: exact protocol and page
    /// routes, and the account route family.
    fn classify(path: &str) -> Self {
        match path {
            oidc::TOKEN | oidc::REVOKE | oidc::PAR => Self::OAuthBackChannel,
            oidc::USERINFO => Self::UserInfo,
            oidc::DISCOVERY | oidc::OAUTH_METADATA | oidc::JWKS => Self::Discovery,
            service::LIVE | service::READY => Self::Health,
            oidc::AUTHORIZE => Self::Authorize,
            oidc::LOGOUT => Self::Logout,
            // The root and a page's path ending in a slash redirect to a page.
            page::ROOT => Self::Page,
            _ if page::ALL.contains(&path.strip_suffix('/').unwrap_or(path)) => Self::Page,
            _ if path.starts_with(ACCOUNT_PREFIX) => Self::Account,
            _ => Self::Other,
        }
    }

    /// Protocol handlers enforce their own credentials and navigation checks.
    const fn is_protocol(self) -> bool {
        match self {
            Self::OAuthBackChannel | Self::UserInfo | Self::Authorize | Self::Logout => true,
            Self::Discovery
            | Self::Health
            | Self::Account
            | Self::Page
            | Self::Dashboard
            | Self::Other => false,
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
            Self::Authorize | Self::Logout | Self::Other => Some(RateCategory::Login),
            Self::Page => Some(RateCategory::Page),
            Self::Dashboard => Some(RateCategory::Dashboard),
            Self::Discovery | Self::Health => None,
        }
    }
}

piquel_common::str_enum! {
    /// Independent request budgets persisted under stable category names, so one kind of
    /// traffic from a client cannot exhaust another: a relying party's `UserInfo` calls
    /// never block its code exchanges, and browsing auth's pages never blocks a passkey
    /// ceremony or an authorization.
    enum RateCategory {
        /// OAuth credential exchanges and revocation.
        Token = "token",
        /// Bearer-token claim lookups by relying parties.
        UserInfo = "userinfo",
        /// The account JSON APIs' reads and mutations.
        Account = "account",
        /// Passkey ceremonies, providers' callbacks, authorization, logout and the
        /// other auth-origin routes.
        Login = "login",
        /// Auth's server-rendered pages, sign-in included, and the forms they post.
        Page = "page",
        /// The admin dashboard's pages and forms.
        Dashboard = "dashboard",
    }
}

/// The CORS headers a response carries.
enum CorsGrant {
    /// Public, credential-free documents that any origin may read.
    Public,
    /// An approved origin, which calls without the browser's cookies: a public
    /// client's, on the back channel and userinfo. Auth's own pages need no grant,
    /// being same-origin.
    Client(HeaderValue),
}

/// Who may store a response, and for how long. Handlers choose a class with [`Cached`];
/// [`HttpSecurity::decorate`] enforces it on every response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheClass {
    /// Never stored: pages, APIs, OAuth, errors and every response without a class.
    NoStore,
    /// Content-addressed build assets, which any cache may keep for a year.
    Immutable,
    /// Public, credential-free data, the same for every caller and readable from any
    /// origin. Its route must accept any `Origin` and never read the session.
    Public { max_age: StdDuration },
}

impl CacheClass {
    /// The class a response keeps: its handler's, unless it sets a cookie or is
    /// anything but a success.
    fn enforced(response: &Response) -> Self {
        match response.extensions().get::<Self>() {
            Some(&class)
                if response.status() == StatusCode::OK
                    && !response.headers().contains_key(header::SET_COOKIE) =>
            {
                class
            }
            _ => Self::NoStore,
        }
    }

    /// The `Cache-Control` value of this class. Every value forbids transforming the
    /// body: Cloudflare's edge would otherwise rewrite pages, hiding email addresses
    /// behind a decoding script the Content-Security-Policy blocks.
    fn cache_control(self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Self::NoStore => "no-store, no-transform",
            Self::Immutable => "public, max-age=31536000, immutable, no-transform",
            Self::Public { max_age } => {
                // Digits and fixed text always form a valid header value.
                return HeaderValue::try_from(format!(
                    "public, max-age={}, no-transform",
                    max_age.as_secs()
                ))
                .unwrap_or(HeaderValue::from_static("no-store, no-transform"));
            }
        })
    }
}

/// The only way to mark a response cacheable: wraps a handler's response with its class.
pub(crate) struct Cached<T>(pub CacheClass, pub T);

impl<T: IntoResponse> IntoResponse for Cached<T> {
    /// Attaches the class for [`HttpSecurity::decorate`] to enforce.
    fn into_response(self) -> Response {
        let mut response = self.1.into_response();
        response.extensions_mut().insert(self.0);
        response
    }
}

/// Failures in shared HTTP trust checks, preserving actionable internal sources.
#[derive(Debug, Error)]
pub(crate) enum HttpSecurityError {
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
    /// A form was posted to one of auth's pages from somewhere else.
    #[error("page form posted from another origin")]
    ForeignForm,
    /// The request names a host this listener does not serve.
    #[error("request host is not this listener's")]
    WrongHost,
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
            HttpSecurityError::ForeignForm => {
                Self::forbidden("Submit this form from its page on this site.")
            }
            HttpSecurityError::WrongHost => Self::new(
                StatusCode::MISDIRECTED_REQUEST,
                "This host is not served here.",
            ),
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
            HttpSecurityError::RateLimited => {
                Self::too_many_requests("Too many requests. Please wait a minute.", RATE_WINDOW)
            }
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

/// Shared origin, proxy, timeout and request-limit policy, one per listener.
#[derive(Clone)]
pub(crate) struct HttpSecurity {
    /// Stores the rate-limit counters.
    pub database: Database,
    /// Peers allowed to report the client IP in `X-Forwarded-For`.
    pub trusted_proxies: Arc<Vec<IpNet>>,
    /// Deadline for the whole request, handler included.
    pub request_timeout: StdDuration,
    /// Origin of the listener's own pages, allowed on every endpoint.
    pub origin: url::Origin,
    /// Which listener it guards.
    listener: Listener,
}

/// The listener an [`HttpSecurity`] guards.
#[derive(Clone)]
enum Listener {
    /// Auth's public listener: protocol endpoints, JSON APIs and pages, each
    /// classified by its route.
    Public,
    /// The admin listener, which serves only the dashboard's pages, and only to
    /// requests naming the dashboard's host, this `Host` header value: a request
    /// reaching it under another name, by a misrouted ingress or a rebound DNS
    /// name, is refused before anything runs.
    Admin(HeaderValue),
}

impl HttpSecurity {
    /// Derives the public listener's policy from validated startup configuration.
    pub(crate) fn new(config: &crate::AuthConfig, database: Database) -> Self {
        Self {
            database,
            trusted_proxies: Arc::new(config.trusted_proxies.clone()),
            request_timeout: REQUEST_TIMEOUT,
            origin: config.passkey.origin.as_url().origin(),
            listener: Listener::Public,
        }
    }

    /// Derives the admin listener's policy, for the dashboard at `dashboard`, from
    /// validated startup configuration.
    pub(crate) fn admin(
        config: &crate::AuthConfig,
        database: Database,
        dashboard: &Origin,
    ) -> Result<Self, InvalidHeaderValue> {
        // What browsers send: the host, and the port unless it is the scheme's own.
        let host = match dashboard.as_url().port() {
            Some(port) => format!("{}:{port}", dashboard.host()),
            None => dashboard.host().to_owned(),
        };
        Ok(Self {
            listener: Listener::Admin(HeaderValue::from_str(&host)?),
            origin: dashboard.as_url().origin(),
            ..Self::new(config, database)
        })
    }

    /// Refuses a request to the admin listener that names another host, by its
    /// `Host` header or, over HTTP/2, its authority.
    fn check_host(&self, request: &Request) -> Result<(), HttpSecurityError> {
        let Listener::Admin(expected) = &self.listener else {
            return Ok(());
        };
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|host| host.to_str().ok())
            .or_else(|| request.uri().authority().map(Authority::as_str));
        match host {
            Some(host) if host.eq_ignore_ascii_case(expected.to_str().unwrap_or_default()) => {
                Ok(())
            }
            _ => Err(HttpSecurityError::WrongHost),
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
            .ok_or(HttpSecurityError::MissingForwardedAddress)?;
        if forwarded.next().is_some() {
            return Err(HttpSecurityError::MultipleForwardedHeaders);
        }
        Ok(header.to_str()?.parse()?)
    }

    /// Determines whether an exact browser origin may access this endpoint family:
    /// any origin reads discovery, and auth's own pages reach every endpoint. The
    /// back-channel and `UserInfo` endpoints also serve the redirect origins of
    /// enabled public clients. Those are looked up per request, so registration
    /// changes apply at once; same-origin requests skip the query.
    async fn allowed_origin(
        &self,
        endpoint: Endpoint,
        origin: &str,
    ) -> Result<bool, HttpSecurityError> {
        if matches!(endpoint, Endpoint::Discovery) || origin == self.origin.ascii_serialization() {
            return Ok(true);
        }
        if !matches!(endpoint, Endpoint::OAuthBackChannel | Endpoint::UserInfo) {
            return Ok(false);
        }
        Ok(self.database.oidc().public_client_origin(origin).await?)
    }

    /// Middleware: runs the trust checks and the handler under one deadline, then adds the
    /// cache, isolation and CORS headers to every response, errors included.
    /// Discovery's errors and preflights get the public grant from their endpoint.
    pub(crate) async fn protect(
        State(policy): State<Self>,
        request: Request,
        next: Next,
    ) -> Response {
        // Reuse the original header for CORS so decoration cannot fail during re-parsing.
        let origin = request.headers().get(header::ORIGIN).cloned();
        let endpoint = match policy.listener {
            Listener::Public => Endpoint::of(&request),
            Listener::Admin(_) => Endpoint::Dashboard,
        };
        // Set by the origin check, which runs under the deadline; an error response
        // still carries CORS headers once the origin is known to be allowed.
        let mut allowed = false;
        let mut response = tokio::time::timeout(policy.request_timeout, async {
            policy.check_host(&request)?;
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
            _ => origin.filter(|_| allowed).map(CorsGrant::Client),
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
        Self::check_browser(endpoint, request.headers(), allowed, mutation, &self.origin)?;
        // Unknown paths have no `MatchedPath`: they never consume a budget or need peer metadata.
        if request.extensions().get::<MatchedPath>().is_some()
            && let Some(category) = endpoint.rate_category()
        {
            let client_ip = self.client_ip(&request)?;
            let bucket = Digest::sha256(format!("{category}:{client_ip}").as_bytes());
            if !self
                .database
                .security()
                .allow_request(bucket.as_bytes(), REQUESTS_PER_MINUTE, RATE_WINDOW)
                .await?
            {
                THROTTLED.add(1, &[("category", category.as_str())]);
                return Err(HttpSecurityError::RateLimited);
            }
            let context = RequestContext::new(client_ip, request.headers());
            request.extensions_mut().insert(context);
        }
        Ok(next.run(request).await)
    }

    /// Rejects unapproved browser origins and mutations without CSRF proof. Protocol
    /// endpoints are exempt: their handlers check credentials and navigation themselves.
    /// Pages take any navigation, but a form only from `site`'s own pages
    /// ([`BrowserRequest::is_same_origin`]): a plain form cannot send the CSRF header,
    /// and sends `Origin: null` under `Referrer-Policy: no-referrer`.
    fn check_browser(
        endpoint: Endpoint,
        headers: &HeaderMap,
        allowed: bool,
        mutation: bool,
        site: &url::Origin,
    ) -> Result<(), HttpSecurityError> {
        if endpoint.is_protocol() {
            return Ok(());
        }
        if matches!(endpoint, Endpoint::Page | Endpoint::Dashboard) {
            let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
            let request = BrowserRequest {
                fetch_site: text(FETCH_SITE_HEADER),
                origin: text(header::ORIGIN.as_str()),
            };
            return if !mutation || request.is_same_origin(site) {
                Ok(())
            } else {
                Err(HttpSecurityError::ForeignForm)
            };
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

    /// Adds the enforced [`CacheClass`] and browser isolation headers, plus the CORS
    /// `grant` when set. A cacheable response is the same for every origin, so public
    /// data is granted to all origins and other cached responses to none.
    fn decorate(response: &mut Response, grant: Option<CorsGrant>) {
        let class = CacheClass::enforced(response);
        let grant = match class {
            CacheClass::NoStore => grant,
            CacheClass::Public { .. } => Some(CorsGrant::Public),
            CacheClass::Immutable => None,
        };
        let headers = response.headers_mut();
        // Replaces any handler value: only the class decides.
        headers.insert(header::CACHE_CONTROL, class.cache_control());
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
            Some(CorsGrant::Client(origin)) => origin,
        };
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        for (name, value) in [
            (
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "content-type, authorization",
            ),
            (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
            (header::VARY, "Origin"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        // Lets cross-origin callers, such as public clients, read the trace ID of a
        // failed request.
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HttpTelemetry::TRACE_ID_HEADER.into(),
        );
    }
}

/// Focused tests for this module and its security contracts, plus shared assertions.
#[cfg(test)]
pub(crate) mod tests;
