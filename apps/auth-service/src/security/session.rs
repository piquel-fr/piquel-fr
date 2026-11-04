//! Browser sessions: signing in, re-authenticating, revoking, and the extractors
//! requiring a session, or its recent passkey confirmation, before a handler runs.

use super::{ApiError, BrowserCookie, CONFIRMATION_MAX_AGE, RequestContext, SESSION_LIFETIME_DAYS};
use crate::recovery::ProbationPasskey;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, request::Parts},
};
use chrono::{Duration, Utc};
use piquel_common::{
    AuthenticationMethod, PasskeyId, SessionId, UserId,
    events::{DomainEvent, EventContext, InlineSignIn, RevocationReason},
    protocol::{api::ErrorCode, step_up::StepUpRequirement},
};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertSession, LAST_SEEN_INTERVAL,
    SessionAuthentication, SessionScope, StoredSession,
};
use thiserror::Error;

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

    /// Ends every session of the account, recording each revocation as `context`
    /// says, which tells their clients, then revokes every refresh grant, those of
    /// sessions that already expired included. Callers hold the account lock.
    pub(crate) async fn end_all(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user_id: UserId,
        reason: RevocationReason,
    ) -> Result<(), DatabaseError> {
        tx.revoke_sessions(context, user_id, SessionScope::All, &reason)
            .await?;
        tx.tokens().revoke_for_user(user_id, None).await?;
        Ok(())
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
                        inline: None,
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
        let session = Self::insert(tx, context, user_id, credential, None).await?;
        let secret = Secret::generate()?;
        tx.sessions()
            .insert_browser_secret(session.id, secret.digest().as_bytes())
            .await?;
        Ok(secret)
    }

    /// Creates the session of a sign-in with `credential` on an application's page,
    /// inside the caller's transaction, and records the sign-in. It has no browser
    /// secret, so no auth cookie: only the tokens the client gets from it use it.
    pub(crate) async fn create_inline(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        user_id: UserId,
        credential: Credential,
        inline: InlineSignIn,
    ) -> Result<StoredSession, SessionError> {
        Self::insert(tx, context, user_id, credential, Some(inline)).await
    }

    /// Inserts a session, confirmed and naming its passkey if `credential` is one,
    /// and records the sign-in, on an application's page when `inline` says so.
    async fn insert(
        tx: &mut DatabaseTransaction<'_>,
        context: RequestContext,
        user_id: UserId,
        credential: Credential,
        inline: Option<InlineSignIn>,
    ) -> Result<StoredSession, SessionError> {
        let method = credential.method();
        let now = Utc::now();
        let session = tx
            .sessions()
            .insert(&InsertSession {
                id: SessionId::new(),
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
        tx.record(
            &context.user(&session),
            Some(user_id),
            DomainEvent::SignedIn {
                session_id: session.id,
                method,
                inline,
            },
        )
        .await?;
        Ok(session)
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
