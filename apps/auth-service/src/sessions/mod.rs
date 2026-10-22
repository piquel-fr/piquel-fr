//! The signed-in user's sessions, one per signed-in browser, and signing them out.
use crate::routes;
use crate::security::{self, ApiError, RequestContext};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use piquel_common::{
    AuthenticationMethod, SessionId,
    events::{RevocationReason, UserAgentFamily},
};
use piquel_repository::{Database, SessionScope, StoredSession};
use serde::Serialize;
use std::net::IpAddr;

/// Sign-out failures and their browser response mapping.
mod error;
use error::SessionsError;

/// The account's sessions.
#[derive(Clone)]
pub(crate) struct SessionsApplication {
    /// Sessions, their refresh families and events.
    database: Database,
}

/// One active session of the account.
#[derive(Serialize)]
struct SessionItem {
    /// Session ID, to sign it out.
    id: SessionId,
    /// Whether it is the session making the request.
    current: bool,
    /// The browser and platform it signed in with, if recorded.
    device: Option<UserAgentFamily>,
    /// The IP address of its last recorded activity, if recorded.
    ip: Option<IpAddr>,
    /// How it authenticated.
    methods: Vec<AuthenticationMethod>,
    /// When it signed in.
    authenticated_at: DateTime<Utc>,
    /// Its last recorded activity, refreshed at most every few minutes.
    last_seen_at: DateTime<Utc>,
    /// When it expires.
    expires_at: DateTime<Utc>,
}

/// The answer to signing every other session out.
#[derive(Serialize)]
struct Revoked {
    /// How many sessions were signed out.
    revoked: usize,
}

impl SessionItem {
    /// Shows `session`, marking it if it is the `current` one.
    fn new(session: StoredSession, current: SessionId) -> Self {
        Self {
            current: session.id == current,
            id: session.id,
            device: session.user_agent_family,
            ip: session.last_seen_ip,
            methods: session.authentication_methods,
            authenticated_at: session.authenticated_at,
            last_seen_at: session.last_seen_at,
            expires_at: session.expires_at,
        }
    }
}

impl SessionsApplication {
    /// Serves the sessions from `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Returns the session endpoints with this application as state.
    ///
    /// Signing out needs a session but no passkey confirmation: it only removes
    /// access, and a user who suspects a stolen cookie must be able to act at once.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::sessions::LIST, get(Self::list))
            .route(routes::sessions::ITEM, delete(Self::revoke))
            .route(routes::sessions::REVOKE_OTHERS, post(Self::revoke_others))
            .with_state(self)
    }

    /// Lists the account's active sessions, most recently active first. The
    /// extractor has just recorded the current session's activity.
    async fn list(
        State(app): State<Self>,
        security::Session(session): security::Session,
    ) -> Result<Json<Vec<SessionItem>>, ApiError> {
        Ok(Json(
            app.database
                .sessions()
                .list_active_for_user(session.user_id)
                .await?
                .into_iter()
                .map(|item| SessionItem::new(item, session.id))
                .collect(),
        ))
    }

    /// Signs one other session of the account out, with its applications' refresh
    /// grants. The current session signs out through `/session/logout`, which also
    /// clears its cookie.
    async fn revoke(
        State(app): State<Self>,
        context: RequestContext,
        security::Session(session): security::Session,
        Path(id): Path<SessionId>,
    ) -> Result<StatusCode, ApiError> {
        if id == session.id {
            return Err(SessionsError::Current.into());
        }
        if app
            .end(context, &session, SessionScope::One(id))
            .await?
            .is_empty()
        {
            return Err(SessionsError::NotFound.into());
        }
        Ok(StatusCode::NO_CONTENT)
    }

    /// Signs every other session of the account out, with their applications'
    /// refresh grants, and says how many there were.
    async fn revoke_others(
        State(app): State<Self>,
        context: RequestContext,
        security::Session(session): security::Session,
    ) -> Result<Json<Revoked>, ApiError> {
        let revoked = app
            .end(context, &session, SessionScope::AllExcept(session.id))
            .await?;
        Ok(Json(Revoked {
            revoked: revoked.len(),
        }))
    }

    /// Ends the `scope` sessions of `session`'s account in one transaction, under
    /// [`security::Session::lock`], and returns the ones it ended.
    async fn end(
        &self,
        context: RequestContext,
        session: &StoredSession,
        scope: SessionScope,
    ) -> Result<Vec<SessionId>, ApiError> {
        let mut tx = self.database.begin().await?;
        security::Session::lock(&mut tx, session).await?;
        let revoked = security::Session::revoke(
            &mut tx,
            context,
            session,
            scope,
            RevocationReason::UserRevoked,
        )
        .await?;
        tx.commit().await?;
        Ok(revoked)
    }
}

/// Supplies the shared database boundary to browser-session extractors.
impl axum::extract::FromRef<SessionsApplication> for Database {
    /// Shares persistence with the session extractors.
    fn from_ref(application: &SessionsApplication) -> Self {
        application.database.clone()
    }
}

/// Database-backed listing and sign-out scenarios.
#[cfg(test)]
mod tests;
