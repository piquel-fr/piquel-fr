//! The account's sessions, one per signed-in browser, and signing them out:
//! settings any administrator may also change, which [`AccountService`] serves.
use crate::account::{AccountError, AccountService, ActingAs, Subject};
use chrono::{DateTime, Utc};
use piquel_common::{
    AuthenticationMethod, SessionId,
    events::{RevocationReason, UserAgentFamily},
};
use piquel_repository::{SessionScope, StoredSession};
use serde::Serialize;
use std::net::IpAddr;

/// Sign-out failures and their browser response mapping.
mod error;
pub(crate) use error::SessionsError;

/// One active session of the account.
#[derive(Serialize)]
pub(crate) struct SessionItem {
    /// Session ID, to sign it out.
    pub(crate) id: SessionId,
    /// Whether it is the session making the request; never, when someone other
    /// than the owner asks.
    pub(crate) current: bool,
    /// The browser and platform it signed in with, if recorded.
    pub(crate) device: Option<UserAgentFamily>,
    /// The IP address of its last recorded activity, if recorded.
    pub(crate) ip: Option<IpAddr>,
    /// How it authenticated.
    pub(crate) methods: Vec<AuthenticationMethod>,
    /// When it signed in.
    pub(crate) authenticated_at: DateTime<Utc>,
    /// Its last recorded activity, refreshed at most every few minutes.
    pub(crate) last_seen_at: DateTime<Utc>,
    /// When it expires.
    pub(crate) expires_at: DateTime<Utc>,
}

/// The answer to signing every other session out.
#[derive(Serialize)]
pub(crate) struct Revoked {
    /// How many sessions were signed out.
    pub(crate) revoked: usize,
}

impl SessionItem {
    /// Shows `session`, marking it if it is the `current` one.
    fn new(session: StoredSession, current: Option<SessionId>) -> Self {
        Self {
            current: Some(session.id) == current,
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

/// Sessions any administrator may also sign out. Signing out needs no passkey
/// confirmation: it only removes access, and a user who suspects a stolen cookie
/// must be able to act at once.
impl AccountService {
    /// Lists the account's active sessions, most recently active first. On the
    /// owner mount, the extractor has just recorded the owner's own activity.
    pub(crate) async fn sessions(
        &self,
        subject: &Subject,
    ) -> Result<Vec<SessionItem>, AccountError> {
        subject.viewed(&self.database).await?;
        Ok(self
            .database
            .sessions()
            .list_active_for_user(subject.user)
            .await?
            .into_iter()
            .map(|session| SessionItem::new(session, subject.own_session()))
            .collect())
    }

    /// Signs one session of the account out, with its applications' refresh
    /// grants. The owner's own session signs out through `/session/logout`, which
    /// also clears its cookie.
    pub(crate) async fn revoke_session(
        &self,
        subject: &Subject,
        id: SessionId,
    ) -> Result<(), AccountError> {
        if subject.own_session() == Some(id) {
            return Err(SessionsError::Current.into());
        }
        if self.end(subject, SessionScope::One(id)).await?.is_empty() {
            return Err(SessionsError::NotFound.into());
        }
        Ok(())
    }

    /// Signs every other session of the account out, with their applications'
    /// refresh grants, and says how many there were: all but the owner's own, or
    /// every one when someone else acts.
    pub(crate) async fn revoke_other_sessions(
        &self,
        subject: &Subject,
    ) -> Result<Revoked, AccountError> {
        let revoked = self.end(subject, subject.others()).await?;
        Ok(Revoked {
            revoked: revoked.len(),
        })
    }

    /// Ends the `scope` sessions of the account in one transaction, under the
    /// account lock, and returns the ones it ended.
    async fn end(
        &self,
        subject: &Subject,
        scope: SessionScope,
    ) -> Result<Vec<SessionId>, AccountError> {
        let reason = match subject.by {
            ActingAs::Owner { .. } => RevocationReason::UserRevoked,
            ActingAs::Operator { .. } => RevocationReason::Admin,
        };
        let mut tx = self.database.begin().await?;
        subject.lock(&mut tx).await?;
        let revoked = tx
            .revoke_sessions(&subject.context(), subject.user, scope, &reason)
            .await?;
        subject.commit(tx).await?;
        Ok(revoked)
    }
}

/// Database-backed listing and sign-out scenarios.
#[cfg(test)]
mod tests;
