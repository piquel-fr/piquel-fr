//! Central-session policy values.

use chrono::{Duration as ChronoDuration, Utc};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, UserId};
use piquel_repository::{Database, DatabaseError, InsertSession, StoredSession};
use std::time::Duration;
use thiserror::Error;

/// Session creation input with minimized client metadata.
#[derive(Clone, Debug)]
pub(super) struct NewSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub methods: Vec<AuthenticationMethod>,
    pub ttl: Duration,
    pub user_agent_family: Option<String>,
}

#[derive(Debug, Error)]
pub(super) enum SessionError {
    #[error("invalid session")]
    InvalidSession,
    #[error("session operation failed")]
    Database(#[from] DatabaseError),
}

/// Requires bounded expiry and at least one actual authentication method.
pub(super) fn validate_new_session(session: &NewSession) -> Result<(), ()> {
    if session.methods.is_empty()
        || session.ttl.is_zero()
        || session.ttl > Duration::from_hours(720)
    {
        return Err(());
    }
    if session
        .user_agent_family
        .as_deref()
        .is_some_and(|value| value.len() > 100)
    {
        return Err(());
    }
    Ok(())
}

/// Creates a bounded central session for an active account.
pub(super) async fn create(
    database: &Database,
    session: NewSession,
) -> Result<StoredSession, SessionError> {
    validate_new_session(&session).map_err(|()| SessionError::InvalidSession)?;
    let authenticated_at = Utc::now();
    let ttl = ChronoDuration::from_std(session.ttl).map_err(|_| SessionError::InvalidSession)?;
    let expires_at = authenticated_at
        .checked_add_signed(ttl)
        .ok_or(SessionError::InvalidSession)?;
    database
        .sessions()
        .insert(&InsertSession {
            id: session.id,
            user_id: session.user_id,
            authentication_methods: session.methods,
            authenticated_at,
            expires_at,
            user_agent_family: session.user_agent_family,
        })
        .await
        .map_err(Into::into)
}

/// Resolves a session only while both it and its account remain active.
pub(super) async fn find_active(
    database: &Database,
    id: SessionId,
) -> Result<Option<StoredSession>, SessionError> {
    database
        .sessions()
        .find_active_by_id(id)
        .await
        .map_err(Into::into)
}

/// Advances activity tracking only for a currently usable session.
pub(super) async fn touch(database: &Database, id: SessionId) -> Result<bool, SessionError> {
    database.sessions().touch(id).await.map_err(Into::into)
}

/// Idempotently revokes a central session.
pub(super) async fn revoke(database: &Database, id: SessionId) -> Result<bool, SessionError> {
    database.sessions().revoke(id).await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_session() -> NewSession {
        NewSession {
            id: SessionId::new(),
            user_id: UserId::new(),
            methods: vec![AuthenticationMethod::Passkey],
            ttl: Duration::from_hours(1),
            user_agent_family: Some("Firefox".into()),
        }
    }

    #[test]
    fn session_creation_policy_is_bounded() {
        assert!(validate_new_session(&valid_session()).is_ok());

        let mut no_method = valid_session();
        no_method.methods.clear();
        assert!(validate_new_session(&no_method).is_err());

        let mut excessive_ttl = valid_session();
        excessive_ttl.ttl = Duration::from_hours(721);
        assert!(validate_new_session(&excessive_ttl).is_err());

        let mut excessive_metadata = valid_session();
        excessive_metadata.user_agent_family = Some("x".repeat(101));
        assert!(validate_new_session(&excessive_metadata).is_err());
    }
}
