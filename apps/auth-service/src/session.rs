//! Central-session policy values.

use piquel_auth_protocol::{AuthenticationMethod, SessionId, UserId};
use std::time::Duration;

/// Session creation input with minimized client metadata.
#[derive(Clone, Debug)]
pub(super) struct NewSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub methods: Vec<AuthenticationMethod>,
    pub ttl: Duration,
    pub user_agent_family: Option<String>,
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
