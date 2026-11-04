//! Reading the request's session, and refreshing its access token under the
//! lease the SDK keeps in the session record, so one request at a time calls auth.

use super::{Login, SignedIn};
use crate::axum::{
    StoredLogin,
    bearer::ErrorChain,
    session::{BackendError, Lease, LeaseId, Session, SessionKey},
};
use axum::http::HeaderMap;
use chrono::{DateTime, TimeDelta, Utc};
use std::time::Duration;

/// Access tokens this close to expiry are refreshed first.
const REFRESH_MARGIN: TimeDelta = TimeDelta::seconds(30);
/// Longest a refresh may take, auth's response and its ID token check included.
const REFRESH_DEADLINE: Duration = Duration::from_secs(20);
/// Time kept back from a lease for saving its result, so the save lands before the
/// lease expires even when the backend is slow.
const SAVE_MARGIN: TimeDelta = TimeDelta::seconds(10);
/// How long a refresh lease lasts if its holder never releases it.
const REFRESH_LEASE: Duration = Duration::from_secs(60);
/// How long a request waits for another's refresh before using what it has.
const REFRESH_WAIT: Duration = Duration::from_secs(25);
/// How often a request waiting for another's refresh reloads the session.
const REFRESH_POLL: Duration = Duration::from_millis(50);

impl Login {
    /// The signed-in session the request's cookie names, its access token refreshed
    /// when it is about to expire.
    /// `retry` marks a request returning from a step-up login.
    pub(super) async fn session(
        &self,
        headers: &HeaderMap,
        retry: bool,
    ) -> Result<Option<SignedIn>, BackendError> {
        let Some(key) = Self::cookie(headers, &self.cookies.session).and_then(SessionKey::parse)
        else {
            return Ok(None);
        };
        let Some(mut current) = self.sessions.load(&key, self.now()).await? else {
            return Ok(None);
        };
        let login = &current.login;
        if login.refresh_token().is_some() && login.expires_at() <= self.now() + REFRESH_MARGIN {
            match self.refresh(&key, current).await? {
                Some(refreshed) => current = refreshed,
                None => return Ok(None),
            }
        }
        Ok(Some(SignedIn {
            login: current.login,
            checked_at: self.now(),
            retry,
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
            Lease::Acquired(until) => self.refresh_leased(key, &lease, until, current).await,
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

    /// Refreshes while holding `lease` until `until`, then saves the result or gives
    /// the lease back. The refresh must finish while enough of the lease is left to
    /// save: the time is measured after acquiring the lease, since the backend calls
    /// that acquired it may have been slow.
    async fn refresh_leased(
        &self,
        key: &SessionKey,
        lease: &LeaseId,
        until: DateTime<Utc>,
        current: Session,
    ) -> Result<Option<Session>, BackendError> {
        let budget = (until - self.now() - SAVE_MARGIN)
            .to_std()
            .ok()
            .filter(|budget| !budget.is_zero());
        let (Some(refresh), Some(budget)) = (current.login.refresh_token(), budget) else {
            // Nothing to refresh, or no time left to do it safely: auth was not
            // called, so give the lease back with the session unchanged.
            return self.save(key, lease, until, current.login).await;
        };
        let Ok(refreshed) =
            tokio::time::timeout(budget.min(REFRESH_DEADLINE), self.client.refresh(refresh)).await
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
                self.save(key, lease, until, refreshed).await
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
                self.save(key, lease, until, current.login).await
            }
            // The request never reached auth, so nothing was rotated either.
            Err(crate::OAuthError::Network(error)) if error.unsent() => {
                tracing::warn!(error = %ErrorChain(&error), "session refresh could not reach auth");
                self.save(key, lease, until, current.login).await
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
    ///
    /// The save must land before the lease expires, since afterwards another request
    /// may find it abandoned and delete the session. A save still running at expiry
    /// may or may not have landed, so the session ends.
    async fn save(
        &self,
        key: &SessionKey,
        lease: &LeaseId,
        until: DateTime<Utc>,
        login: StoredLogin,
    ) -> Result<Option<Session>, BackendError> {
        let remaining = (until - self.now()).to_std().unwrap_or_default();
        let saving = self.sessions.save(key, lease, login, || self.now());
        if let Ok(saved) = tokio::time::timeout(remaining, saving).await {
            saved
        } else {
            tracing::warn!("saving a refresh outlasted its lease; ending the session");
            self.end(key).await
        }
    }

    /// Ends the session.
    async fn end(&self, key: &SessionKey) -> Result<Option<Session>, BackendError> {
        self.sessions.delete(key).await?;
        Ok(None)
    }
}
