//! Signing administrators in to the admin dashboard, which auth serves on its
//! admin listener, for the dashboard's own origin. It is no OIDC client: auth's
//! handoff page hands an administrator's passkey session over in-process.
//!
//! 1. A browser without a dashboard session, or whose change needs a passkey
//!    confirmation, is sent to auth's handoff page ([`DashboardSignIn::start`]),
//!    with a state whose digest the dashboard keeps in a cookie of its own origin.
//! 2. The handoff page needs a session signed in with a passkey, of an account
//!    that still holds administrator rights. It answers with a single-use code,
//!    valid for [`HANDOFF_LIFETIME`], bound to that session and to the state
//!    ([`DashboardSignIn::hand_off`]). A confirmation counts only when a passkey
//!    proved it in a ceremony the handoff page started for it, never a
//!    confirmation of the auth session itself.
//! 3. The dashboard redeems the code in the browser holding the state, and starts
//!    a session of its own, storing only its cookie's digest, with the auth
//!    session and the confirmation ([`DashboardSignIn::finish`]).
//!
//! A dashboard session lasts while its auth session does: signing out of auth,
//! revoking that session or replacing it ends the dashboard's too. Every request
//! checks the administrator's rights again ([`DashboardSignIn::operator`]).

use super::{AdminError, AdminSession, Operator};
use crate::{
    account::Owner,
    federation::ReturnTo,
    passkey::AdminProof,
    routes,
    security::{BrowserCookie, RequestContext},
};
use axum::http::{HeaderMap, header::InvalidHeaderValue};
use chrono::{Duration, Utc};
use piquel_common::{UserId, config::Origin};
use piquel_crypto::Secret;
use piquel_repository::{Database, InsertHandoff};
use piquel_ui::{Checkbox, HandoffQuery, Query};
use url::Url;

/// How long a handoff code works: the redirect from auth to the dashboard.
const HANDOFF_LIFETIME: Duration = Duration::seconds(60);

/// Signs administrators in to the admin dashboard, and finds who is signed in.
#[derive(Clone)]
pub(crate) struct DashboardSignIn {
    /// Auth sessions, administrators, handoff codes and dashboard sessions.
    database: Database,
    /// Auth's origin, whose handoff page signs administrators in.
    auth: Origin,
    /// The dashboard's origin, where handoffs go on to.
    dashboard: Origin,
}

/// An administrator signed in to the dashboard, as a request found them.
pub(crate) struct SignedInAdmin {
    /// Who acts.
    pub(crate) operator: Operator,
    /// Their account.
    pub(crate) user_id: UserId,
    /// Their handle, which the dashboard shows.
    pub(crate) handle: String,
}

/// How a step of signing in to the dashboard changes the browser's cookies on the
/// dashboard's origin. Its page applies it to its answer.
pub(crate) struct DashboardCookie(Step);

/// The change a [`DashboardCookie`] makes.
enum Step {
    /// A sign-in started: the state its handoff must come back to.
    Started(Secret),
    /// Signed in: the session's cookie, and the state is done with.
    SignedIn(Secret),
    /// Signed out: the session's cookie goes.
    SignedOut,
}

impl DashboardCookie {
    /// Adds the `Set-Cookie` headers making the change to `response`, keeping any
    /// other cookies being set.
    pub(crate) fn set_on<B>(
        self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), InvalidHeaderValue> {
        match self.0 {
            Step::Started(state) => BrowserCookie::DashboardState.set_on(response, &state),
            Step::SignedIn(session) => {
                BrowserCookie::Dashboard.set_on(response, &session)?;
                BrowserCookie::DashboardState.clear_on(response)
            }
            Step::SignedOut => BrowserCookie::Dashboard.clear_on(response),
        }
    }
}

impl DashboardSignIn {
    /// Signs administrators in from `auth`'s handoff page to the dashboard at
    /// `dashboard`.
    pub(crate) const fn new(database: Database, auth: Origin, dashboard: Origin) -> Self {
        Self {
            database,
            auth,
            dashboard,
        }
    }

    /// The dashboard's origin, where handoffs go on to.
    pub(crate) const fn dashboard(&self) -> &Origin {
        &self.dashboard
    }

    /// Starts signing the browser in to the dashboard, to go on to the dashboard
    /// path `return_to`, with a passkey confirmation if `confirm`: the handoff page
    /// on auth to send it to, and the state cookie binding the handoff to it.
    pub(crate) fn start(
        &self,
        return_to: &str,
        confirm: bool,
    ) -> Result<(Url, DashboardCookie), AdminError> {
        let state = Secret::generate()?;
        let query = HandoffQuery {
            state: state.encoded(),
            return_to: return_to.to_owned(),
            confirm: Checkbox(confirm),
        };
        let page = query.url(self.auth.as_url(), routes::page::ADMIN)?;
        Ok((page, DashboardCookie(Step::Started(state))))
    }

    /// Hands `owner`'s session off to the dashboard as `handoff` asks: where the
    /// dashboard is to go on to, with the code to redeem there. The session must be
    /// signed in with a passkey, of an account that still holds administrator
    /// rights. A handoff that asks for a confirmation needs `proof`, of this
    /// session, whose time the dashboard session keeps as its confirmation.
    pub(crate) async fn hand_off(
        &self,
        owner: &Owner,
        handoff: &HandoffQuery,
        proof: Option<AdminProof>,
    ) -> Result<Url, AdminError> {
        let session = owner.session();
        let operator = Operator::Admin(AdminSession {
            user_id: session.user_id,
            session_id: session.id,
            confirmed_at: None,
            context: owner.request(),
        });
        operator.authorize_read(&self.database).await?;
        let confirmed_at = match proof {
            Some(proof) if proof.session_id() == session.id => Some(proof.at()),
            Some(_) => return Err(AdminError::SessionEnded),
            None if handoff.confirm.0 => return Err(AdminError::InvalidHandoff),
            None => None,
        };
        let state = Secret::parse(&handoff.state).map_err(|_| AdminError::InvalidHandoff)?;
        let return_to = Self::path(&handoff.return_to)?;
        let code = Secret::generate()?;
        self.database
            .dashboard()
            .insert_handoff(&InsertHandoff {
                code_digest: code.digest().as_bytes(),
                session_id: session.id,
                state_digest: state.digest().as_bytes(),
                return_to: return_to.as_str(),
                confirmed_at,
                expires_at: Utc::now() + HANDOFF_LIFETIME,
            })
            .await?;
        let mut target = self.dashboard.url(routes::dashboard::SIGN_IN);
        target
            .query_pairs_mut()
            .append_pair("code", &code.encoded());
        Ok(target)
    }

    /// Redeems auth's handoff `code` in the browser whose cookies `headers` carries,
    /// which must hold the state the handoff was bound to. Starts the dashboard
    /// session, replacing the browser's previous one, and returns the dashboard
    /// path to go on to, with the cookies to set.
    pub(crate) async fn finish(
        &self,
        headers: &HeaderMap,
        code: &str,
    ) -> Result<(ReturnTo, DashboardCookie), AdminError> {
        let state = BrowserCookie::DashboardState
            .read(headers)
            .ok_or(AdminError::InvalidHandoff)?;
        let code = Secret::parse(code).map_err(|_| AdminError::InvalidHandoff)?;
        let mut tx = self.database.begin().await?;
        let handoff = tx
            .dashboard()
            .redeem_handoff(code.digest().as_bytes(), state.digest().as_bytes())
            .await?
            .ok_or(AdminError::InvalidHandoff)?;
        if let Some(previous) = BrowserCookie::Dashboard.read(headers) {
            tx.dashboard()
                .delete_session(previous.digest().as_bytes())
                .await?;
        }
        let secret = Secret::generate()?;
        tx.dashboard()
            .insert_session(
                secret.digest().as_bytes(),
                handoff.session_id,
                handoff.confirmed_at,
            )
            .await?;
        tx.commit().await?;
        let return_to = Self::path(&handoff.return_to)?;
        Ok((return_to, DashboardCookie(Step::SignedIn(secret))))
    }

    /// The administrator signed in to the dashboard in the browser whose cookies
    /// `headers` carries, acting from `context`, or `None` when it has no session,
    /// or its auth session ended. Their rights and auth session are checked now,
    /// as every read checks them again.
    pub(crate) async fn signed_in(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
    ) -> Result<Option<SignedInAdmin>, AdminError> {
        let Some(secret) = BrowserCookie::Dashboard.read(headers) else {
            return Ok(None);
        };
        let Some(stored) = self
            .database
            .dashboard()
            .find_session(secret.digest().as_bytes())
            .await?
        else {
            return Ok(None);
        };
        let operator = Operator::Admin(AdminSession {
            user_id: stored.user_id,
            session_id: stored.session_id,
            confirmed_at: stored.confirmed_at,
            context,
        });
        match operator.authorize_read(&self.database).await {
            Ok(()) => Ok(Some(SignedInAdmin {
                operator,
                user_id: stored.user_id,
                handle: stored.handle,
            })),
            Err(AdminError::SessionEnded) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Ends the dashboard session of the browser whose cookies `headers` carries.
    /// Its auth session stays signed in.
    pub(crate) async fn sign_out(
        &self,
        headers: &HeaderMap,
    ) -> Result<DashboardCookie, AdminError> {
        if let Some(secret) = BrowserCookie::Dashboard.read(headers) {
            self.database
                .dashboard()
                .delete_session(secret.digest().as_bytes())
                .await?;
        }
        Ok(DashboardCookie(Step::SignedOut))
    }

    /// The dashboard path `value` names, which cannot leave the dashboard's origin.
    fn path(value: &str) -> Result<ReturnTo, AdminError> {
        ReturnTo::parse(Some(value)).map_err(|_| AdminError::InvalidHandoff)
    }
}
