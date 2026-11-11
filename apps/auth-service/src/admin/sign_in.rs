//! Signing administrators in to the admin dashboard, which auth serves on its
//! admin listener, for the dashboard's own origin. It is no OIDC client: auth's
//! handoff page hands an administrator's passkey session over in-process.
//!
//! 1. A browser without a dashboard session, or whose change needs a passkey
//!    confirmation, is sent to auth's handoff page ([`DashboardSignIn::start`]),
//!    with a state whose digest the dashboard keeps in a cookie of its own origin.
//! 2. The handoff page needs a session signed in with a passkey, of an account
//!    that still holds administrator rights, and a passkey's proof, in a ceremony
//!    it started for the handoff, never a confirmation of the auth session
//!    itself: a browser left signed in to auth cannot open the dashboard without
//!    the administrator's passkey. It answers with a single-use code, valid for
//!    [`HANDOFF_LIFETIME`], bound to that session and to the state
//!    ([`DashboardSignIn::hand_off`]).
//! 3. The dashboard redeems the code in the browser holding the state, and starts
//!    a session of its own, confirmed by the proof, storing only its cookie's
//!    digest, with the auth session ([`DashboardSignIn::finish`]).
//!
//! The dashboard's own page may confirm its session later, with a passkey proved
//! for the dashboard's origin, a related origin of auth's RP ID
//! ([`DashboardSignIn::confirm`]), sparing the browser the trip to the handoff
//! page and back.
//!
//! A dashboard session lasts while its auth session does: signing out of auth,
//! revoking that session or replacing it ends the dashboard's too. It also ends
//! [`DASHBOARD_IDLE_MINUTES`] after its last request, [`DASHBOARD_LIFETIME_HOURS`]
//! after its sign-in, and when the account's rights are revoked. Every request
//! checks the administrator's rights again ([`DashboardSignIn::signed_in`]).
//! Signing in and out are recorded in the administrator's history; a session
//! that times out records nothing.

use super::{AdminError, AdminSession, Operator};
use crate::{
    account::Owner,
    federation::ReturnTo,
    passkey::AdminProof,
    routes,
    security::{BrowserCookie, DASHBOARD_IDLE_MINUTES, DASHBOARD_LIFETIME_HOURS, RequestContext},
};
use axum::http::{HeaderMap, header::InvalidHeaderValue};
use chrono::{DateTime, Duration, Utc};
use sourceorigin_common::{
    Handle, PictureId, SessionId, UserId,
    config::Origin,
    events::{Actor, DomainEvent},
};
use sourceorigin_crypto::Secret;
use sourceorigin_repository::{Database, DatabaseTransaction, InsertHandoff};
use sourceorigin_ui::{HandoffQuery, Query};
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
    /// The auth session the dashboard's session rests on.
    pub(crate) session_id: SessionId,
    /// Their handle, which the dashboard shows.
    pub(crate) handle: Handle,
    /// Their profile picture, which the dashboard shows.
    pub(crate) picture: Option<PictureId>,
}

/// How a step of signing in to the dashboard changes the browser's cookies on the
/// dashboard's origin. Its page applies it to its answer.
#[derive(Debug)]
pub(crate) struct DashboardCookie(Step);

/// The change a [`DashboardCookie`] makes.
#[derive(Debug)]
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
        &self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), InvalidHeaderValue> {
        match &self.0 {
            Step::Started(state) => BrowserCookie::DashboardState.set_on(response, state),
            Step::SignedIn(session) => {
                BrowserCookie::Dashboard.set_on(response, session)?;
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

    /// Starts signing the browser in to the dashboard, or confirming its session,
    /// to go on to the dashboard path `return_to`: the handoff page on auth to
    /// send it to, which asks for a passkey, and the state cookie binding the
    /// handoff to it.
    pub(crate) fn start(&self, return_to: &str) -> Result<(Url, DashboardCookie), AdminError> {
        let state = Secret::generate()?;
        let query = HandoffQuery {
            state: state.encoded(),
            return_to: return_to.to_owned(),
        };
        let page = query.url(self.auth.as_url(), routes::page::ADMIN)?;
        Ok((page, DashboardCookie(Step::Started(state))))
    }

    /// Requires `owner`'s session to be signed in with a passkey, of an account
    /// that still holds administrator rights: what a handoff needs, which its
    /// page checks before asking for a passkey.
    pub(crate) async fn admit(&self, owner: &Owner) -> Result<(), AdminError> {
        let session = owner.session();
        let operator = Operator::Admin(AdminSession {
            user_id: session.user_id,
            session_id: session.id,
            confirmed_at: None,
            context: owner.request(),
        });
        operator.authorize_read(&self.database).await
    }

    /// Hands `owner`'s session off to the dashboard as `handoff` asks, with
    /// `proof`, a passkey's of this session: where the dashboard is to go on to,
    /// with the code to redeem there. The session must be one [`Self::admit`]
    /// admits. The dashboard session the code starts keeps the proof's time as
    /// its confirmation.
    pub(crate) async fn hand_off(
        &self,
        owner: &Owner,
        handoff: &HandoffQuery,
        proof: AdminProof,
    ) -> Result<Url, AdminError> {
        let session = owner.session();
        self.admit(owner).await?;
        if proof.session_id() != session.id {
            return Err(AdminError::SessionEnded);
        }
        let state = Secret::parse(&handoff.state).map_err(|_| AdminError::InvalidHandoff)?;
        let return_to = Self::path(&handoff.return_to)?;
        let code = Secret::generate()?;
        let mut tx = self.database.begin().await?;
        Self::hold_rights(&mut tx, session.user_id).await?;
        tx.dashboard()
            .insert_handoff(&InsertHandoff {
                code_digest: code.digest().as_bytes(),
                session_id: session.id,
                state_digest: state.digest().as_bytes(),
                return_to: return_to.as_str(),
                confirmed_at: proof.at(),
                expires_at: Utc::now() + HANDOFF_LIFETIME,
            })
            .await?;
        tx.commit().await?;
        let mut target = self.dashboard.url(routes::dashboard::SIGN_IN);
        target
            .query_pairs_mut()
            .append_pair("code", &code.encoded());
        Ok(target)
    }

    /// Redeems auth's handoff `code` in the browser whose cookies `headers` carries,
    /// which must hold the state the handoff was bound to, from `context`. Starts
    /// the dashboard session, replacing the browser's previous one, records the
    /// sign-in, and returns the dashboard path to go on to, with the cookies to
    /// set.
    pub(crate) async fn finish(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
        code: &str,
    ) -> Result<(ReturnTo, DashboardCookie), AdminError> {
        let state = BrowserCookie::DashboardState
            .read(headers)
            .ok_or(AdminError::InvalidHandoff)?;
        let code = Secret::parse(code).map_err(|_| AdminError::InvalidHandoff)?;
        let mut tx = self.database.begin().await?;
        let user_id = (tx
            .dashboard()
            .handoff_user(code.digest().as_bytes())
            .await?)
            .ok_or(AdminError::InvalidHandoff)?;
        Self::hold_rights(&mut tx, user_id).await?;
        let handoff = tx
            .dashboard()
            .redeem_handoff(code.digest().as_bytes(), state.digest().as_bytes())
            .await?
            .ok_or(AdminError::InvalidHandoff)?;
        // The new session replaces it, in the same browser: no sign-out to record.
        if let Some(previous) = BrowserCookie::Dashboard.read(headers) {
            tx.dashboard()
                .delete_session(previous.digest().as_bytes())
                .await?;
        }
        let secret = Secret::generate()?;
        let lifetime = Duration::hours(DASHBOARD_LIFETIME_HOURS.into());
        tx.dashboard()
            .insert_session(
                secret.digest().as_bytes(),
                handoff.session_id,
                handoff.confirmed_at,
                Utc::now() + lifetime,
            )
            .await?;
        let signed_in = DomainEvent::DashboardSignedIn {
            session_id: handoff.session_id,
        };
        tx.record(
            &Self::by(context, handoff.user_id, handoff.session_id),
            Some(handoff.user_id),
            signed_in,
        )
        .await?;
        tx.commit().await?;
        let return_to = Self::path(&handoff.return_to)?;
        Ok((return_to, DashboardCookie(Step::SignedIn(secret))))
    }

    /// The administrator signed in to the dashboard in the browser whose cookies
    /// `headers` carries, acting from `context`, or `None` when it has no session,
    /// its session timed out, or its auth session ended. This request counts as
    /// the session's latest. Their rights and auth session are checked now, as
    /// every read checks them again.
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
            .use_session(secret.digest().as_bytes(), Self::idle_since())
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
                session_id: stored.session_id,
                handle: stored.handle,
                picture: stored.picture,
            })),
            Err(AdminError::SessionEnded) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Confirms the dashboard session of the browser whose cookies `headers`
    /// carries with `proof`, a passkey's on the dashboard's own page, which must be
    /// of the auth session it rests on.
    pub(crate) async fn confirm(
        &self,
        headers: &HeaderMap,
        proof: &AdminProof,
    ) -> Result<(), AdminError> {
        let secret = BrowserCookie::Dashboard
            .read(headers)
            .ok_or(AdminError::SessionEnded)?;
        let confirmed = self
            .database
            .dashboard()
            .confirm_session(secret.digest().as_bytes(), proof.session_id(), proof.at())
            .await?;
        confirmed.then_some(()).ok_or(AdminError::SessionEnded)
    }

    /// Ends the dashboard session of the browser whose cookies `headers` carries,
    /// from `context`, and records it. Its auth session stays signed in.
    pub(crate) async fn sign_out(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
    ) -> Result<DashboardCookie, AdminError> {
        if let Some(secret) = BrowserCookie::Dashboard.read(headers) {
            let mut tx = self.database.begin().await?;
            if let Some(ended) = tx
                .dashboard()
                .delete_session(secret.digest().as_bytes())
                .await?
            {
                let signed_out = DomainEvent::DashboardSignedOut {
                    session_id: ended.session_id,
                };
                tx.record(
                    &Self::by(context, ended.user_id, ended.session_id),
                    Some(ended.user_id),
                    signed_out,
                )
                .await?;
            }
            tx.commit().await?;
        }
        Ok(DashboardCookie(Step::SignedOut))
    }

    /// Requires `user_id` to hold administrator rights, share-locked until `tx`
    /// ends: a handoff or a dashboard session written in `tx` then commits before
    /// a revocation of the rights, which ends it, or not at all. The rights come
    /// first, as a revocation takes them before the handoffs and sessions it
    /// deletes, so neither waits for the other in a cycle.
    async fn hold_rights(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        if tx.administrators().contains_for_share(user_id).await? {
            Ok(())
        } else {
            Err(AdminError::NotAdministrator)
        }
    }

    /// The earliest last request of a dashboard session still in use: one unused
    /// since has timed out.
    pub(crate) fn idle_since() -> DateTime<Utc> {
        Utc::now() - Duration::minutes(DASHBOARD_IDLE_MINUTES.into())
    }

    /// Attributes a sign-in or sign-out, from `context`, to the account `user_id`
    /// in its auth session `session_id`: the administrator acts as themselves.
    fn by(
        context: RequestContext,
        user_id: UserId,
        session_id: SessionId,
    ) -> sourceorigin_common::events::EventContext {
        context.actor(Actor::User {
            user_id,
            session_id: Some(session_id),
        })
    }

    /// The dashboard path `value` names, which cannot leave the dashboard's origin.
    fn path(value: &str) -> Result<ReturnTo, AdminError> {
        ReturnTo::parse(Some(value)).map_err(|_| AdminError::InvalidHandoff)
    }
}
