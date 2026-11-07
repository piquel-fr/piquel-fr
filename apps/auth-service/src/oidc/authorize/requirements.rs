//! Whether a session meets a pending authorization's sign-in requirements: the
//! hinted account, a fresh enough sign-in, and the target `acr`.

use crate::account::AccountService;
use crate::oidc::{OAuthCode, OAuthError, OidcApplication, Reject};
use chrono::{DateTime, Utc};
use piquel_common::{
    AuthenticationMethod, RecoveryId, UserId,
    protocol::{claims::Acr, step_up::StepUpRequirement},
};
use piquel_repository::{
    DatabaseError, DatabaseTransaction, SessionAuthentication, StoredAuthorizationRequest,
    StoredSession,
};

impl OidcApplication {
    /// Requires the session to meet the pending authorization's requirements.
    pub(super) fn require_authorization_session(
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> Result<(), OAuthError> {
        if Self::satisfies(request, session) {
            Ok(())
        } else {
            Err(OAuthCode::InvalidToken.reject(
                "this sign-in does not meet the authorization's requirements; sign in again",
            ))
        }
    }

    /// Whether `session` meets the pending authorization `request`'s requirements.
    pub(in crate::oidc) fn satisfies(
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> bool {
        Self::session_satisfies(
            session,
            request.interaction.forces_login(),
            request.max_age,
            request.hinted_user_id,
            request.target_acr,
            Some(request.started_at),
        )
    }

    /// Whether a session meets an authorization's sign-in requirements: the hinted
    /// account, a fresh authentication for `prompt=login` or `max_age=0`, and the
    /// target `acr` and a positive `max_age` as a [`StepUpRequirement`], the rule
    /// resources and auth's own settings apply. Ages count from the session's
    /// `auth_time`, and only authenticating after the request started (`started_at`:
    /// when stored, or claimed if pushed) counts as fresh. A negative `max_age` is
    /// never met.
    pub(super) fn session_satisfies(
        session: &StoredSession,
        force_login: bool,
        max_age: Option<i64>,
        hinted_user_id: Option<UserId>,
        target_acr: Option<Acr>,
        started_at: Option<DateTime<Utc>>,
    ) -> bool {
        let authentication = SessionAuthentication::from(session);
        let fresh = started_at.is_some_and(|started_at| authentication.auth_time >= started_at);
        let (force_login, max_age) = match max_age {
            // Requests reject negative ages, so one stored anyway is never met.
            Some(age) if age < 0 => return false,
            // `max_age=0` asks for a sign-in after the request, as `prompt=login` does.
            Some(0) => (true, None),
            // An age past `u32` excludes no sign-in.
            age => (
                force_login,
                age.map(|age| u32::try_from(age).unwrap_or(u32::MAX)),
            ),
        };
        let requirement = StepUpRequirement {
            acr: target_acr,
            max_age,
        };
        (fresh || !force_login)
            && requirement
                .check(
                    Some(&authentication.acr),
                    Some(authentication.auth_time),
                    Utc::now(),
                )
                .is_ok()
            && hinted_user_id.is_none_or(|subject| subject == session.user_id)
    }

    /// Whether a passkey signed `session` in, or in again, after the request
    /// started without confirming it, for the hinted account, and the session
    /// still falls short of the request's target `acr`. Only a recovered passkey
    /// during its probation signs in without confirming. The session's methods
    /// are its whole life's: one that such a passkey once signed in, then a
    /// provider signed in again, is answered so too.
    pub(super) fn falls_short_after_signing_in(
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> bool {
        let authentication = SessionAuthentication::from(session);
        let unconfirmed_passkey = session.passkey_confirmed_at.is_none()
            && session
                .authentication_methods
                .contains(&AuthenticationMethod::Passkey);
        let target = StepUpRequirement {
            acr: request.target_acr,
            max_age: None,
        };
        unconfirmed_passkey
            && Self::signed_in_for(request, session)
            && request
                .hinted_user_id
                .is_none_or(|subject| subject == session.user_id)
            && target
                .check(Some(&authentication.acr), None, Utc::now())
                .is_err()
    }

    /// Whether `session` signed in, or in again, after `request` started: for it.
    pub(super) fn signed_in_for(
        request: &StoredAuthorizationRequest,
        session: &StoredSession,
    ) -> bool {
        SessionAuthentication::from(session).auth_time >= request.started_at
    }

    /// The recovery of `user`'s account that can still be undone, if any, which a
    /// sign-in for an application first asks about: was it the owner's
    /// (`docs/dev/security/account-recovery.md`, C3)? An owner signing in with an
    /// older passkey learns of it there, even when its notice reached only a
    /// hijacked mailbox. Every sign-in for an application asks, or, inline, sends
    /// the browser to auth's pages to.
    pub(in crate::oidc) async fn undoable_recovery(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
    ) -> Result<Option<RecoveryId>, DatabaseError> {
        let undoable = AccountService::undoable(tx, user).await?;
        Ok(undoable.map(|undoable| undoable.id()))
    }
}
