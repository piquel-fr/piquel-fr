//! Account recovery: enrolling a passkey with a recovery link, which signs in
//! during its probation, and the owner's undo of it with an older passkey.

use super::{
    PasskeyApplication, PasskeyError, PasskeyName,
    acceptance::Accepted,
    ceremonies::{Ceremony, RecoveryCeremony, UndoCeremony},
    types::{AuthenticationFinish, RecoveryStart, RecoveryUndo, RegistrationFinish, UndoOutcome},
};
use crate::account::{AccountError, AccountService, Owner};
use crate::recovery::{PROBATION, ProbationPasskey, RecoveryError, RecoveryView};
use crate::security::{self, ApiError, Credential, RequestContext};
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use sourceorigin_common::{
    PasskeyId, RecoveryId, UserId,
    events::{Actor, DomainEvent},
};
use sourceorigin_repository::DatabaseTransaction;
use webauthn_rs::prelude::*;

impl PasskeyApplication {
    /// Starts enrolling a passkey with a recovery link, excluding the account's
    /// current credentials. The link's token authorizes it, without a session.
    pub(super) async fn start_recovery(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RecoveryStart>,
    ) -> Result<Response, ApiError> {
        let recovery = app.service().open_recovery(&input.token).await?;
        let user_id = recovery.user_id();
        let exclusions = app.exclusions(user_id).await?;
        let account = recovery.account();
        let (challenge, state) = app.registration(
            user_id,
            account.handle.as_str(),
            &account.display_name,
            Some(exclusions),
            input.passkey_kind,
            &headers,
        )?;
        Ok(app
            .start(
                &headers,
                Ceremony::Recover(RecoveryCeremony {
                    recovery_id: recovery.id(),
                    user_id,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Finishes enrolling a passkey with a recovery link: uses the link, and signs
    /// the browser in with the new passkey.
    pub(super) async fn finish_recovery(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        Json(input): Json<RegistrationFinish>,
    ) -> Result<Response, ApiError> {
        let friendly_name = PasskeyName::parse(input.friendly_name)?;
        let RecoveryCeremony {
            recovery_id,
            user_id,
            state,
        } = app
            .consume::<RecoveryCeremony>(&headers, input.ceremony_id)
            .await?;
        let key = app
            .webauthn
            .finish_passkey_registration(&input.credential, &state)
            .map_err(PasskeyError::from)?;
        let mut tx = app.database.begin().await?;
        let probation = AccountService::complete_recovery(
            &mut tx,
            recovery_id,
            user_id,
            key,
            friendly_name,
            context,
        )
        .await?;
        // Always a new session: one the browser already had, of this account or
        // another, is neither renewed nor carried over.
        let session = security::Session::sign_in_anew(
            &mut tx,
            context,
            &headers,
            user_id,
            Credential::Probation(probation),
        )
        .await?;
        Ok(Self::signed_in(tx, &session).await?)
    }

    /// Describes the account's recovery that can still be undone, if any.
    pub(super) async fn recovery(
        State(app): State<Self>,
        owner: Owner,
    ) -> Result<Json<Option<RecoveryView>>, ApiError> {
        Ok(Json(app.service().recovery(&owner).await?))
    }

    /// Starts undoing the recovery the undo page names, challenging every passkey
    /// of the account but the recovery's own. Needs no session: whoever used the
    /// link cannot stop an undo by signing the owner out, nor by having the
    /// account disabled.
    pub(super) async fn start_undo(
        State(app): State<Self>,
        headers: HeaderMap,
        Json(input): Json<RecoveryUndo>,
    ) -> Result<Response, ApiError> {
        let (user_id, passkeys) = app.service().undo_passkeys(input.recovery_id).await?;
        let (challenge, state) = app
            .webauthn
            .start_passkey_authentication(&Self::decode(passkeys)?)
            .map_err(PasskeyError::from)?;
        Ok(app
            .start(
                &headers,
                Ceremony::Undo(UndoCeremony {
                    recovery_id: input.recovery_id,
                    user_id,
                    state,
                }),
                challenge,
            )
            .await?)
    }

    /// Finishes undoing a recovery with the passkey's assertion, in one
    /// transaction, and signs the browser in with that passkey. Undoing a recovery
    /// in probation ends every session before that sign-in; an unused link is only
    /// cancelled. On a disabled account, it undoes and signs nobody in.
    pub(super) async fn finish_undo(
        State(app): State<Self>,
        context: RequestContext,
        headers: HeaderMap,
        Json(input): Json<AuthenticationFinish>,
    ) -> Result<Response, ApiError> {
        let (mut tx, verified) = app.verify_undo(context, &headers, input).await?;
        AccountService::undo_recovery(&mut tx, context, &verified).await?;
        let session = match verified.accepted {
            Accepted::Active(passkey) => Some(
                security::Session::sign_in(
                    &mut tx,
                    context,
                    &headers,
                    verified.user_id,
                    Credential::Passkey(passkey),
                )
                .await?,
            ),
            Accepted::Disabled(_) => None,
        };
        tx.commit().await?;
        let signed_in = session.is_some();
        let mut response = Json(UndoOutcome { signed_in }).into_response();
        if let Some(session) = session {
            session
                .set_on(&mut response)
                .map_err(PasskeyError::CookieHeader)?;
        }
        Ok(response)
    }

    /// Consumes the browser's undo ceremony and verifies its assertion under the
    /// account lock, whatever the account's status. Returns the transaction that
    /// holds the lock, and the undo it proves: the only way to build a
    /// [`VerifiedRecoveryUndo`].
    async fn verify_undo(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
        input: AuthenticationFinish,
    ) -> Result<(DatabaseTransaction<'_>, VerifiedRecoveryUndo), ApiError> {
        let UndoCeremony {
            recovery_id,
            user_id,
            state,
        } = self
            .consume::<UndoCeremony>(headers, input.ceremony_id)
            .await?;
        let verified = self
            .webauthn
            .finish_passkey_authentication(&input.credential, &state);
        let (tx, accepted) = self
            .accept_credential::<Accepted>(context, Actor::Anonymous, user_id, verified)
            .await?;
        let undo = VerifiedRecoveryUndo {
            user_id,
            recovery_id,
            accepted,
        };
        Ok((tx, undo))
    }
}

/// An undo of a recovery that a passkey proved: its undo ceremony was consumed
/// and the assertion verified under the account lock, binding the account, the
/// recovery and the passkey. Only [`PasskeyApplication::verify_undo`] builds one,
/// so [`AccountService::undo_recovery`] is never handed IDs nobody proved.
pub(crate) struct VerifiedRecoveryUndo {
    /// The account.
    user_id: UserId,
    /// The recovery its ceremony named.
    recovery_id: RecoveryId,
    /// The passkey that asserted, and whether the account may be signed in to.
    accepted: Accepted,
}

impl VerifiedRecoveryUndo {
    /// The account.
    pub(crate) const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The recovery its ceremony named.
    pub(crate) const fn recovery_id(&self) -> RecoveryId {
        self.recovery_id
    }

    /// The passkey that asserted.
    pub(crate) const fn passkey(&self) -> PasskeyId {
        self.accepted.passkey()
    }

    /// An undo of `recovery_id` of `user_id` by `passkey` on an active account, as
    /// if verified: a fixture for the undo's own checks under the lock.
    #[cfg(test)]
    pub(crate) const fn unverified(
        user_id: UserId,
        recovery_id: RecoveryId,
        passkey: PasskeyId,
    ) -> Self {
        Self {
            user_id,
            recovery_id,
            accepted: Accepted::Active(passkey),
        }
    }
}

/// The passkey a recovery's link enrolls, which its token authorizes.
impl AccountService {
    /// Completes recovery `recovery_id` of `user_id` with `key`, a passkey its
    /// link's ceremony verified, in the caller's transaction, which signs the
    /// browser in with it on commit. Stores the passkey, starts the recovery's
    /// probation, and records the completion as the browser's, which the link
    /// authorized, not a session. Fails, rolling the passkey back, if the link
    /// stopped working since the ceremony started. Returns the passkey, which
    /// signs in without confirming during the probation.
    async fn complete_recovery(
        tx: &mut DatabaseTransaction<'_>,
        recovery_id: RecoveryId,
        user_id: UserId,
        key: Passkey,
        friendly_name: PasskeyName,
        request: RequestContext,
    ) -> Result<ProbationPasskey, AccountError> {
        tx.users()
            .find_active_by_id_for_update(user_id)
            .await?
            .ok_or(RecoveryError::InvalidLink)?;
        let context = request.actor(Actor::Anonymous);
        let passkey_id =
            PasskeyApplication::insert_passkey(tx, &context, user_id, key, friendly_name).await?;
        if !tx
            .recoveries()
            .complete(user_id, recovery_id, passkey_id, PROBATION)
            .await?
        {
            return Err(RecoveryError::InvalidLink.into());
        }
        let recovery = tx.recoveries().find(recovery_id).await?;
        let probation = recovery
            .as_ref()
            .and_then(ProbationPasskey::of)
            .ok_or(RecoveryError::InvalidLink)?;
        tx.record(
            &context,
            Some(user_id),
            DomainEvent::RecoveryCompleted {
                recovery_id,
                passkey_id,
            },
        )
        .await?;
        Ok(probation)
    }
}
