//! Accepting a verified passkey assertion: the latest credential state must
//! accept it too, and each ceremony accepts what its account's status allows.

use super::{PasskeyApplication, PasskeyError};
use crate::recovery::ProbationPasskey;
use crate::security::{Credential, RequestContext};
use serde_json::Value;
use sourceorigin_common::{AccountStatus, AuthenticationMethod, PasskeyId, UserId, events::Actor};
use sourceorigin_repository::{DatabaseError, DatabaseTransaction};
use webauthn_rs::prelude::*;

/// Signature counter location in webauthn-rs's serialized passkey representation.
pub(super) const CREDENTIAL_COUNTER_POINTER: &str = "/cred/counter";
/// Stable telemetry event name for a signature counter regression, a sign of a copied passkey.
const COUNTER_REGRESSION_EVENT: &str = "auth.passkey_counter_regression";

impl PasskeyApplication {
    /// Locks the account, whatever its status, then checks the latest stored
    /// counter under lock before updating the credential, and returns what `A`
    /// accepts of it: a [`Credential`], a recovery's passkey during its probation
    /// included, for an account `A` may sign in to.
    async fn update_credential<A: Acceptance>(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        result: &AuthenticationResult,
    ) -> Result<A, PasskeyError> {
        if !result.user_verified() {
            return Err(PasskeyError::UserVerificationRequired);
        }
        let status = tx
            .users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(PasskeyError::AccountInactive)?
            .status;
        let stored = tx
            .passkeys()
            .find_active_by_credential_id_for_update(result.cred_id().as_ref())
            .await?
            .filter(|stored| stored.user_id == user_id)
            .ok_or(PasskeyError::AccountInactive)?;
        // The ceremony contains a credential snapshot. Check the latest counter under
        // the row lock as well, so overlapping ceremonies cannot accept a regression.
        let counter = stored
            .credential
            .pointer(CREDENTIAL_COUNTER_POINTER)
            .and_then(Value::as_u64)
            .ok_or(PasskeyError::MissingCounter)?;
        if (counter > 0 || result.counter() > 0) && u64::from(result.counter()) <= counter {
            return Err(PasskeyError::CounterRegression);
        }
        let mut credential: Passkey =
            serde_json::from_value(stored.credential).map_err(PasskeyError::StoredCredential)?;
        credential
            .update_credential(result)
            .ok_or(PasskeyError::CredentialMismatch)?;
        if !tx
            .passkeys()
            .update_after_authentication(
                result.cred_id().as_ref(),
                &serde_json::to_value(credential).map_err(PasskeyError::Serialization)?,
            )
            .await?
        {
            return Err(PasskeyError::CredentialRevoked);
        }
        let credential = Self::credential(tx, stored.id).await?;
        A::accept(status, stored.id, credential)
    }

    /// What an assertion of `passkey` signs in as: a recovery's passkey during its
    /// probation confirms nothing, any other passkey confirms the session.
    pub(crate) async fn credential(
        tx: &mut DatabaseTransaction<'_>,
        passkey: PasskeyId,
    ) -> Result<Credential, DatabaseError> {
        Ok(match tx.recoveries().of_passkey(passkey).await? {
            Some(recovery) => ProbationPasskey::of(&recovery)
                .map_or(Credential::Passkey(passkey), Credential::Probation),
            None => Credential::Passkey(passkey),
        })
    }

    /// Takes `WebAuthn`'s verdict on an assertion for `user_id` and, once the latest
    /// credential state also accepts it, opens the transaction that completes the
    /// authentication, and returns it with what `A` accepts: a [`SignIn`], a
    /// [`Credential`] to confirm with, or [`Accepted`] for an undo. The ceremony was
    /// already consumed. A rejection rolls back any transaction it opened, then is
    /// recorded as `actor`'s failed sign-in in a transaction of its own, so the
    /// record outlives the rejection.
    pub(super) async fn accept_credential<A: Acceptance>(
        &self,
        context: RequestContext,
        actor: Actor,
        user_id: UserId,
        verified: Result<AuthenticationResult, WebauthnError>,
    ) -> Result<(DatabaseTransaction<'_>, A), PasskeyError> {
        let (error, tx) = match verified {
            Ok(result) => {
                let mut tx = self.database.begin().await?;
                match Self::update_credential(&mut tx, user_id, &result).await {
                    Ok(accepted) => return Ok((tx, accepted)),
                    Err(error) => (error, Some(tx)),
                }
            }
            Err(error) => (error.into(), None),
        };
        if let PasskeyError::CounterRegression = error {
            // Logged first so the signal survives a database failure.
            tracing::warn!(
                event = COUNTER_REGRESSION_EVENT,
                %user_id,
                "passkey signature counter regression rejected"
            );
        }
        // A failed rollback is only logged: the record matters more, and a broken
        // connection releases its locks anyway.
        if let Some(tx) = tx
            && let Err(rollback) = tx.rollback().await
        {
            tracing::error!(
                error = %sourceorigin_common::ErrorChain(&rollback),
                "passkey authentication rollback failed"
            );
        }
        Err(self.reject(context, actor, Some(user_id), error).await)
    }

    /// Records `error` as `actor`'s failed passkey authentication of `subject`, when
    /// it describes the attempt, then returns it, or the database failure that
    /// prevented recording it.
    pub(super) async fn reject(
        &self,
        context: RequestContext,
        actor: Actor,
        subject: Option<UserId>,
        error: PasskeyError,
    ) -> PasskeyError {
        let Some(reason) = error.sign_in_failure() else {
            return error;
        };
        match context
            .record_sign_in_failure(
                &self.database,
                actor,
                subject,
                AuthenticationMethod::Passkey,
                reason,
            )
            .await
        {
            Ok(()) => error,
            Err(database) => database.into(),
        }
    }
}

/// What an accepted passkey assertion yields, by who it is accepted from. Sign-in
/// and confirmation accept only an active account's passkeys, as a
/// [`Credential`]; the owner's undo of a recovery accepts a disabled account's
/// too, as [`Accepted`], so disabling the account cannot stop the undo.
pub(super) trait Acceptance: Sized {
    /// What an assertion of `passkey`, which signs in as `credential`, for an
    /// account with `status` yields.
    fn accept(
        status: AccountStatus,
        passkey: PasskeyId,
        credential: Credential,
    ) -> Result<Self, PasskeyError>;
}

impl Acceptance for Credential {
    /// The credential, for an active account only.
    fn accept(
        status: AccountStatus,
        _: PasskeyId,
        credential: Credential,
    ) -> Result<Self, PasskeyError> {
        match status {
            AccountStatus::Active => Ok(credential),
            AccountStatus::Disabled | AccountStatus::Deleting => Err(PasskeyError::AccountInactive),
        }
    }
}

/// What a passkey sign-in yields, by its account's status.
pub(super) enum SignIn {
    /// An active account's session, signed in as this credential.
    Session(Credential),
    /// For an account scheduled for deletion, no session but an offer to restore
    /// it, which signs in with this passkey once restored.
    Restore(PasskeyId),
}

impl Acceptance for SignIn {
    /// A session for an active account, an offer for one being deleted. A
    /// recovery's passkey in probation is offered nothing: restoring takes back a
    /// deletion only a confirmed session or support could make, so it needs
    /// another of the account's passkeys, which may confirm.
    fn accept(
        status: AccountStatus,
        passkey: PasskeyId,
        credential: Credential,
    ) -> Result<Self, PasskeyError> {
        match (status, credential) {
            (AccountStatus::Active, credential) => Ok(Self::Session(credential)),
            (AccountStatus::Deleting, Credential::Probation(_)) => {
                Err(PasskeyError::RestoreInProbation)
            }
            (AccountStatus::Deleting, Credential::Passkey(_) | Credential::Federation) => {
                Ok(Self::Restore(passkey))
            }
            (AccountStatus::Disabled, _) => Err(PasskeyError::AccountInactive),
        }
    }
}

/// The passkey of an assertion an undo accepts, by whether its account may be
/// signed in to afterwards.
#[derive(Clone, Copy)]
pub(super) enum Accepted {
    /// An active account's: the undo signs the browser in with it.
    Active(PasskeyId),
    /// A disabled account's: the undo signs nobody in.
    Disabled(PasskeyId),
}

impl Accepted {
    /// The passkey that asserted.
    pub(super) const fn passkey(self) -> PasskeyId {
        match self {
            Self::Active(passkey) | Self::Disabled(passkey) => passkey,
        }
    }
}

impl Acceptance for Accepted {
    /// Either, by the account's status. An account being deleted is refused: it is
    /// restored, from the sign-in page or by support, before its recovery is undone.
    fn accept(
        status: AccountStatus,
        passkey: PasskeyId,
        _: Credential,
    ) -> Result<Self, PasskeyError> {
        match status {
            AccountStatus::Active => Ok(Self::Active(passkey)),
            AccountStatus::Disabled => Ok(Self::Disabled(passkey)),
            AccountStatus::Deleting => Err(PasskeyError::AccountInactive),
        }
    }
}
