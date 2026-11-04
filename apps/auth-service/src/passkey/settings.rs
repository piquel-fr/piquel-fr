//! Passkey settings of the account service: the owner adds passkeys, and any
//! administrator may also list, rename and remove them.

use super::{PasskeyApplication, PasskeyError, PasskeyName};
use crate::account::{AccountError, AccountService, Owner, Subject, Viewer};
use piquel_common::{
    PasskeyId,
    events::{DomainEvent, RevocationReason},
    protocol::api,
};
use webauthn_rs::prelude::*;

/// Passkey settings any administrator may also change: listing, renaming and
/// removing. Only the owner adds a passkey, since it is a way to sign in.
impl AccountService {
    /// Adds `key`, a passkey the owner's browser registered and the enrollment
    /// ceremony verified, under the owner's session lock. A recent confirmation
    /// authorized the ceremony at its start, and the ceremony belongs to this
    /// session and expires on its own, so a confirmation lapsing at the
    /// authenticator never discards the new credential.
    pub(crate) async fn add_passkey(
        &self,
        owner: &Owner,
        key: Passkey,
        friendly_name: PasskeyName,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        PasskeyApplication::insert_passkey(
            &mut tx,
            &owner.context(),
            owner.user(),
            key,
            friendly_name,
        )
        .await?;
        Ok(tx.commit().await?)
    }

    /// Lists public labels and identifiers of the account's active passkeys.
    pub(crate) async fn passkeys(
        &self,
        viewer: &Viewer,
    ) -> Result<Vec<api::Passkey>, AccountError> {
        viewer.authorize(&self.database).await?;
        let passkeys = self.database.passkeys().list_active(viewer.user()).await?;
        Ok(passkeys.into_iter().map(Into::into).collect())
    }

    /// Changes a passkey's label. A name grants nothing, so the owner needs no
    /// passkey confirmation.
    pub(crate) async fn rename_passkey(
        &self,
        subject: &Subject,
        id: PasskeyId,
        name: String,
    ) -> Result<(), AccountError> {
        let friendly_name = PasskeyName::parse(name)?;
        let mut tx = self.database.begin().await?;
        subject.lock(&mut tx).await?;
        if !tx
            .passkeys()
            .rename(id, subject.user(), friendly_name.as_str())
            .await?
        {
            return Err(PasskeyError::PasskeyNotFound.into());
        }
        tx.record(
            &subject.context(),
            Some(subject.user()),
            DomainEvent::PasskeyRenamed { passkey_id: id },
        )
        .await?;
        subject.commit(tx).await
    }

    /// Removes a passkey and signs the account out elsewhere. One active passkey
    /// always remains, even with a social identity linked. While a recovery can
    /// be undone, only its own passkey is removed, by anyone
    /// ([`Self::refuse_mid_recovery`]).
    pub(crate) async fn revoke_passkey(
        &self,
        subject: &Subject,
        id: PasskeyId,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        subject.lock_confirmed(&mut tx).await?;
        Self::refuse_mid_recovery(&mut tx, subject.user(), id).await?;
        if !tx.passkeys().revoke_if_not_last(id, subject.user()).await? {
            return Err(PasskeyError::LastPasskey.into());
        }
        let context = subject.context();
        tx.record(
            &context,
            Some(subject.user()),
            DomainEvent::PasskeyRemoved { passkey_id: id },
        )
        .await?;
        tx.revoke_sessions(
            &context,
            subject.user(),
            subject.others(),
            &RevocationReason::CredentialRemoved,
        )
        .await?;
        subject.commit(tx).await
    }
}
