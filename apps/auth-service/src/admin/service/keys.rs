//! Signing keys: listing, rotating, revoking and importing them, through the
//! [`KeyStore`] the caller holds, which seals them with its key-encryption key.

use super::AdminService;
use crate::{
    KeyStore,
    admin::{AdminError, Operator, Reason},
};
use sourceorigin_common::{admin::SigningKey, protocol::jwt::KeyId};
use sourceorigin_crypto::Rs256Key;

impl AdminService {
    /// Lists every signing key, oldest first, without either half of the key.
    pub(crate) async fn list_signing_keys(
        &self,
        operator: &Operator,
    ) -> Result<Vec<SigningKey>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(Self::views(self.database.signing_keys().list().await?))
    }

    /// Publishes a `next` signing key in `keys`, or keeps the one already
    /// published, and returns its ID; with `immediately`, it signs at once, as
    /// [`KeyStore::rotate`] says. Every replica picks it up within a minute.
    pub(crate) async fn rotate_signing_key(
        &self,
        operator: &Operator,
        keys: &KeyStore,
        immediately: bool,
        reason: Reason,
    ) -> Result<KeyId, AdminError> {
        Ok(keys.rotate(operator, &reason, immediately).await?)
    }

    /// Deletes signing key `id` from `keys` at once, as [`KeyStore::revoke`]
    /// does, and returns the key that signs instead, when it was the active one.
    pub(crate) async fn revoke_signing_key(
        &self,
        operator: &Operator,
        keys: &KeyStore,
        id: &KeyId,
        reason: Reason,
    ) -> Result<Option<KeyId>, AdminError> {
        Ok(keys.revoke(operator, &reason, id).await?)
    }

    /// Imports `key`, the deployment's PEM key, into `keys` as the active key,
    /// if the key set is empty, and returns whether it did.
    pub(crate) async fn import_signing_key(
        &self,
        operator: &Operator,
        keys: &KeyStore,
        key: Rs256Key,
        reason: Reason,
    ) -> Result<bool, AdminError> {
        Ok(keys.import(operator, &reason, key).await?)
    }
}
