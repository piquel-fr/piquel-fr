//! OIDC clients operators and deployments manage, their secrets, and the origins
//! approved for their pages to sign users in.

use super::AdminService;
use crate::{
    Applied, ClientDetails, ClientRegistry, ClientRegistryError, GracePeriod,
    admin::{AdminError, Operator, Reason},
};
use sourceorigin_common::{
    ClientId,
    admin::{ApprovedOrigin, Client},
    clients::{ClientField, ClientOwner, ClientRegistration, RelatedOrigin},
};
use sourceorigin_crypto::ClientSecret;
use sourceorigin_repository::StoredOidcClient;

impl AdminService {
    /// Lists every OIDC client, enabled or not.
    pub(crate) async fn list_clients(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Client>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(Self::views(self.database.oidc().list_clients().await?))
    }

    /// Describes one OIDC client as stored, with the lifetimes of its secrets.
    pub(crate) async fn client_details(
        &self,
        operator: &Operator,
        id: &ClientId,
    ) -> Result<ClientDetails, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut tx = self.database.begin().await?;
        let client = tx
            .oidc()
            .find_client(id.as_str())
            .await?
            .ok_or(AdminError::ClientNotFound)?;
        let secrets = tx.oidc().client_secrets(id).await?;
        tx.commit().await?;
        Ok(ClientDetails { client, secrets })
    }

    /// Runs `change` on the client registry in one transaction, attributed to
    /// `operator` with their `reason`, and commits once the operator is
    /// authorized again. The registry records each change's event itself.
    async fn change_clients<T, E: From<AdminError>>(
        &self,
        operator: &Operator,
        reason: Reason,
        change: impl AsyncFnOnce(&mut ClientRegistry<'_, '_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut tx = self.database.begin().await.map_err(AdminError::from)?;
        let context = operator.context(&reason);
        let value = change(&mut ClientRegistry::new(&mut tx, context)).await?;
        Self::finish(tx, operator, &reason, None, Vec::new()).await?;
        Ok(value)
    }

    /// Registers a client operators manage, and returns a confidential client's
    /// first secret, which is shown only this once.
    pub(crate) async fn create_client(
        &self,
        operator: &Operator,
        registration: &ClientRegistration,
        reason: Reason,
    ) -> Result<Option<ClientSecret>, AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients
                .create(ClientOwner::Operator, registration, None)
                .await?)
        })
        .await
    }

    /// Registers a client a deployment manages, or updates it to match, with the
    /// secret its deployment generated. Earlier secrets keep working for `grace`.
    pub(crate) async fn apply_client(
        &self,
        operator: &Operator,
        registration: &ClientRegistration,
        secret: Option<ClientSecret>,
        grace: GracePeriod,
        reason: Reason,
    ) -> Result<Applied, AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients.apply(registration, secret, grace).await?)
        })
        .await
    }

    /// Replaces client `id`'s registration with what `edit` makes of the stored
    /// one, and returns the settings that changed.
    pub(crate) async fn update_client<E>(
        &self,
        operator: &Operator,
        id: &ClientId,
        reason: Reason,
        edit: impl FnOnce(&StoredOidcClient) -> Result<ClientRegistration, E>,
    ) -> Result<Vec<ClientField>, E>
    where
        E: From<AdminError> + From<ClientRegistryError>,
    {
        self.change_clients(operator, reason, async |clients| {
            clients.update(id, edit).await
        })
        .await
    }

    /// Enables or disables client `id`. A suspended client cannot be enabled.
    pub(crate) async fn set_client_enabled(
        &self,
        operator: &Operator,
        id: &ClientId,
        enabled: bool,
        reason: Reason,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients.set_enabled(id, enabled).await?)
        })
        .await
    }

    /// Suspends client `id`, which disables it until the suspension is lifted, or
    /// lifts its suspension, which leaves it disabled.
    pub(crate) async fn set_client_suspended(
        &self,
        operator: &Operator,
        id: &ClientId,
        suspended: bool,
        reason: Reason,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients.set_suspended(id, suspended).await?)
        })
        .await
    }

    /// Deletes client `id`: it stops working at once, and its ID is never reused.
    pub(crate) async fn delete_client(
        &self,
        operator: &Operator,
        id: &ClientId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients.delete(id).await?)
        })
        .await
    }

    /// Gives confidential client `id` a new secret, shown only this once. Earlier
    /// secrets keep working for `grace`.
    pub(crate) async fn rotate_client_secret(
        &self,
        operator: &Operator,
        id: &ClientId,
        grace: GracePeriod,
        reason: Reason,
    ) -> Result<ClientSecret, AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients.rotate_secret(id, grace).await?)
        })
        .await
    }

    /// Lists every origin approved for clients' pages to sign users in.
    pub(crate) async fn list_related_origins(
        &self,
        operator: &Operator,
    ) -> Result<Vec<ApprovedOrigin>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self.database.oidc().related_origins().await?)
    }

    /// Approves `origin` for client `id`'s pages to sign users in with passkeys
    /// for `rp_id`, auth's `WebAuthn` RP ID.
    pub(crate) async fn approve_related_origin(
        &self,
        operator: &Operator,
        id: &ClientId,
        origin: &RelatedOrigin,
        rp_id: &str,
        reason: Reason,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients.approve_origin(id, origin, rp_id).await?)
        })
        .await
    }

    /// Removes `origin` from client `id`'s approved origins.
    pub(crate) async fn remove_related_origin(
        &self,
        operator: &Operator,
        id: &ClientId,
        origin: &RelatedOrigin,
        reason: Reason,
    ) -> Result<(), AdminError> {
        self.change_clients(operator, reason, async |clients| {
            Ok(clients.remove_origin(id, origin).await?)
        })
        .await
    }
}
