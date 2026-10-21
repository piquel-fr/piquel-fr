//! The one place that changes OIDC client registrations. Each change commits with
//! the event that records it. The `client` command uses it, as does the deployment
//! job that registers the admin dashboard; the owner API (#43), dynamic
//! registration (#44) and the admin API (#38) will too.
//!
//! Nothing is cached: every request reads the registration it needs from the
//! database, so a change applies to the next request on every replica.

use piquel_common::{
    ClientId,
    clients::{ClientKind, ClientRegistration},
    events::DomainEvent,
};
use piquel_crypto::{ClientSecret, CryptoError};
use piquel_repository::{Database, DatabaseError, DatabaseTransaction, StoredOidcClient};
use thiserror::Error;

use crate::{GracePeriod, Operator};

/// Creates, updates, applies, enables, disables and rotates the secrets of clients.
#[derive(Clone)]
pub struct ClientRegistry {
    /// Where registrations and their events are stored.
    database: Database,
}

/// Why a client change was refused.
#[derive(Debug, Error)]
pub enum ClientRegistryError {
    /// Another client has this ID.
    #[error("a client with ID {id} already exists")]
    Exists {
        /// The requested ID.
        id: ClientId,
        /// The uniqueness violation.
        #[source]
        source: DatabaseError,
    },
    /// No client has this ID.
    #[error("no client has ID {0}")]
    Unknown(ClientId),
    /// Public clients authenticate without a secret.
    #[error("client {0} is public, so it has no secret")]
    Public(ClientId),
    /// A confidential client applied without its secret, which its deployment
    /// must provide.
    #[error("client {0} is confidential, so applying it needs its secret")]
    MissingSecret(ClientId),
    /// An update changed the client's ID or kind, which would orphan its grants
    /// or secrets.
    #[error("client {0}'s ID and kind cannot change; register a new client instead")]
    Immutable(ClientId),
    /// A secret could not be generated.
    #[error("could not generate a client secret")]
    Crypto(#[from] CryptoError),
    /// The database failed.
    #[error("client registration database operation failed")]
    Database(#[from] DatabaseError),
}

/// What [`ClientRegistry::apply`] changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The client was not registered yet.
    Registered,
    /// Its registration or secret changed.
    Updated,
    /// It was already as given; nothing was recorded.
    Unchanged,
}

impl ClientRegistryError {
    /// Reports `NotFound` as an unknown client `id`.
    fn lookup(id: &ClientId) -> impl FnOnce(DatabaseError) -> Self {
        move |error| match error {
            DatabaseError::NotFound => Self::Unknown(id.clone()),
            error => error.into(),
        }
    }
}

impl ClientRegistry {
    /// Changes the registrations stored in `database`.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Registers an enabled client. A confidential client gets its first secret,
    /// `secret` or a generated one, returned here once; only its digest is stored.
    ///
    /// # Errors
    /// Fails if the ID is taken, a public client is given a secret, a secret
    /// cannot be generated or the database fails.
    pub async fn create(
        &self,
        operator: &Operator,
        registration: &ClientRegistration,
        secret: Option<ClientSecret>,
    ) -> Result<Option<ClientSecret>, ClientRegistryError> {
        if registration.kind == ClientKind::Public && secret.is_some() {
            return Err(ClientRegistryError::Public(registration.id.clone()));
        }
        let mut tx = self.database.begin().await?;
        tx.oidc()
            .create_client(registration)
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => ClientRegistryError::Exists {
                    id: registration.id.clone(),
                    source: error,
                },
                error => error.into(),
            })?;
        let secret = match registration.kind {
            ClientKind::Public => None,
            ClientKind::Confidential => {
                let secret = secret.map_or_else(ClientSecret::generate, Ok)?;
                tx.oidc()
                    .insert_client_secret(&registration.id, secret.digest().as_bytes())
                    .await?;
                Some(secret)
            }
        };
        tx.record(
            &operator.context(),
            None,
            DomainEvent::ClientRegistered {
                client_id: registration.id.clone(),
                kind: registration.kind,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(secret)
    }

    /// Replaces client `id`'s registration with what `edit` makes of the stored one.
    /// The client stays locked from the read to the write, so concurrent updates
    /// cannot undo each other. Its ID, kind, enabled state and secrets stay.
    ///
    /// # Errors
    /// Fails if the client does not exist, `edit` fails or changes the ID or kind,
    /// or the database fails.
    pub async fn update<E: From<ClientRegistryError>>(
        &self,
        operator: &Operator,
        id: &ClientId,
        edit: impl FnOnce(StoredOidcClient) -> Result<ClientRegistration, E>,
    ) -> Result<(), E> {
        let mut tx = self
            .database
            .begin()
            .await
            .map_err(ClientRegistryError::from)?;
        let current = Self::locked(&mut tx, id).await?;
        let kind = current.kind;
        let registration = edit(current)?;
        if registration.id != *id || registration.kind != kind {
            return Err(ClientRegistryError::Immutable(id.clone()).into());
        }
        Self::replace(&mut tx, operator, &registration).await?;
        tx.commit().await.map_err(ClientRegistryError::from)?;
        Ok(())
    }

    /// Makes a client a deployment manages match `registration`, with `secret` as
    /// a confidential client's current secret: registers it, or updates what
    /// differs. Its other secrets keep working for `grace` at most, so the running
    /// deployment can roll out; zero revokes them now. Its enabled state stays.
    ///
    /// # Errors
    /// Fails if `secret` is missing for a confidential client or given for a public
    /// one, the client's kind differs, or the database fails.
    pub async fn apply(
        &self,
        operator: &Operator,
        registration: &ClientRegistration,
        secret: Option<ClientSecret>,
        grace: GracePeriod,
    ) -> Result<Applied, ClientRegistryError> {
        let id = &registration.id;
        let secret = match (registration.kind, secret) {
            (ClientKind::Public, Some(_)) => return Err(ClientRegistryError::Public(id.clone())),
            (ClientKind::Confidential, None) => {
                return Err(ClientRegistryError::MissingSecret(id.clone()));
            }
            (_, secret) => secret,
        };
        let mut tx = self.database.begin().await?;
        let current = match Self::locked(&mut tx, id).await {
            Err(ClientRegistryError::Unknown(_)) => {
                drop(tx);
                self.create(operator, registration, secret).await?;
                return Ok(Applied::Registered);
            }
            current => current?,
        };
        if current.kind != registration.kind {
            return Err(ClientRegistryError::Immutable(id.clone()));
        }
        let mut applied = Applied::Unchanged;
        if !current.registers(registration) {
            Self::replace(&mut tx, operator, registration).await?;
            applied = Applied::Updated;
        }
        if let Some(secret) = secret
            && Self::make_current(&mut tx, operator, id, grace, &secret).await?
        {
            applied = Applied::Updated;
        }
        tx.commit().await?;
        Ok(applied)
    }

    /// Writes an update checked by the caller, and records it.
    async fn replace(
        tx: &mut DatabaseTransaction<'_>,
        operator: &Operator,
        registration: &ClientRegistration,
    ) -> Result<(), ClientRegistryError> {
        tx.oidc().update_client(registration).await?;
        tx.record(
            &operator.context(),
            None,
            DomainEvent::ClientUpdated {
                client_id: registration.id.clone(),
            },
        )
        .await?;
        Ok(())
    }

    /// Enables or disables a client. A client already in that state records nothing.
    ///
    /// # Errors
    /// Fails if the client does not exist or the database fails.
    pub async fn set_enabled(
        &self,
        operator: &Operator,
        id: &ClientId,
        enabled: bool,
    ) -> Result<(), ClientRegistryError> {
        let mut tx = self.database.begin().await?;
        let changed = tx
            .oidc()
            .set_client_enabled(id, enabled)
            .await
            .map_err(ClientRegistryError::lookup(id))?;
        if changed {
            let client_id = id.clone();
            let event = if enabled {
                DomainEvent::ClientEnabled { client_id }
            } else {
                DomainEvent::ClientDisabled { client_id }
            };
            tx.record(&operator.context(), None, event).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Gives a confidential client a new secret, returned here once. Its earlier
    /// secrets keep working for `grace` at most, so it can redeploy in between;
    /// zero revokes them now.
    ///
    /// # Errors
    /// Fails if the client does not exist or is public, a secret cannot be
    /// generated or the database fails.
    pub async fn rotate_secret(
        &self,
        operator: &Operator,
        id: &ClientId,
        grace: GracePeriod,
    ) -> Result<ClientSecret, ClientRegistryError> {
        let mut tx = self.database.begin().await?;
        // Locked, so a concurrent rotation cannot insert a secret this cap misses.
        let client = Self::locked(&mut tx, id).await?;
        if client.kind == ClientKind::Public {
            return Err(ClientRegistryError::Public(client.id));
        }
        let secret = ClientSecret::generate()?;
        Self::make_current(&mut tx, operator, id, grace, &secret).await?;
        tx.commit().await?;
        Ok(secret)
    }

    /// Makes `secret` the locked confidential client `id`'s secret without an end,
    /// adding it unless it already is one, and makes its other secrets stop at
    /// `grace` from now at the latest. Records the rotation and returns `true` if
    /// either changed anything.
    async fn make_current(
        tx: &mut DatabaseTransaction<'_>,
        operator: &Operator,
        id: &ClientId,
        grace: GracePeriod,
        secret: &ClientSecret,
    ) -> Result<bool, ClientRegistryError> {
        let digest = secret.digest();
        let added = !tx.oidc().has_lasting_secret(id, digest.as_bytes()).await?;
        if added {
            tx.oidc()
                .insert_client_secret(id, digest.as_bytes())
                .await?;
        }
        let (previous_expire_at, capped) = tx
            .oidc()
            .cap_client_secrets(id, grace.duration(), Some(digest.as_bytes()))
            .await?;
        if added || capped {
            tx.record(
                &operator.context(),
                None,
                DomainEvent::ClientSecretRotated {
                    client_id: id.clone(),
                    previous_expire_at,
                },
            )
            .await?;
        }
        Ok(added || capped)
    }

    /// Locks client `id` for the rest of `tx`, then reads it.
    async fn locked(
        tx: &mut DatabaseTransaction<'_>,
        id: &ClientId,
    ) -> Result<StoredOidcClient, ClientRegistryError> {
        tx.oidc()
            .lock_client(id)
            .await
            .map_err(ClientRegistryError::lookup(id))?;
        tx.oidc()
            .find_client(id.as_str())
            .await?
            .ok_or_else(|| ClientRegistryError::Unknown(id.clone()))
    }
}

/// Changes made while auth serves requests apply to the next request.
#[cfg(test)]
mod tests;
