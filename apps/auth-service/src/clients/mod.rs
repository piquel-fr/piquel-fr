//! The one place that changes OIDC client registrations. Each change happens in
//! the caller's transaction, with the event that records it, so the caller can
//! check inside the same transaction that its user still may make it.
//! `AdminService` uses it for the `client` command and the deployment job that
//! registers the admin dashboard, and `AccountService` for the clients accounts
//! own ([`owned`]); dynamic registration (#44) will too.
//!
//! Nothing is cached: every request reads the registration it needs from the
//! database, so a change applies to the next request on every replica.

use piquel_common::{
    ClientId, UserId,
    clients::{ClientField, ClientKind, ClientOwner, ClientRegistration},
    events::{DomainEvent, EventContext},
    protocol::oauth::Scope,
};
use piquel_crypto::{ClientSecret, CryptoError};
use piquel_repository::{DatabaseError, DatabaseTransaction, StoredClientSecret, StoredOidcClient};
use serde::Serialize;
use thiserror::Error;

use crate::GracePeriod;

/// The clients an account owns: their policy and the owner's operations.
mod owned;
pub(crate) use owned::{ClientPatch, ClientSettings, NewClient, OwnedClient, OwnedClientError};

/// Scopes a new client may request when none are given.
pub const DEFAULT_CLIENT_SCOPES: [Scope; 3] = [Scope::OpenId, Scope::Profile, Scope::Email];
/// Live clients an account may manage at once. Deleting one frees its place.
pub const MAX_OWNED_CLIENTS: u32 = 10;
/// Clients an account may register a day, deleted ones included. A deleted client
/// stays as a tombstone forever, so this bounds how many an account can leave.
pub const MAX_DAILY_REGISTRATIONS: u32 = 20;
/// The window [`MAX_DAILY_REGISTRATIONS`] counts in.
const REGISTRATION_WINDOW: chrono::Duration = chrono::Duration::days(1);

/// Creates, updates, applies, enables, disables, rotates the secrets of and
/// deletes clients in one transaction, attributing each change to one actor.
pub struct ClientRegistry<'a, 't> {
    /// Where the changes and their events are written; the caller commits it.
    tx: &'a mut DatabaseTransaction<'t>,
    /// Who makes the changes, and where their request came from.
    context: EventContext,
}

/// Why a client change was refused.
#[derive(Debug, Error)]
pub enum ClientRegistryError {
    /// Another client, registered or deleted, has this ID.
    #[error("client ID {id} is taken, by a registered or a deleted client")]
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
    /// The client was deleted. Its ID stays reserved, so it cannot change again.
    #[error("client {0} was deleted")]
    Deleted(ClientId),
    /// The client is suspended, so it cannot be enabled until the suspension is lifted.
    #[error("client {0} is suspended; lift the suspension before enabling it")]
    Suspended(ClientId),
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
    /// The account already manages [`MAX_OWNED_CLIENTS`] clients.
    #[error("an account may manage at most {MAX_OWNED_CLIENTS} clients")]
    QuotaExceeded,
    /// The account registered [`MAX_DAILY_REGISTRATIONS`] clients in the last day.
    #[error("an account may register at most {MAX_DAILY_REGISTRATIONS} clients a day")]
    DailyLimitExceeded,
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

/// A client's registration and the lifetimes of its secrets, as `client show`
/// shows them, and `AccountService::client` to their owner.
#[derive(Serialize)]
pub struct ClientDetails {
    /// The registration.
    #[serde(flatten)]
    pub client: StoredOidcClient,
    /// Its secrets, oldest first; never their values.
    pub secrets: Vec<StoredClientSecret>,
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

impl<'a, 't> ClientRegistry<'a, 't> {
    /// Changes registrations in `tx`, recording each change as made in `context`.
    #[must_use]
    pub const fn new(tx: &'a mut DatabaseTransaction<'t>, context: EventContext) -> Self {
        Self { tx, context }
    }

    /// Registers an enabled client managed by `owner`. A confidential client gets
    /// its first secret, `secret` or a generated one, returned here once; only its
    /// digest is stored. An account may manage at most [`MAX_OWNED_CLIENTS`], and
    /// register at most [`MAX_DAILY_REGISTRATIONS`] a day.
    ///
    /// # Errors
    /// Fails if the ID is taken, the owner's quota or daily limit is used up, a public client is
    /// given a secret, a secret cannot be generated or the database fails.
    pub async fn create(
        &mut self,
        owner: ClientOwner,
        registration: &ClientRegistration,
        secret: Option<ClientSecret>,
    ) -> Result<Option<ClientSecret>, ClientRegistryError> {
        if registration.kind == ClientKind::Public && secret.is_some() {
            return Err(ClientRegistryError::Public(registration.id.clone()));
        }
        if let ClientOwner::Account(user_id) = owner {
            self.reserve(user_id).await?;
        }
        self.tx
            .oidc()
            .create_client(registration, owner)
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
                self.tx
                    .oidc()
                    .insert_client_secret(&registration.id, secret.digest().as_bytes())
                    .await?;
                Some(secret)
            }
        };
        self.record(DomainEvent::ClientRegistered {
            client_id: registration.id.clone(),
            kind: registration.kind,
        })
        .await?;
        Ok(secret)
    }

    /// Checks that `owner` may register one more client. Their account stays
    /// locked until the transaction ends, so concurrent registrations count one
    /// another rather than each seeing a free place.
    async fn reserve(&mut self, owner: UserId) -> Result<(), ClientRegistryError> {
        // Only the lock matters: an account in any status keeps its clients.
        self.tx.users().find_by_id_for_update(owner).await?;
        let counts = self
            .tx
            .oidc()
            .count_owned_clients(owner, REGISTRATION_WINDOW)
            .await?;
        if counts.live >= u64::from(MAX_OWNED_CLIENTS) {
            return Err(ClientRegistryError::QuotaExceeded);
        }
        if counts.registered_recently >= u64::from(MAX_DAILY_REGISTRATIONS) {
            return Err(ClientRegistryError::DailyLimitExceeded);
        }
        Ok(())
    }

    /// Replaces client `id`'s registration with what `edit` makes of the stored one,
    /// and returns the settings that changed. The client stays locked from the read
    /// to the write, so concurrent updates cannot undo each other. Its ID, kind,
    /// owner, enabled state and secrets stay. A change that changes nothing records
    /// nothing.
    ///
    /// # Errors
    /// Fails if the client does not exist or was deleted, `edit` fails or changes
    /// the ID or kind, or the database fails.
    pub async fn update<E: From<ClientRegistryError>>(
        &mut self,
        id: &ClientId,
        edit: impl FnOnce(&StoredOidcClient) -> Result<ClientRegistration, E>,
    ) -> Result<Vec<ClientField>, E> {
        let current = self.locked(id).await?;
        let registration = edit(&current)?;
        if registration.id != *id || registration.kind != current.kind {
            return Err(ClientRegistryError::Immutable(id.clone()).into());
        }
        let changed = current.changes(&registration);
        if !changed.is_empty() {
            self.replace(&registration, changed.clone()).await?;
        }
        Ok(changed)
    }

    /// Makes a client a deployment manages match `registration`, with `secret` as
    /// a confidential client's current secret: registers it, managed by operators,
    /// or updates what differs. Its other secrets keep working for `grace` at most,
    /// so the running deployment can roll out; zero revokes them now. Its enabled
    /// state stays.
    ///
    /// # Errors
    /// Fails if `secret` is missing for a confidential client or given for a public
    /// one, the client's kind differs, it was deleted, or the database fails.
    pub async fn apply(
        &mut self,
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
        let current = match self.locked(id).await {
            Err(ClientRegistryError::Unknown(_)) => {
                self.create(ClientOwner::Operator, registration, secret)
                    .await?;
                return Ok(Applied::Registered);
            }
            current => current?,
        };
        if current.kind != registration.kind {
            return Err(ClientRegistryError::Immutable(id.clone()));
        }
        let mut applied = Applied::Unchanged;
        let changed = current.changes(registration);
        if !changed.is_empty() {
            self.replace(registration, changed).await?;
            applied = Applied::Updated;
        }
        if let Some(secret) = secret
            && self.make_current(id, grace, &secret).await?
        {
            applied = Applied::Updated;
        }
        Ok(applied)
    }

    /// Writes an update checked by the caller, and records the `changed` settings.
    async fn replace(
        &mut self,
        registration: &ClientRegistration,
        changed: Vec<ClientField>,
    ) -> Result<(), ClientRegistryError> {
        self.tx.oidc().update_client(registration).await?;
        self.record(DomainEvent::ClientUpdated {
            client_id: registration.id.clone(),
            changed,
        })
        .await
    }

    /// Enables or disables a client: a pause its owner can undo. A client already
    /// in that state records nothing.
    ///
    /// # Errors
    /// Fails if the client does not exist, was deleted or, to enable it, is
    /// suspended, or the database fails.
    pub async fn set_enabled(
        &mut self,
        id: &ClientId,
        enabled: bool,
    ) -> Result<(), ClientRegistryError> {
        let client = self.locked(id).await?;
        if enabled && client.suspended_at.is_some() {
            return Err(ClientRegistryError::Suspended(client.id));
        }
        let changed = self
            .tx
            .oidc()
            .set_client_enabled(id, enabled)
            .await
            .map_err(ClientRegistryError::lookup(id))?;
        if changed {
            let client_id = id.clone();
            self.record(if enabled {
                DomainEvent::ClientEnabled { client_id }
            } else {
                DomainEvent::ClientDisabled { client_id }
            })
            .await?;
        }
        Ok(())
    }

    /// Suspends a client, which disables it until an operator lifts the
    /// suspension, or lifts it, which leaves the client disabled for its owner to
    /// enable. Only operators call this: no owner operation does. A client
    /// already in that state records nothing.
    ///
    /// # Errors
    /// Fails if the client does not exist or was deleted, or the database fails.
    pub async fn set_suspended(
        &mut self,
        id: &ClientId,
        suspended: bool,
    ) -> Result<(), ClientRegistryError> {
        self.locked(id).await?;
        if self.tx.oidc().set_client_suspended(id, suspended).await? {
            let client_id = id.clone();
            self.record(if suspended {
                DomainEvent::ClientSuspended { client_id }
            } else {
                DomainEvent::ClientSuspensionLifted { client_id }
            })
            .await?;
        }
        Ok(())
    }

    /// Gives a confidential client a new secret, returned here once. Its earlier
    /// secrets keep working for `grace` at most, so it can redeploy in between;
    /// zero revokes them now.
    ///
    /// # Errors
    /// Fails if the client does not exist, was deleted or is public, a secret
    /// cannot be generated or the database fails.
    pub async fn rotate_secret(
        &mut self,
        id: &ClientId,
        grace: GracePeriod,
    ) -> Result<ClientSecret, ClientRegistryError> {
        // Locked, so a concurrent rotation cannot insert a secret this cap misses.
        let client = self.locked(id).await?;
        if client.kind == ClientKind::Public {
            return Err(ClientRegistryError::Public(client.id));
        }
        let secret = ClientSecret::generate()?;
        self.make_current(id, grace, &secret).await?;
        Ok(secret)
    }

    /// Deletes a client. Its row stays, disabled, so its ID, which tokens carry as
    /// `aud`, is never given to another client. Its refresh families are revoked
    /// and its secrets and consents removed, so it stops working at once. A
    /// family a code exchange creates meanwhile is revoked too if it commits
    /// first, and otherwise never works: refreshing needs an enabled client.
    ///
    /// # Errors
    /// Fails if the client does not exist or was already deleted, or the database
    /// fails.
    pub async fn delete(&mut self, id: &ClientId) -> Result<(), ClientRegistryError> {
        // Families before the client, in the order a refresh rotation locks them.
        self.tx.tokens().lock_client_families(id).await?;
        self.locked(id).await?;
        self.tx
            .oidc()
            .delete_client(id)
            .await
            .map_err(ClientRegistryError::lookup(id))?;
        self.record(DomainEvent::ClientDeleted {
            client_id: id.clone(),
        })
        .await
    }

    /// Makes `secret` the locked confidential client `id`'s secret without an end,
    /// adding it unless it already is one, and makes its other secrets stop at
    /// `grace` from now at the latest. Records the rotation and returns `true` if
    /// either changed anything.
    async fn make_current(
        &mut self,
        id: &ClientId,
        grace: GracePeriod,
        secret: &ClientSecret,
    ) -> Result<bool, ClientRegistryError> {
        let digest = secret.digest();
        let added = !self
            .tx
            .oidc()
            .has_lasting_secret(id, digest.as_bytes())
            .await?;
        if added {
            self.tx
                .oidc()
                .insert_client_secret(id, digest.as_bytes())
                .await?;
        }
        let (previous_expire_at, capped) = self
            .tx
            .oidc()
            .cap_client_secrets(id, grace.duration(), Some(digest.as_bytes()))
            .await?;
        if added || capped {
            self.record(DomainEvent::ClientSecretRotated {
                client_id: id.clone(),
                previous_expire_at,
            })
            .await?;
        }
        Ok(added || capped)
    }

    /// Locks client `id` for the rest of the transaction, then reads it. A deleted
    /// client is refused: nothing may change it again.
    async fn locked(&mut self, id: &ClientId) -> Result<StoredOidcClient, ClientRegistryError> {
        self.tx
            .oidc()
            .lock_client(id)
            .await
            .map_err(ClientRegistryError::lookup(id))?;
        let client = self
            .tx
            .oidc()
            .find_client(id.as_str())
            .await?
            .ok_or_else(|| ClientRegistryError::Unknown(id.clone()))?;
        if client.deleted_at.is_some() {
            return Err(ClientRegistryError::Deleted(client.id));
        }
        Ok(client)
    }

    /// Records `event`, about no account, as made in this registry's context.
    async fn record(&mut self, event: DomainEvent) -> Result<(), ClientRegistryError> {
        Ok(self.tx.record(&self.context, None, event).await?)
    }
}

/// Changes made while auth serves requests apply to the next request.
#[cfg(test)]
mod tests;
