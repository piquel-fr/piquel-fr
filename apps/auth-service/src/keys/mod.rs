//! Signing keys: sealed in PostgreSQL, rotated on a schedule by one replica at a
//! time, and reloaded by every replica.
//!
//! A key is published as `next` for [`PRE_PUBLICATION`] before it signs, so
//! verifiers have it before its first token. It then signs as `active` for
//! [`ROTATION_PERIOD`], and stays published as `retiring` for
//! [`RETIRING_WINDOW`], while the tokens it signed may be valid. As `retired` it
//! verifies only `id_token_hint`s, which may be expired, for [`RETIRED_WINDOW`],
//! the longest session, and is then deleted.

use crate::{
    Operator, jobs::Shutdown, oidc::ACCESS_TOKEN_SECONDS, oidc::PublicDocument,
    security::SESSION_LIFETIME_DAYS,
};
use chrono::{DateTime, TimeDelta, Utc};
use piquel_common::{
    events::{DomainEvent, EventContext, SigningKeyChange},
    protocol::jwt::KeyId,
};
use piquel_crypto::{CryptoError, KeyEncryptionKey, KeySet, PublicKey, Rs256Key, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertSigningKey, SigningKeyState,
    SigningKeyType, StoredSigningKey,
};
use std::{
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};
use thiserror::Error;
use tokio::time::MissedTickBehavior;

/// How long a key signs before its successor is generated.
const ROTATION_PERIOD: TimeDelta = TimeDelta::days(90);
/// How long a `next` key is published before it signs: well over the JWKS cache lifetime.
const PRE_PUBLICATION: TimeDelta = TimeDelta::hours(24);
/// How long a `retiring` key stays published: the longest token lifetime, plus
/// the JWKS cache lifetime for verifiers that fetched keys just before it stopped.
const RETIRING_WINDOW: TimeDelta =
    TimeDelta::seconds(ACCESS_TOKEN_SECONDS + PublicDocument::MAX_AGE_SECONDS);
/// How long a retired key verifies `id_token_hint`s: the longest session.
const RETIRED_WINDOW: TimeDelta = TimeDelta::days(SESSION_LIFETIME_DAYS as i64);
/// How often every replica advances rotation and reloads its key set: also the
/// longest a revoked key keeps verifying at auth.
const RELOAD_EVERY: Duration = Duration::from_mins(1);
/// Characters of a generated key ID: 22 base64url characters carry 132 random bits.
const KEY_ID_LENGTH: usize = 22;

/// Failures of signing key storage and rotation, keeping their causes.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The database failed.
    #[error("signing key storage failed")]
    Database(#[from] DatabaseError),
    /// Generating, sealing or encoding a key failed.
    #[error("signing key cryptography failed")]
    Crypto(#[from] CryptoError),
    /// A stored key cannot be used, e.g. because it was sealed with another
    /// key-encryption key.
    #[error("stored signing key {id} cannot be used")]
    Stored {
        /// The key.
        id: KeyId,
        /// Why.
        #[source]
        source: CryptoError,
    },
    /// No key with this ID exists.
    #[error("no signing key has ID {0}")]
    Unknown(KeyId),
    /// No key signs, so no key set can be built.
    #[error("no signing key is active; run `auth-service keys rotate --now`")]
    NoActiveKey,
}

/// The key set this replica signs and verifies with. Clones share it, and a reload
/// replaces it for all of them at once.
#[derive(Clone)]
pub struct SigningKeys(Arc<RwLock<Arc<KeySet>>>);

impl SigningKeys {
    /// Shares `keys` until the next reload.
    pub(crate) fn new(keys: KeySet) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(keys))))
    }

    /// The current key set. A request keeps the set it started with.
    pub(crate) fn current(&self) -> Arc<KeySet> {
        // A writer only swaps the pointer, so a panic cannot leave it half-written.
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Replaces the key set for every clone.
    fn replace(&self, keys: KeySet) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
    }
}

/// The signing keys in the database, sealed with the key-encryption key. The
/// `keys` commands use it without the HTTP service.
#[derive(Clone)]
pub struct KeyStore {
    /// Holds the keys.
    database: Database,
    /// Seals and opens their private keys.
    kek: Arc<KeyEncryptionKey>,
}

impl KeyStore {
    /// The keys in `database`, sealed with `kek`.
    #[must_use]
    pub const fn new(database: Database, kek: Arc<KeyEncryptionKey>) -> Self {
        Self { database, kek }
    }

    /// Every key, oldest first.
    ///
    /// # Errors
    /// Returns the database failure.
    pub async fn list(&self) -> Result<Vec<StoredSigningKey>, KeyError> {
        Ok(self.database.signing_keys().list().await?)
    }

    /// Publishes a `next` key, or keeps the one already published, and returns
    /// its ID. With `immediately`, it signs at once, skipping pre-publication:
    /// verifiers that cached JWKS see an unknown key until they fetch again.
    ///
    /// # Errors
    /// Returns database and key generation failures.
    pub async fn rotate(&self, operator: &Operator, immediately: bool) -> Result<KeyId, KeyError> {
        self.change(Some(operator), async |change| {
            change.rotate(immediately).await
        })
        .await
    }

    /// Deletes key `id` at once, for a compromised key: it leaves JWKS, and every
    /// replica stops accepting it within a minute. When it was the active key,
    /// the `next` key is deleted too, and a new key signs at once; its ID is
    /// returned.
    ///
    /// # Errors
    /// Returns [`KeyError::Unknown`] for an unknown key, or the database or key
    /// generation failure.
    pub async fn revoke(&self, operator: &Operator, id: &KeyId) -> Result<Option<KeyId>, KeyError> {
        self.change(Some(operator), async |change| change.revoke(id).await)
            .await
    }

    /// Imports `key`, the deployment's PEM key, as the active key, so tokens it
    /// signed keep verifying. Imports only into an empty key set, so a repeated
    /// import never brings back a key that rotated out; returns whether it did.
    ///
    /// # Errors
    /// Returns database and sealing failures.
    pub async fn import(&self, operator: &Operator, key: Rs256Key) -> Result<bool, KeyError> {
        self.change(Some(operator), async |change| change.import(key).await)
            .await
    }

    /// Makes sure a key signs, generating one on first start, and loads the key
    /// set. Waits for any rotation in progress.
    ///
    /// # Errors
    /// Returns database, generation and loading failures.
    pub async fn start(&self) -> Result<SigningKeys, KeyError> {
        self.change(None, async |change| change.advance().await)
            .await?;
        Ok(SigningKeys::new(self.key_set(&self.list().await?)?))
    }

    /// Every [`RELOAD_EVERY`], advances rotation unless another replica is, then
    /// reloads `keys`, until `shutdown`. Failures are logged and leave the
    /// current key set in use.
    pub(crate) async fn run(self, keys: SigningKeys, shutdown: Shutdown) {
        let mut interval = tokio::time::interval(RELOAD_EVERY);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = shutdown.requested() => return,
                _ = interval.tick() => {}
            }
            if let Err(error) = self.tick().await {
                tracing::error!(?error, "signing key rotation failed");
            }
            match self.list().await.and_then(|stored| self.key_set(&stored)) {
                Ok(set) => keys.replace(set),
                Err(error) => tracing::error!(?error, "could not reload signing keys"),
            }
        }
    }

    /// Advances rotation once, unless another replica or command holds the lock.
    async fn tick(&self) -> Result<(), KeyError> {
        let mut tx = self.database.begin().await?;
        if self.tick_in(&mut tx, Utc::now()).await? {
            tx.commit().await?;
        }
        Ok(())
    }

    /// Advances rotation in `tx` as of `now`, if the lock is free. Returns whether it ran.
    async fn tick_in(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        now: DateTime<Utc>,
    ) -> Result<bool, KeyError> {
        if !tx.signing_keys().try_lock().await? {
            return Ok(false);
        }
        self.check(tx).await?;
        Change::new(tx, &self.kek, now, None).advance().await?;
        Ok(true)
    }

    /// Checks that this store's key-encryption key opens the stored active key
    /// and the stored keys form a key set, before changing them: otherwise a
    /// command or replica with another key-encryption key would store keys that
    /// no replica can load, and every replica would keep its stale key set.
    async fn check(&self, tx: &mut DatabaseTransaction<'_>) -> Result<(), KeyError> {
        let stored = tx.signing_keys().list().await?;
        if stored
            .iter()
            .any(|key| key.state == SigningKeyState::Active)
        {
            self.key_set(&stored)?;
        }
        Ok(())
    }

    /// Runs `apply` in a transaction holding the signing key lock, then commits.
    async fn change<T>(
        &self,
        operator: Option<&Operator>,
        apply: impl AsyncFnOnce(&mut Change<'_, '_>) -> Result<T, KeyError>,
    ) -> Result<T, KeyError> {
        let mut tx = self.database.begin().await?;
        tx.signing_keys().lock().await?;
        self.check(&mut tx).await?;
        let context = operator.map(Operator::context);
        let value = apply(&mut Change::new(&mut tx, &self.kek, Utc::now(), context)).await?;
        tx.commit().await?;
        Ok(value)
    }

    /// Builds the key set of `stored` keys: the active one signs, `next` and
    /// `retiring` ones verify and are published with it, retired ones verify hints.
    fn key_set(&self, stored: &[StoredSigningKey]) -> Result<KeySet, KeyError> {
        let mut signer = None;
        let (mut published, mut retired) = (Vec::new(), Vec::new());
        for key in stored {
            let invalid = |source| KeyError::Stored {
                id: key.id.clone(),
                source,
            };
            let public = PublicKey::from_jwk(key.public_jwk.clone()).map_err(invalid)?;
            match key.state {
                SigningKeyState::Active => {
                    // The table keeps a private key for every key that is not retired.
                    let sealed = key.sealed_private_key.as_deref().unwrap_or_default();
                    let der = self
                        .kek
                        .open(sealed, &Change::associated_data(&key.id, key.key_type))
                        .map_err(invalid)?;
                    signer = Some(match key.key_type {
                        SigningKeyType::Rsa => {
                            Rs256Key::from_der(key.id.as_str(), &der).map_err(invalid)?
                        }
                    });
                    published.push(public);
                }
                SigningKeyState::Next | SigningKeyState::Retiring => published.push(public),
                SigningKeyState::Retired => retired.push(public),
            }
        }
        Ok(KeySet::new(
            signer.ok_or(KeyError::NoActiveKey)?,
            published,
            retired,
        )?)
    }
}

/// One change to the signing keys: a transaction holding their lock, the time
/// it happens at, and the operator's context for its events.
struct Change<'t, 'c> {
    /// Holds the signing key lock until it ends.
    tx: &'t mut DatabaseTransaction<'c>,
    /// Seals new private keys.
    kek: &'t KeyEncryptionKey,
    /// When the change happens.
    now: DateTime<Utc>,
    /// Who makes it, for its events. `None` for rotation by the service itself,
    /// which records none yet: a release may write `JobName::KeyRotation` only
    /// once the release before it reads it (see `database-crate.md`).
    context: Option<EventContext>,
}

impl<'t, 'c> Change<'t, 'c> {
    /// A change in `tx`, which must hold the signing key lock.
    const fn new(
        tx: &'t mut DatabaseTransaction<'c>,
        kek: &'t KeyEncryptionKey,
        now: DateTime<Utc>,
        context: Option<EventContext>,
    ) -> Self {
        Self {
            tx,
            kek,
            now,
            context,
        }
    }

    /// Binds a sealed private key to its record: the key's ID and type, separated
    /// by a newline, which no key ID contains.
    fn associated_data(id: &KeyId, key_type: SigningKeyType) -> Vec<u8> {
        format!("{id}\n{key_type}").into_bytes()
    }

    /// Logs a change and records it as made by the operator, if any.
    async fn record(&mut self, id: &KeyId, change: SigningKeyChange) -> Result<(), KeyError> {
        tracing::info!(key_id = %id, %change, "signing key changed");
        if let Some(context) = &self.context {
            self.tx
                .record(
                    context,
                    None,
                    DomainEvent::SigningKeyChanged {
                        key_id: id.clone(),
                        change,
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// Seals and stores `key` in `state`.
    async fn insert(&mut self, key: &Rs256Key, state: SigningKeyState) -> Result<KeyId, KeyError> {
        let key_type = SigningKeyType::Rsa;
        let id: KeyId = key.kid().parse().map_err(|_| CryptoError::KeyId)?;
        let sealed_private_key = self.kek.seal(
            &key.private_key_der()?,
            &Self::associated_data(&id, key_type),
        )?;
        self.tx
            .signing_keys()
            .insert(&InsertSigningKey {
                id: id.clone(),
                key_type,
                state,
                public_jwk: key.public_key().jwk().clone(),
                sealed_private_key,
                at: self.now,
            })
            .await?;
        Ok(id)
    }

    /// Generates a key with a random ID, published as `next` or signing as `active`.
    async fn generate(&mut self, state: SigningKeyState) -> Result<KeyId, KeyError> {
        let random = Secret::generate()?.encoded();
        let id = self
            .insert(&Rs256Key::generate(&random[..KEY_ID_LENGTH])?, state)
            .await?;
        self.record(&id, SigningKeyChange::Generated).await?;
        if state == SigningKeyState::Active {
            self.record(&id, SigningKeyChange::Activated).await?;
        }
        Ok(id)
    }

    /// Makes `next` sign in place of `active`, which keeps being published.
    async fn promote(&mut self, next: &KeyId, active: Option<&KeyId>) -> Result<(), KeyError> {
        if let Some(active) = active {
            self.tx.signing_keys().deactivate(active, self.now).await?;
            self.record(active, SigningKeyChange::Retiring).await?;
        }
        self.tx.signing_keys().activate(next, self.now).await?;
        self.record(next, SigningKeyChange::Activated).await
    }

    /// The step rotation takes now, if any, for each key type: a key signs from
    /// the first start; a successor is published once the active key is
    /// [`ROTATION_PERIOD`] old, and signs once it has been published for
    /// [`PRE_PUBLICATION`]; retiring and retired keys end once their window has.
    async fn advance(&mut self) -> Result<(), KeyError> {
        let keys = self.tx.signing_keys().list().await?;
        let now = self.now;
        let older_than =
            |at: Option<DateTime<Utc>>, age: TimeDelta| at.is_some_and(|at| at <= now - age);
        let find = |state| Self::find(&keys, state);
        match (find(SigningKeyState::Active), find(SigningKeyState::Next)) {
            (None, None) => {
                self.generate(SigningKeyState::Active).await?;
            }
            // Only a manual change leaves a published key with none signing.
            (None, Some(next)) => self.promote(&next.id, None).await?,
            (Some(active), None) if older_than(active.activated_at, ROTATION_PERIOD) => {
                self.generate(SigningKeyState::Next).await?;
            }
            (Some(active), Some(next)) if older_than(Some(next.created_at), PRE_PUBLICATION) => {
                self.promote(&next.id, Some(&active.id)).await?;
            }
            (Some(_), _) => {}
        }
        for key in &keys {
            match key.state {
                SigningKeyState::Retiring if older_than(key.deactivated_at, RETIRING_WINDOW) => {
                    self.tx.signing_keys().retire(&key.id, self.now).await?;
                    self.record(&key.id, SigningKeyChange::Retired).await?;
                }
                SigningKeyState::Retired if older_than(key.retired_at, RETIRED_WINDOW) => {
                    self.tx.signing_keys().delete(&key.id).await?;
                    self.record(&key.id, SigningKeyChange::Deleted).await?;
                }
                SigningKeyState::Next
                | SigningKeyState::Active
                | SigningKeyState::Retiring
                | SigningKeyState::Retired => {}
            }
        }
        Ok(())
    }

    /// See [`KeyStore::rotate`].
    async fn rotate(&mut self, immediately: bool) -> Result<KeyId, KeyError> {
        let keys = self.tx.signing_keys().list().await?;
        let next = match Self::find(&keys, SigningKeyState::Next) {
            Some(next) => next.id.clone(),
            None => self.generate(SigningKeyState::Next).await?,
        };
        if immediately {
            let active = Self::find(&keys, SigningKeyState::Active).map(|key| &key.id);
            self.promote(&next, active).await?;
        }
        Ok(next)
    }

    /// See [`KeyStore::revoke`].
    async fn revoke(&mut self, id: &KeyId) -> Result<Option<KeyId>, KeyError> {
        let keys = self.tx.signing_keys().list().await?;
        let key = keys
            .iter()
            .find(|key| key.id == *id)
            .ok_or_else(|| KeyError::Unknown(id.clone()))?;
        self.tx.signing_keys().delete(id).await?;
        self.record(id, SigningKeyChange::Revoked).await?;
        if key.state != SigningKeyState::Active {
            return Ok(None);
        }
        // Whatever exposed the signing key may have exposed the `next` one too,
        // which would otherwise sign within a day; rotation publishes another.
        if let Some(next) = Self::find(&keys, SigningKeyState::Next) {
            self.tx.signing_keys().delete(&next.id).await?;
            self.record(&next.id, SigningKeyChange::Revoked).await?;
        }
        Ok(Some(self.generate(SigningKeyState::Active).await?))
    }

    /// The key of `keys` in `state`, of which the table allows one per key type.
    fn find(keys: &[StoredSigningKey], state: SigningKeyState) -> Option<&StoredSigningKey> {
        keys.iter().find(|key| key.state == state)
    }

    /// See [`KeyStore::import`].
    async fn import(&mut self, key: Rs256Key) -> Result<bool, KeyError> {
        if !self.tx.signing_keys().list().await?.is_empty() {
            return Ok(false);
        }
        let id = self.insert(&key, SigningKeyState::Active).await?;
        self.record(&id, SigningKeyChange::Imported).await?;
        Ok(true)
    }
}

/// Rotation steps, concurrent ticks, revocation and import on the test database.
#[cfg(test)]
mod tests;
