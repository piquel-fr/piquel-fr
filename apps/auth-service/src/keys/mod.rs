//! Signing keys: sealed in PostgreSQL, rotated on a schedule by one replica at a
//! time, and reloaded by every replica.
//!
//! A key is published as `next` for [`PRE_PUBLICATION`] before it signs, so
//! verifiers have it before its first token. It then signs as `active` for
//! [`ROTATION_PERIOD`], and stays published as `retiring` for
//! [`RETIRING_WINDOW`], while the tokens it signed may be valid. As `retired` it
//! verifies only `id_token_hint`s, which may be expired, for [`RETIRED_WINDOW`],
//! the longest session, and is then deleted.
//!
//! Every replica reloads its key set each [`RELOAD_EVERY`]. One that cannot turns
//! unready after [`UNREADY_AFTER`], and stops using its stale key set after
//! [`STALE_AFTER`], since it may still trust a revoked key.

use crate::{
    AdminError, Operator, jobs::Shutdown, oidc::ACCESS_TOKEN_SECONDS, oidc::PublicDocument,
    security::SESSION_LIFETIME_DAYS,
};
use chrono::{DateTime, TimeDelta, Utc};
use piquel_common::{
    events::{DomainEvent, EventContext, SigningKeyChange},
    protocol::jwt::KeyId,
};
use piquel_crypto::{CryptoError, Digest, KeyEncryptionKey, KeySet, PublicKey, Rs256Key, Secret};
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, InsertSigningKey, SigningKeyState,
    SigningKeyType, StoredSigningKey,
};
use std::{
    sync::{Arc, PoisonError, RwLock},
    time::{Duration, Instant},
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
/// longest a revoked key keeps verifying at auth, while reloads succeed.
const RELOAD_EVERY: Duration = Duration::from_mins(1);
/// How long a replica may go without reloading its key set before readiness
/// fails, so traffic moves to the replicas that can, and someone hears of it.
const UNREADY_AFTER: Duration = Duration::from_mins(5);
/// How long a replica may go without reloading its key set before it stops using
/// it: the longest a revoked key keeps verifying at a replica that cannot reload.
const STALE_AFTER: Duration = Duration::from_mins(15);
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
    /// A stored private key is not the private half of the public key stored
    /// with it.
    #[error("stored signing key {0} does not match its public key")]
    Mismatched(KeyId),
    /// No key with this ID exists.
    #[error("no signing key has ID {0}")]
    Unknown(KeyId),
    /// No key signs, so no key set can be built.
    #[error("no signing key is active; run `auth-service keys rotate --now`")]
    NoActiveKey,
    /// The operator may no longer make the change, checked just before it
    /// commits, as every admin change is.
    #[error(transparent)]
    Refused(Box<AdminError>),
}

/// This replica has not reloaded its key set for too long: it may still trust a
/// revoked key, or lack the one that signs now.
#[derive(Debug, Error)]
#[error("signing keys were last reloaded {}s ago", .age.as_secs())]
pub(crate) struct StaleKeys {
    /// How long ago.
    age: Duration,
}

/// The key set this replica signs and verifies with. Clones share it, and a reload
/// replaces it for all of them at once.
#[derive(Clone)]
pub struct SigningKeys(Arc<RwLock<Loaded>>);

/// A key set, and when it was loaded.
struct Loaded {
    /// The keys.
    keys: Arc<KeySet>,
    /// When they were loaded.
    at: Instant,
}

impl SigningKeys {
    /// Shares `keys` until the next reload.
    pub(crate) fn new(keys: KeySet) -> Self {
        Self(Arc::new(RwLock::new(Loaded {
            keys: Arc::new(keys),
            at: Instant::now(),
        })))
    }

    /// The current key set. A request keeps the set it started with.
    ///
    /// # Errors
    /// Returns [`StaleKeys`] once no reload succeeded for [`STALE_AFTER`].
    pub(crate) fn current(&self) -> Result<Arc<KeySet>, StaleKeys> {
        self.loaded_within(STALE_AFTER)
    }

    /// Whether readiness passes: a reload succeeded in the last [`UNREADY_AFTER`].
    ///
    /// # Errors
    /// Returns [`StaleKeys`] otherwise.
    pub(crate) fn ready(&self) -> Result<(), StaleKeys> {
        self.loaded_within(UNREADY_AFTER).map(drop)
    }

    /// The current key set, if it was loaded at most `limit` ago.
    fn loaded_within(&self, limit: Duration) -> Result<Arc<KeySet>, StaleKeys> {
        // A writer only swaps the value, so a panic cannot leave it half-written.
        let loaded = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let age = loaded.at.elapsed();
        if age > limit {
            return Err(StaleKeys { age });
        }
        Ok(Arc::clone(&loaded.keys))
    }

    /// Replaces the key set for every clone.
    fn replace(&self, keys: KeySet) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Loaded {
            keys: Arc::new(keys),
            at: Instant::now(),
        };
    }

    /// Makes the key set look loaded `age` ago, as if reloads had failed since.
    #[cfg(test)]
    fn age(&self, age: Duration) {
        let mut loaded = self.0.write().unwrap_or_else(PoisonError::into_inner);
        loaded.at = Instant::now().checked_sub(age).expect("an earlier instant");
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
    /// Returns database and key generation failures, and refuses to make a `next`
    /// key sign if its private key cannot be opened or does not match it.
    pub async fn rotate(&self, operator: &Operator, immediately: bool) -> Result<KeyId, KeyError> {
        self.change(Some(operator), None, async |change| {
            change.rotate(immediately).await
        })
        .await
    }

    /// Deletes key `id` at once, for a compromised key: it leaves JWKS, and every
    /// replica stops accepting it within a minute. When it was the active key,
    /// every other key whose private key is still stored, `next` and `retiring`,
    /// is deleted too, and a new key signs at once; its ID is returned. Revoking
    /// the active key works even when it cannot be opened, so it recovers a key
    /// set whose active key is broken.
    ///
    /// # Errors
    /// Returns [`KeyError::Unknown`] for an unknown key, or the database or key
    /// generation failure.
    pub async fn revoke(&self, operator: &Operator, id: &KeyId) -> Result<Option<KeyId>, KeyError> {
        self.change(Some(operator), Some(id), async |change| {
            change.revoke(id).await
        })
        .await
    }

    /// Imports `key`, the deployment's PEM key, as the active key, so tokens it
    /// signed keep verifying. Imports only into an empty key set, so a repeated
    /// import never brings back a key that rotated out; returns whether it did.
    ///
    /// # Errors
    /// Returns database and sealing failures.
    pub async fn import(&self, operator: &Operator, key: Rs256Key) -> Result<bool, KeyError> {
        self.change(Some(operator), None, async |change| {
            change.import(key).await
        })
        .await
    }

    /// Makes sure a key signs, generating one on first start, and loads the key
    /// set. Waits for any rotation in progress.
    ///
    /// # Errors
    /// Returns database, generation and loading failures.
    pub async fn start(&self) -> Result<SigningKeys, KeyError> {
        self.change(None, None, async |change| change.advance().await)
            .await?;
        Ok(SigningKeys::new(self.key_set(&self.list().await?)?))
    }

    /// Every [`RELOAD_EVERY`], advances rotation unless another replica is, then
    /// reloads `keys`, until `shutdown`. Failures are logged and leave the
    /// current key set in use, until it is stale (see [`SigningKeys::current`]).
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
            self.reload(&keys).await;
        }
    }

    /// Reloads `keys` from the database. A failure is logged, and leaves the
    /// current key set in use while it is fresh.
    async fn reload(&self, keys: &SigningKeys) {
        match self.list().await.and_then(|stored| self.key_set(&stored)) {
            Ok(set) => keys.replace(set),
            Err(error) => tracing::error!(?error, "could not reload signing keys"),
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
        self.check(tx, None).await?;
        Change::new(tx, self, now, None).advance().await?;
        Ok(true)
    }

    /// Checks that this store's key-encryption key opens the stored active key
    /// and the stored keys form a key set, before changing them: otherwise a
    /// command or replica with another key-encryption key would store keys that
    /// no replica can load, and every replica would keep its stale key set.
    ///
    /// Revoking the active key, `revoking`, keeps no stored private key, so it
    /// skips the check, which recovers a key set whose active key cannot be
    /// opened. An operator with the wrong key-encryption key could then replace a
    /// working key with one no replica opens: replicas turn unready, and revoking
    /// it again with the right key-encryption key recovers.
    async fn check(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        revoking: Option<&KeyId>,
    ) -> Result<(), KeyError> {
        let stored = tx.signing_keys().list().await?;
        if Change::find(&stored, SigningKeyState::Active)
            .is_some_and(|active| Some(&active.id) != revoking)
        {
            self.key_set(&stored)?;
        }
        Ok(())
    }

    /// Runs `apply` in a transaction holding the signing key lock, then commits
    /// once `operator`, if any, is authorized again after the last write, as
    /// `AdminService` authorizes every change. `revoking` names the key the
    /// change revokes, if any (see [`Self::check`]).
    async fn change<T>(
        &self,
        operator: Option<&Operator>,
        revoking: Option<&KeyId>,
        apply: impl AsyncFnOnce(&mut Change<'_, '_>) -> Result<T, KeyError>,
    ) -> Result<T, KeyError> {
        let mut tx = self.database.begin().await?;
        tx.signing_keys().lock().await?;
        self.check(&mut tx, revoking).await?;
        let context = operator.map(Operator::context);
        let value = apply(&mut Change::new(&mut tx, self, Utc::now(), context)).await?;
        if let Some(operator) = operator {
            operator
                .authorize(&mut tx)
                .await
                .map_err(|refused| KeyError::Refused(Box::new(refused)))?;
        }
        tx.commit().await?;
        Ok(value)
    }

    /// Builds the key set of `stored` keys: the active one signs, `next` and
    /// `retiring` ones verify and are published with it, retired ones verify hints.
    /// Each key with a private key is opened first, so only public keys matching
    /// the private keys sealed with them are trusted. A `next` or `retiring` one
    /// that fails is left out and logged, rather than failing the whole set: it
    /// signs nothing, and promotion refuses it.
    fn key_set(&self, stored: &[StoredSigningKey]) -> Result<KeySet, KeyError> {
        let mut signer = None;
        let (mut published, mut retired) = (Vec::new(), Vec::new());
        for key in stored {
            match key.state {
                SigningKeyState::Active => {
                    let private = self.open(key)?;
                    published.push(private.public_key().clone());
                    signer = Some(private);
                }
                SigningKeyState::Next | SigningKeyState::Retiring => match self.open(key) {
                    Ok(private) => published.push(private.public_key().clone()),
                    Err(error) => tracing::error!(
                        ?error,
                        key_id = %key.id,
                        state = %key.state,
                        "leaving out a signing key that cannot be opened",
                    ),
                },
                SigningKeyState::Retired => retired.push(
                    PublicKey::from_jwk(key.public_jwk.clone()).map_err(|source| {
                        KeyError::Stored {
                            id: key.id.clone(),
                            source,
                        }
                    })?,
                ),
            }
        }
        Ok(KeySet::new(
            signer.ok_or(KeyError::NoActiveKey)?,
            published,
            retired,
        )?)
    }

    /// Opens `key`'s sealed private key, under either [`Binding`], and checks it
    /// is the private half of the public key stored with it.
    fn open(&self, key: &StoredSigningKey) -> Result<Rs256Key, KeyError> {
        let invalid = |source| KeyError::Stored {
            id: key.id.clone(),
            source,
        };
        let thumbprint = PublicKey::from_jwk(key.public_jwk.clone())
            .and_then(|public| public.thumbprint())
            .map_err(invalid)?;
        // The table keeps a private key for every key that is not retired.
        let sealed = key.sealed_private_key.as_deref().unwrap_or_default();
        // Opening fails only as `Unsealable`, so the attempts lose no detail.
        let der = Binding::ALL
            .into_iter()
            .find_map(|binding| {
                let associated = binding.associated_data(&key.id, key.key_type, &thumbprint);
                self.kek.open(sealed, &associated).ok()
            })
            .ok_or(CryptoError::Unsealable)
            .map_err(invalid)?;
        let private = match key.key_type {
            SigningKeyType::Rsa => Rs256Key::from_der(key.id.as_str(), &der).map_err(invalid)?,
        };
        if private.public_key().thumbprint().map_err(invalid)? != thumbprint {
            return Err(KeyError::Mismatched(key.id.clone()));
        }
        Ok(private)
    }
}

/// What the associated data of a sealed private key binds it to, so a sealed key
/// moved to another record fails to open.
#[derive(Clone, Copy, Debug)]
enum Binding {
    /// The key's ID, its type and its public key's JWK thumbprint, so the
    /// public key stored with it cannot be swapped either. Releases open it, but
    /// none seals with it yet: the release before must open it first, or a
    /// rollback would leave keys no replica can open (#316).
    PublicKey,
    /// The key's ID and type: how every release so far seals.
    Record,
}

impl Binding {
    /// Every binding, in the order opening tries them.
    const ALL: [Self; 2] = [Self::PublicKey, Self::Record];
    /// The binding new keys are sealed with.
    const SEALS: Self = Self::Record;

    /// The associated data of the key `id` of `key_type`, whose public key's JWK
    /// thumbprint is `thumbprint`. Fields are separated by newlines, which none
    /// contains.
    fn associated_data(self, id: &KeyId, key_type: SigningKeyType, thumbprint: &Digest) -> Vec<u8> {
        match self {
            Self::PublicKey => format!("{id}\n{key_type}\n{}", thumbprint.encoded()),
            Self::Record => format!("{id}\n{key_type}"),
        }
        .into_bytes()
    }
}

/// One change to the signing keys: a transaction holding their lock, the time
/// it happens at, and the operator's context for its events.
struct Change<'t, 'c> {
    /// Holds the signing key lock until it ends.
    tx: &'t mut DatabaseTransaction<'c>,
    /// Seals new private keys and opens stored ones.
    store: &'t KeyStore,
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
        store: &'t KeyStore,
        now: DateTime<Utc>,
        context: Option<EventContext>,
    ) -> Self {
        Self {
            tx,
            store,
            now,
            context,
        }
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
        let sealed_private_key = self.store.kek.seal(
            &key.private_key_der()?,
            &Binding::SEALS.associated_data(&id, key_type, &key.public_key().thumbprint()?),
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

    /// Makes `next` sign in place of `active`, which keeps being published. First
    /// opens `next`'s private key and checks it matches its public key, so a key
    /// that cannot sign is refused, and the active key keeps signing: revoke it,
    /// and rotation publishes another.
    async fn promote(&mut self, next: &KeyId, active: Option<&KeyId>) -> Result<(), KeyError> {
        let keys = self.tx.signing_keys().list().await?;
        let stored = keys
            .iter()
            .find(|key| key.id == *next)
            .ok_or_else(|| KeyError::Unknown(next.clone()))?;
        self.store.open(stored)?;
        if let Some(active) = active {
            self.tx.signing_keys().deactivate(active, self.now).await?;
            self.record(active, SigningKeyChange::Retiring).await?;
        }
        self.tx.signing_keys().activate(next, self.now).await?;
        self.record(next, SigningKeyChange::Activated).await
    }

    /// The step rotation takes now, if any: a key signs from
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
            (None, Some(next)) => self.promote(&next.id, None).await.or_else(Self::refused)?,
            (Some(active), None) if older_than(active.activated_at, ROTATION_PERIOD) => {
                self.generate(SigningKeyState::Next).await?;
            }
            (Some(active), Some(next)) if older_than(Some(next.created_at), PRE_PUBLICATION) => {
                self.promote(&next.id, Some(&active.id))
                    .await
                    .or_else(Self::refused)?;
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

    /// Logs `error` if it refuses a promotion, which writes nothing, so rotation
    /// still ends expired keys while the active key keeps signing. Any other
    /// error stays one.
    fn refused(error: KeyError) -> Result<(), KeyError> {
        match error {
            KeyError::Stored { .. } | KeyError::Mismatched(_) => {
                tracing::error!(?error, "next signing key cannot sign; revoke it");
                Ok(())
            }
            error => Err(error),
        }
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
        // Whatever exposed the signing key may have exposed every private key still
        // stored: `next`, which would sign within a day, and `retiring` ones, which
        // still verify for up to an hour. Rotation publishes another `next`.
        for other in keys
            .iter()
            .filter(|key| matches!(key.state, SigningKeyState::Next | SigningKeyState::Retiring))
        {
            self.tx.signing_keys().delete(&other.id).await?;
            self.record(&other.id, SigningKeyChange::Revoked).await?;
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
