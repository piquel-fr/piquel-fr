//! Seals events into the chain and signs checkpoints of its head.

use super::{AuditChain, AuditError, AuditKeys, Chain, CheckpointText, TrustedCheckpoint};
use crate::{
    alerts::Alerts,
    config::AuditConfig,
    jobs::{ExclusiveJob, Shutdown},
};
use chrono::{SubsecRound, TimeDelta, Utc};
use sourceorigin_common::{
    alerts::{Alert, AlertKind},
    events::{EventContext, JobName},
};
use sourceorigin_crypto::NoteKey;
use sourceorigin_repository::{
    ChainLink, Checkpoint, EventContent, ExclusiveConnection, LockKey, SealedEvent,
};
use sourceorigin_telemetry::Counter;
use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

/// Checkpoints the sealer passed over because none of the environment's audit
/// keys verifies them, counted each time it looks for one to build on.
static UNTRUSTED_CHECKPOINTS: Counter = Counter::new(
    "sourceorigin.auth.audit.untrusted_checkpoints",
    "{checkpoint}",
    "Checkpoints newer than the newest one that verifies, counted each time the sealer passes over them.",
);

/// Seals events in safe consumer order, on one replica at a time, and signs a
/// checkpoint of the head every five minutes while there are new events.
///
/// Every replica tries the job's lock every five seconds, each time on a new
/// connection outside the pool (see `Database::try_exclusive`).
pub(crate) struct Sealer {
    /// Signs checkpoints; its name is the checkpoints' origin.
    key: Arc<NoteKey>,
    /// Verifies the checkpoints the sealer builds on.
    keys: Arc<AuditKeys>,
    /// The least time between two checkpoints.
    checkpoint_every: TimeDelta,
    /// Events sealed per transaction.
    batch: u32,
    /// The canonical format events are sealed in.
    format: i16,
    /// When an attempt to sign a checkpoint last ended in failure. The next try
    /// waits as long as the interval, so a broken chain is not recomputed on
    /// every pass.
    failed_at: Mutex<Option<Instant>>,
}

impl Sealer {
    /// Events sealed per transaction in production: few enough that a batch of
    /// the largest events migration 0035 allows still fits in memory.
    const BATCH: u32 = 100;
    /// The least time between two checkpoints in production.
    const CHECKPOINT_EVERY: TimeDelta = TimeDelta::minutes(5);

    /// A sealer signing with `audit`'s key, and building only on checkpoints its
    /// keys verify. It seals in [`EventContent::NEWEST_FORMAT`], which the release
    /// before this one verifies too.
    pub(crate) fn new(audit: &AuditConfig) -> Self {
        Self {
            key: audit.key.clone(),
            keys: audit.keys.clone(),
            checkpoint_every: Self::CHECKPOINT_EVERY,
            batch: Self::BATCH,
            format: EventContent::NEWEST_FORMAT,
            failed_at: Mutex::new(None),
        }
    }

    /// A sealer that signs a checkpoint on every pass with new events, for tests.
    #[cfg(test)]
    pub(crate) fn eager(audit: &AuditConfig) -> Self {
        Self {
            checkpoint_every: TimeDelta::zero(),
            ..Self::new(audit)
        }
    }

    /// This sealer, signing at most once per `every`, for tests.
    #[cfg(test)]
    pub(crate) fn checkpointing_every(self, every: TimeDelta) -> Self {
        Self {
            checkpoint_every: every,
            ..self
        }
    }

    /// This sealer, sealing `batch` events per transaction, in `format`, for tests.
    #[cfg(test)]
    pub(crate) fn sealing(self, batch: u32, format: i16) -> Self {
        Self {
            batch,
            format,
            ..self
        }
    }

    /// Seals up to [`Self::batch`] events after the head in one transaction, and
    /// returns how many it sealed. Positions follow [`unsealed`]'s order, so no
    /// event can later need a position before one already given.
    ///
    /// [`unsealed`]: sourceorigin_repository::AuditRepository::unsealed
    pub(super) async fn seal(
        &self,
        connection: &mut ExclusiveConnection,
    ) -> Result<usize, AuditError> {
        let mut tx = connection.begin().await?;
        let mut head = tx.audit().head().await?.unwrap_or(ChainLink::GENESIS);
        let mut sealed = Vec::new();
        for content in tx.audit().unsealed(self.batch, self.format).await? {
            head = head.extend(&content)?;
            sealed.push(SealedEvent {
                link: head,
                content,
            });
        }
        if !sealed.is_empty() {
            tx.audit().seal(&sealed).await?;
        }
        tx.commit().await?;
        Ok(sealed.len())
    }

    /// Signs and stores a checkpoint of the head, if it moved since the newest
    /// checkpoint and that one is at least [`Self::checkpoint_every`] old.
    ///
    /// It builds on the newest checkpoint the environment's keys verify. Newer
    /// ones that do not verify, which someone with auth's database role but not
    /// the audit key could add, are logged, counted and passed over, so they
    /// cannot stop signing: the next checkpoint follows them once a new event is
    /// sealed. While one holds the head's position, nothing is recomputed.
    /// `audit verify` still reports them.
    ///
    /// The head is recomputed from the checkpoint built on rather than read back,
    /// so a checkpoint never signs events that no longer match their stored hashes,
    /// or a chain with recent events missing. It cannot tell an edit whose hashes
    /// were recomputed too: events are signed only once a checkpoint covers them.
    ///
    /// After a failure, nothing is tried until [`Self::checkpoint_every`] has
    /// passed.
    ///
    /// Refusing raises the [`Alert::CheckpointRefused`] alert, and the next
    /// recomputation that matches clears it.
    ///
    /// # Errors
    /// Returns [`AuditError::Broken`], signing nothing, if the events sealed since
    /// that checkpoint no longer match their hashes.
    pub(super) async fn checkpoint(
        &self,
        connection: &mut ExclusiveConnection,
    ) -> Result<(), AuditError> {
        let failed_at = || {
            self.failed_at
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        };
        let waiting = failed_at().is_some_and(|at| {
            TimeDelta::from_std(at.elapsed()).is_ok_and(|elapsed| elapsed < self.checkpoint_every)
        });
        if waiting {
            return Ok(());
        }
        let signed = self.sign(connection).await;
        *failed_at() = signed.is_err().then(Instant::now);
        signed
    }

    /// Signs and stores a checkpoint of the head if one is due; see
    /// [`Self::checkpoint`].
    async fn sign(&self, connection: &mut ExclusiveConnection) -> Result<(), AuditError> {
        let mut tx = connection.begin().await?;
        // The note's time has whole seconds, and so does the stored copy.
        let time = Utc::now().trunc_subsecs(0);
        let TrustedCheckpoint { trusted, untrusted } =
            self.keys.newest_trusted(&mut tx.audit()).await?;
        if let Some(newest) = untrusted.first() {
            UNTRUSTED_CHECKPOINTS.add(untrusted.len() as u64, &());
            tracing::error!(
                count = untrusted.len(),
                newest = newest.position,
                "audit checkpoints do not verify against the audit keys; signing from the newest that does"
            );
        }
        // Only a trusted checkpoint counts for the interval, so newer untrusted
        // ones cannot postpone signing.
        if trusted
            .as_ref()
            .is_some_and(|trusted| time - trusted.created_at < self.checkpoint_every)
        {
            return Ok(());
        }
        // Recompute from the trusted checkpoint, or the anchor if it is newer, as
        // when the key that signed it was removed: only pruning moves the anchor.
        let anchor = tx.audit().anchor().await?;
        let start = [trusted.as_ref(), anchor.as_ref()]
            .into_iter()
            .flatten()
            .max_by_key(|checkpoint| checkpoint.position)
            .map_or(ChainLink::GENESIS, |checkpoint| ChainLink {
                position: checkpoint.position,
                hash: checkpoint.head,
            });
        // Nothing new to sign, or an untrusted checkpoint holds the head's position
        // until the next event is sealed: return before recomputing anything.
        let newest = untrusted
            .first()
            .map_or(start.position, |newest| newest.position);
        let stored = tx.audit().head().await?.unwrap_or(ChainLink::GENESIS);
        if stored.position <= newest {
            return Ok(());
        }
        let (head, broken) = AuditChain::walk(&mut tx, start, |_| None).await?;
        let context = EventContext::system(JobName::AuditSealer);
        let mut alerts = Alerts::new(&mut tx, &context);
        if let Some(broken) = broken {
            alerts
                .raise(Alert::CheckpointRefused(broken.clone()))
                .await?;
            tx.commit().await?;
            return Err(AuditError::Broken(broken));
        }
        alerts.clear(AlertKind::CheckpointRefused).await?;
        let text = CheckpointText {
            origin: self.key.verifier().name().to_owned(),
            head,
            time,
        };
        let note = self.key.sign(&text.render()).map_err(AuditError::Signing)?;
        tx.audit()
            .insert_checkpoint(&Checkpoint {
                position: head.position,
                head: head.hash,
                created_at: time,
                note,
            })
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Seals every event ready to seal, signing a checkpoint after each batch if
    /// one is due, so a backlog of full batches never postpones it. A checkpoint
    /// that fails, e.g. over a broken chain, is not tried again this pass, and
    /// sealing goes on: its error is returned once every event is sealed. Stops
    /// sealing early once `shutdown` is requested.
    pub(crate) async fn pass(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: Option<&Shutdown>,
    ) -> Result<(), AuditError> {
        let mut failed = None;
        loop {
            let sealed = match self.seal(connection).await {
                Ok(sealed) => sealed,
                Err(error) => {
                    if let Some(failed) = failed {
                        tracing::error!(error = ?failed, "could not sign an audit checkpoint");
                    }
                    return Err(error);
                }
            };
            if failed.is_none() {
                failed = self.checkpoint(connection).await.err();
            }
            if sealed < self.batch as usize || shutdown.is_some_and(Shutdown::is_requested) {
                return failed.map_or(Ok(()), Err);
            }
        }
    }
}

impl ExclusiveJob for Sealer {
    const NAME: &'static str = "audit-sealer";
    const LOCK: LockKey = LockKey::AuditChain;
    const EVERY: Duration = Duration::from_secs(5);
    type Error = AuditError;

    async fn run(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: &Shutdown,
    ) -> Result<(), AuditError> {
        self.pass(connection, Some(shutdown)).await
    }
}
