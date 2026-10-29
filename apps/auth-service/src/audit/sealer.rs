//! Seals events into the chain and signs checkpoints of its head.

use super::{AuditChain, AuditError, Chain, CheckpointText};
use crate::jobs::{ExclusiveJob, Shutdown};
use chrono::{SubsecRound, TimeDelta, Utc};
use piquel_crypto::NoteKey;
use piquel_repository::{ChainLink, Checkpoint, ExclusiveConnection, LockKey, SealedEvent};
use std::{sync::Arc, time::Duration};

/// Seals events in safe consumer order, on one replica at a time, and signs a
/// checkpoint of the head every five minutes while there are new events.
///
/// Every replica tries the job's lock every five seconds, each time on a new
/// connection outside the pool (see `Database::try_exclusive`).
pub(crate) struct Sealer {
    /// Signs checkpoints; its name is the checkpoints' origin.
    key: Arc<NoteKey>,
    /// The least time between two checkpoints.
    checkpoint_every: TimeDelta,
}

impl Sealer {
    /// Events sealed per transaction.
    const BATCH: u32 = 1_000;
    /// The least time between two checkpoints in production.
    const CHECKPOINT_EVERY: TimeDelta = TimeDelta::minutes(5);

    /// A sealer signing with `key`.
    pub(crate) const fn new(key: Arc<NoteKey>) -> Self {
        Self {
            key,
            checkpoint_every: Self::CHECKPOINT_EVERY,
        }
    }

    /// A sealer that signs a checkpoint on every pass with new events, for tests.
    #[cfg(test)]
    pub(crate) const fn eager(key: Arc<NoteKey>) -> Self {
        Self {
            key,
            checkpoint_every: TimeDelta::zero(),
        }
    }

    /// Seals up to [`Self::BATCH`] events after the head in one transaction, and
    /// returns how many it sealed. Positions follow [`unsealed`]'s order, so no
    /// event can later need a position before one already given.
    ///
    /// [`unsealed`]: piquel_repository::AuditRepository::unsealed
    pub(super) async fn seal(connection: &mut ExclusiveConnection) -> Result<usize, AuditError> {
        let mut tx = connection.begin().await?;
        let mut head = tx.audit().head().await?.unwrap_or(ChainLink::GENESIS);
        let mut sealed = Vec::new();
        for content in tx.audit().unsealed(Self::BATCH).await? {
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

    /// Signs and stores a checkpoint of the head, if it moved since the latest
    /// checkpoint and that one is at least [`Self::checkpoint_every`] old.
    ///
    /// The head is recomputed from the latest signed one rather than read back, so
    /// a checkpoint never signs events that no longer match their stored hashes,
    /// or a chain with recent events missing. It cannot tell an edit whose hashes
    /// were recomputed too: events are signed only once a checkpoint covers them.
    ///
    /// # Errors
    /// Returns [`AuditError::Broken`], signing nothing, if the events sealed since
    /// the latest checkpoint no longer match their hashes.
    pub(super) async fn checkpoint(
        &self,
        connection: &mut ExclusiveConnection,
    ) -> Result<(), AuditError> {
        let mut tx = connection.begin().await?;
        // The note's time has whole seconds, and so does the stored copy.
        let time = Utc::now().trunc_subsecs(0);
        let latest = tx.audit().latest_checkpoint().await?;
        if latest
            .as_ref()
            .is_some_and(|latest| time - latest.created_at < self.checkpoint_every)
        {
            return Ok(());
        }
        // The anchor is a checkpoint, so the latest checkpoint is at or after it.
        let start = latest.map_or(ChainLink::GENESIS, |latest| ChainLink {
            position: latest.position,
            hash: latest.head,
        });
        let (head, broken) = AuditChain::walk(&mut tx, start, |_| None).await?;
        if let Some(broken) = broken {
            return Err(AuditError::Broken(broken));
        }
        if head.position == start.position {
            return Ok(());
        }
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

    /// Seals every event ready to seal, then signs a checkpoint if one is due.
    /// Stops sealing early once `shutdown` is requested.
    pub(crate) async fn pass(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: Option<&Shutdown>,
    ) -> Result<(), AuditError> {
        while Self::seal(connection).await? == Self::BATCH as usize {
            if shutdown.is_some_and(Shutdown::is_requested) {
                return Ok(());
            }
        }
        self.checkpoint(connection).await
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
