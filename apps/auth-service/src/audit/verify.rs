//! Recomputes the chain from its anchor, checks every checkpoint against it, and
//! checks that it verifies before it is pruned. Also reads the dashboard's audit
//! page, which shows the newest verification recorded instead of making one.

use super::{
    AuditChain, AuditCheckpoint, AuditError, AuditKeys, AuditPage, AuditVerification, Chain,
    ChainBreak, ChainProblem, CheckpointText, Pruning, RecordedVerification, StoredChain,
    VerificationKeys,
};
use crate::alerts::Alerts;
use piquel_common::alerts::{Alert, AlertKind};
use piquel_common::events::{DomainEvent, EventContext};
use piquel_crypto::CryptoError;
use piquel_repository::{
    AuditRepository, ChainLink, ChainedEvent, Checkpoint, DatabaseTransaction, RecordedEvent,
    Verifications,
};
use std::collections::BTreeMap;

/// A checkpoint checked on its own, before the chain is compared with it.
struct Checked {
    /// The head stored beside its note.
    head: [u8; 32],
    /// Why it does not verify on its own, if it does not.
    problem: Option<ChainProblem>,
}

/// Every checkpoint by position.
type CheckedCheckpoints = BTreeMap<u64, Checked>;

/// The newest checkpoint that verifies, as [`AuditKeys::newest_trusted`] finds it.
pub(crate) struct TrustedCheckpoint {
    /// The checkpoint, if any verifies.
    pub(crate) trusted: Option<Checkpoint>,
    /// The newer checkpoints, newest first, none of which verifies.
    pub(crate) untrusted: Vec<Checkpoint>,
}

impl TrustedCheckpoint {
    /// The lowest position the search read: the trusted checkpoint's, or the
    /// oldest it passed over once it stopped at its limit, or 0 when it read every
    /// checkpoint. No checkpoint stored below it can change what it finds.
    pub(crate) fn floor(&self) -> u64 {
        match (&self.trusted, self.untrusted.last()) {
            (Some(trusted), _) => trusted.position,
            (None, Some(oldest)) if self.untrusted.len() == AuditKeys::UNTRUSTED_LIMIT => {
                oldest.position
            }
            (None, _) => 0,
        }
    }
}

impl AuditKeys {
    /// The most checkpoints that do not verify [`Self::newest_trusted`] passes over.
    const UNTRUSTED_LIMIT: usize = 1_000;

    /// Checks a checkpoint on its own: a listed key signed its note, and the note
    /// names the position, head and time stored beside it.
    ///
    /// # Errors
    /// Returns [`AuditError::Verifying`] if the cryptographic provider fails, which
    /// says nothing about the checkpoint.
    fn check(&self, checkpoint: &Checkpoint) -> Result<Checked, AuditError> {
        let stored = ChainLink {
            position: checkpoint.position,
            hash: checkpoint.head,
        };
        let problem = match self.verifiers.open(&checkpoint.note) {
            Ok(text) => match CheckpointText::parse(text) {
                Some(text) if text.head == stored && text.time == checkpoint.created_at => None,
                _ => Some(ChainProblem::CheckpointMalformed),
            },
            Err(CryptoError::NoteFormat | CryptoError::NoteText) => {
                Some(ChainProblem::CheckpointMalformed)
            }
            Err(CryptoError::NoteSignature | CryptoError::NoteUnverified) => {
                Some(ChainProblem::CheckpointSignature)
            }
            Err(error) => return Err(AuditError::Verifying(error)),
        };
        Ok(Checked {
            head: checkpoint.head,
            problem,
        })
    }

    /// Reads checkpoints through `audit`, newest first, until one verifies on its
    /// own: a listed key signed it, and its note names the values stored beside it.
    /// The database cannot check signatures, so someone with auth's database role
    /// could add newer checkpoints that do not verify, and removing a key makes
    /// those it signed fail too; they are returned as well. It looks at no more than
    /// [`Self::UNTRUSTED_LIMIT`] of them, so they cannot make every read costly,
    /// and finds none trusted past that many: the sealer then recomputes from the
    /// anchor, and signs above them.
    ///
    /// # Errors
    /// Returns [`AuditError`] if the database or the cryptographic provider fails.
    pub(crate) async fn newest_trusted(
        &self,
        audit: &mut AuditRepository<'_>,
    ) -> Result<TrustedCheckpoint, AuditError> {
        /// Checkpoints read per query.
        const BATCH: u32 = 100;
        let mut untrusted = Vec::new();
        loop {
            let before = untrusted
                .last()
                .map(|checkpoint: &Checkpoint| checkpoint.position);
            let page = audit.newest_checkpoints(before, BATCH).await?;
            if page.is_empty() {
                return Ok(TrustedCheckpoint {
                    trusted: None,
                    untrusted,
                });
            }
            for checkpoint in page {
                if self.check(&checkpoint)?.problem.is_none() {
                    return Ok(TrustedCheckpoint {
                        trusted: Some(checkpoint),
                        untrusted,
                    });
                }
                untrusted.push(checkpoint);
                if untrusted.len() == Self::UNTRUSTED_LIMIT {
                    return Ok(TrustedCheckpoint {
                        trusted: None,
                        untrusted,
                    });
                }
            }
        }
    }
}

impl AuditChain {
    /// Rows read per query: few enough that a page of the largest events migration
    /// 0035 allows still fits in memory.
    const BATCH: u32 = 100;
    /// Checkpoints per [`AuditPage`].
    const PAGE: u32 = 100;

    /// Verifies the chain from its anchor: every sealed event's hash is
    /// recomputed, every checkpoint's signature is checked against `keys`, and
    /// every checkpoint's head against the recomputed chain. Stops at the first
    /// position that does not match. Reads one snapshot, so concurrent sealing or
    /// pruning cannot make it fail.
    ///
    /// # Errors
    /// Returns [`AuditError`] if the database fails or an event cannot be
    /// canonicalized; a broken chain is a result, not an error.
    pub(crate) async fn verify(&self, keys: &AuditKeys) -> Result<AuditVerification, AuditError> {
        Self::verify_in(self.database.begin().await?, keys).await
    }

    /// [`Self::verify`], in `tx`, a transaction just begun, which it makes see one
    /// snapshot and commits.
    pub(super) async fn verify_in(
        mut tx: DatabaseTransaction<'_>,
        keys: &AuditKeys,
    ) -> Result<AuditVerification, AuditError> {
        tx.audit().read_snapshot().await?;
        let verification = Self::verify_snapshot(&mut tx, keys).await?;
        tx.commit().await?;
        Ok(verification)
    }

    /// Records `verification`, made as `context`, in `tx`, and commits: the
    /// dashboard's audit page shows the newest one recorded. A broken chain raises
    /// its alert, and an intact one clears it, unless the keys were given with
    /// `--key`, such as another environment's, which say nothing of this one's
    /// checkpoints.
    pub(crate) async fn record(
        mut tx: DatabaseTransaction<'_>,
        context: &EventContext,
        verification: &AuditVerification,
    ) -> Result<(), AuditError> {
        let verified = DomainEvent::AuditChainVerified(verification.clone());
        tx.record(context, None, verified).await?;
        if verification.keys != VerificationKeys::Given {
            let mut alerts = Alerts::new(&mut tx, context);
            match &verification.broken {
                Some(broken) => alerts.raise(Alert::AuditChainBroken(broken.clone())).await,
                None => alerts.clear(AlertKind::AuditChainBroken).await,
            }?;
        }
        Ok(tx.commit().await?)
    }

    /// The dashboard's audit page: the chain as stored, the newest verification
    /// the audit log records, and up to [`Self::PAGE`] checkpoints after `after`,
    /// or after the anchor, each judged by that verification, all from one
    /// snapshot. It recomputes nothing, so it costs the same however long the
    /// history: [`Self::verify`] runs only when an operator asks, or the
    /// [`Verifier`](super::Verifier) job finds the newest verification too old.
    ///
    /// # Errors
    /// Returns [`AuditError`] if the database fails or the recorded verification
    /// does not decode.
    pub(crate) async fn page(&self, after: Option<u64>) -> Result<AuditPage, AuditError> {
        let mut tx = self.database.begin().await?;
        tx.audit().read_snapshot().await?;
        let point = |checkpoint: Checkpoint| {
            ChainLink {
                position: checkpoint.position,
                hash: checkpoint.head,
            }
            .point()
        };
        let chain = StoredChain {
            anchor: tx.audit().anchor().await?.map(point),
            newest: tx.audit().head().await?.as_ref().map(Chain::point),
            unsealed: tx.audit().unsealed_count().await?,
        };
        // A verification a newer release recorded reads as unknown, so as none.
        let verified = tx
            .events()
            .newest_audit_verification(Verifications::Any)
            .await?
            .and_then(|stored| match stored.event {
                RecordedEvent::Known(DomainEvent::AuditChainVerified(verification)) => {
                    Some(RecordedVerification {
                        at: stored.occurred_at,
                        verification,
                    })
                }
                _ => None,
            });
        let after =
            after.unwrap_or_else(|| chain.anchor.as_ref().map_or(0, |anchor| anchor.position));
        // One more than a page tells whether another follows.
        let mut stored = tx.audit().checkpoints(after, Self::PAGE + 1).await?;
        tx.commit().await?;
        let more = stored.len() > Self::PAGE as usize;
        stored.truncate(Self::PAGE as usize);
        let next = more
            .then(|| stored.last().map(|checkpoint| checkpoint.position))
            .flatten();
        let broken = verified
            .as_ref()
            .and_then(|verified| verified.verification.broken.as_ref());
        let checkpoints = stored
            .into_iter()
            .map(|checkpoint| AuditCheckpoint {
                pruning: Pruning::of(chain.anchor.as_ref(), broken, checkpoint.position),
                signed_at: checkpoint.created_at,
                point: point(checkpoint),
            })
            .collect();
        Ok(AuditPage {
            chain,
            verified,
            checkpoints,
            next,
        })
    }

    /// [`Self::verify`], in a transaction that sees one snapshot.
    async fn verify_snapshot(
        tx: &mut DatabaseTransaction<'_>,
        keys: &AuditKeys,
    ) -> Result<AuditVerification, AuditError> {
        let checkpoints = Self::checkpoints(tx, keys).await?;
        let anchor = tx.audit().anchor().await?.map(|anchor| ChainLink {
            position: anchor.position,
            hash: anchor.head,
        });
        let start = anchor.unwrap_or(ChainLink::GENESIS);
        // Pruning deletes every event through the anchor, so one left there means
        // the anchor was moved to hide it.
        let leftover = tx
            .audit()
            .chain(0, 1)
            .await?
            .pop()
            .filter(|event| event.sealed.link.position <= start.position)
            .map(|event| ChainBreak {
                position: event.sealed.link.position,
                problem: ChainProblem::EventBeforeAnchor,
            });
        // Checkpoints at or before the anchor signed pruned events: only their
        // signatures and notes can still be checked.
        let pruned = Self::first_problem(&checkpoints, ..=start.position);
        let (head, broken) = match [leftover, pruned]
            .into_iter()
            .flatten()
            .min_by_key(|broken| broken.position)
        {
            Some(broken) => (start, Some(broken)),
            None => {
                Self::walk(tx, start, |link| match checkpoints.get(&link.position) {
                    Some(Checked {
                        problem: Some(problem),
                        ..
                    }) => Some(*problem),
                    Some(checked) if checked.head != link.hash => {
                        Some(ChainProblem::CheckpointMismatch)
                    }
                    _ => None,
                })
                .await?
            }
        };
        let events_checked = head.position - start.position;
        // A checkpoint past the last sealed event signed events that are gone. The
        // earliest one is where the chain breaks, whatever is wrong with later ones.
        let broken = broken.or_else(|| {
            checkpoints
                .range(head.position + 1..)
                .next()
                .map(|(&position, checked)| ChainBreak {
                    position,
                    problem: checked
                        .problem
                        .unwrap_or(ChainProblem::CheckpointBeyondChain),
                })
        });
        let checked_through = broken.as_ref().map_or(u64::MAX, |broken| broken.position);
        Ok(AuditVerification {
            checkpoints_checked: checkpoints.range(..checked_through).count() as u64,
            broken,
            events_checked,
            unsealed: tx.audit().unsealed_count().await?,
            anchor: anchor.as_ref().map(Chain::point),
            newest: (head.position > 0).then(|| head.point()),
            latest_checkpoint: checkpoints.last_key_value().map(|(&position, checked)| {
                ChainLink {
                    position,
                    hash: checked.head,
                }
                .point()
            }),
            keys: keys.source,
        })
    }

    /// Recomputes the chain after `start`, comparing each event with its stored hash,
    /// its recorded order with the previous event's, the one at `start` included
    /// unless it was pruned, and each new link with `check`. Returns the last link
    /// that matched, and the first position that did not, if any.
    pub(super) async fn walk(
        tx: &mut DatabaseTransaction<'_>,
        start: ChainLink,
        check: impl Fn(&ChainLink) -> Option<ChainProblem>,
    ) -> Result<(ChainLink, Option<ChainBreak>), AuditError> {
        let mut head = start;
        let mut previous = tx
            .audit()
            .chain(start.position.saturating_sub(1), 1)
            .await?
            .pop()
            .filter(|event| event.sealed.link.position == start.position)
            .map(|event| event.cursor);
        loop {
            let page = tx.audit().chain(head.position, Self::BATCH).await?;
            if page.is_empty() {
                return Ok((head, None));
            }
            for ChainedEvent { sealed, cursor } in page {
                let position = head.position + 1;
                let problem = if sealed.link.position == position {
                    let link = head.extend(&sealed.content)?;
                    if link.hash != sealed.link.hash {
                        Some(ChainProblem::EventChanged)
                    } else if previous.is_some_and(|previous| previous >= cursor) {
                        Some(ChainProblem::OutOfOrder)
                    } else if let Some(problem) = check(&link) {
                        Some(problem)
                    } else {
                        head = link;
                        previous = Some(cursor);
                        None
                    }
                } else {
                    Some(ChainProblem::MissingEvent)
                };
                if let Some(problem) = problem {
                    return Ok((head, Some(ChainBreak { position, problem })));
                }
            }
        }
    }

    /// Reads and checks every checkpoint on its own.
    async fn checkpoints(
        tx: &mut DatabaseTransaction<'_>,
        keys: &AuditKeys,
    ) -> Result<CheckedCheckpoints, AuditError> {
        let mut checked = BTreeMap::new();
        let mut after = 0;
        loop {
            let page = tx.audit().checkpoints(after, Self::BATCH).await?;
            let Some(last) = page.last() else {
                return Ok(checked);
            };
            after = last.position;
            for checkpoint in page {
                checked.insert(checkpoint.position, keys.check(&checkpoint)?);
            }
        }
    }

    /// The first checkpoint in `range` that does not verify on its own.
    fn first_problem(
        checkpoints: &CheckedCheckpoints,
        range: impl std::ops::RangeBounds<u64>,
    ) -> Option<ChainBreak> {
        checkpoints.range(range).find_map(|(&position, checked)| {
            checked
                .problem
                .map(|problem| ChainBreak { position, problem })
        })
    }

    /// Checks that the chain may be pruned through `through`: a checkpoint was
    /// signed there, the anchor is before it, and the chain verifies against `keys`
    /// through it. Pruning itself runs as the schema owner, since auth's role may
    /// not delete events.
    ///
    /// # Errors
    /// Returns [`AuditError::NotOwner`] when the connection's role may not delete
    /// events, before verifying anything, [`AuditError::NoCheckpoint`] unless a
    /// checkpoint was signed at
    /// `through`, [`AuditError::AlreadyPruned`] if the anchor is at or after it,
    /// [`AuditError::Broken`] if the chain breaks at or before it, or another
    /// [`AuditError`] if the database fails.
    pub(crate) async fn check_prunable(
        &self,
        keys: &AuditKeys,
        through: u64,
    ) -> Result<(), AuditError> {
        if !self.database.audit().may_prune().await? {
            return Err(AuditError::NotOwner);
        }
        let mut checkpoint = self
            .database
            .audit()
            .checkpoints(through.saturating_sub(1), 1)
            .await?;
        if checkpoint
            .pop()
            .is_none_or(|checkpoint| checkpoint.position != through)
        {
            return Err(AuditError::NoCheckpoint(through));
        }
        let verification = self.verify(keys).await?;
        let (anchor, broken) = (verification.anchor.as_ref(), verification.broken.as_ref());
        match Pruning::of(anchor, broken, through) {
            Pruning::Prunable => Ok(()),
            Pruning::Pruned { anchor } => Err(AuditError::AlreadyPruned { anchor }),
            Pruning::Broken(broken) => Err(AuditError::Broken(broken)),
        }
    }
}
