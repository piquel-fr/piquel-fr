//! Recomputes the chain from its anchor, checks every checkpoint against it, and
//! prunes it once it verifies.

use super::{AuditChain, AuditError, AuditKeys, Chain, CheckpointText};
use piquel_admin_api::{AuditVerification, ChainBreak, ChainProblem};
use piquel_crypto::CryptoError;
use piquel_repository::{ChainLink, Checkpoint, DatabaseTransaction};
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

impl AuditKeys {
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
}

impl AuditChain {
    /// Rows read per query.
    const PAGE: u32 = 1_000;

    /// Verifies the chain from its anchor: every sealed event's hash is
    /// recomputed, every checkpoint's signature is checked against `keys`, and
    /// every checkpoint's head against the recomputed chain. Stops at the first
    /// position that does not match. Reads one snapshot, so concurrent sealing or
    /// pruning cannot make it fail.
    ///
    /// # Errors
    /// Returns [`AuditError`] if the database fails or an event cannot be
    /// canonicalized; a broken chain is a result, not an error.
    pub async fn verify(&self, keys: &AuditKeys) -> Result<AuditVerification, AuditError> {
        let mut tx = self.database.begin().await?;
        tx.audit().read_snapshot().await?;
        let verification = Self::verify_in(&mut tx, keys).await?;
        tx.commit().await?;
        Ok(verification)
    }

    /// [`Self::verify`], in a transaction that sees one snapshot.
    async fn verify_in(
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
            .filter(|event| event.link.position <= start.position)
            .map(|event| ChainBreak {
                position: event.link.position,
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
        // A checkpoint past the last sealed event signed events that are gone.
        let broken = broken.or_else(|| {
            Self::first_problem(&checkpoints, head.position + 1..).or_else(|| {
                checkpoints
                    .range(head.position + 1..)
                    .next()
                    .map(|(&position, _)| ChainBreak {
                        position,
                        problem: ChainProblem::CheckpointBeyondChain,
                    })
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

    /// Recomputes the chain after `start`, comparing each event with its stored hash
    /// and each new link with `check`. Returns the last link that matched, and the
    /// first position that did not, if any.
    pub(super) async fn walk(
        tx: &mut DatabaseTransaction<'_>,
        start: ChainLink,
        check: impl Fn(&ChainLink) -> Option<ChainProblem>,
    ) -> Result<(ChainLink, Option<ChainBreak>), AuditError> {
        let mut head = start;
        loop {
            let page = tx.audit().chain(head.position, Self::PAGE).await?;
            if page.is_empty() {
                return Ok((head, None));
            }
            for event in page {
                let position = head.position + 1;
                let problem = if event.link.position == position {
                    let link = head.extend(&event.content)?;
                    if link.hash != event.link.hash {
                        Some(ChainProblem::EventChanged)
                    } else if let Some(problem) = check(&link) {
                        Some(problem)
                    } else {
                        head = link;
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
            let page = tx.audit().checkpoints(after, Self::PAGE).await?;
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

    /// Deletes every event through the checkpoint at `through`, which becomes the
    /// anchor, once the chain verifies against `keys` through it. Returns how
    /// many events were deleted. Checkpoints are kept, so the pruned history stays
    /// signed.
    ///
    /// # Errors
    /// Returns [`AuditError::NoCheckpoint`] unless a checkpoint was signed at
    /// `through`, [`AuditError::AlreadyPruned`] if the anchor is at or after it,
    /// [`AuditError::Broken`] if the chain breaks at or before it, or another
    /// [`AuditError`] if the database fails.
    pub async fn prune(&self, keys: &AuditKeys, through: u64) -> Result<u64, AuditError> {
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
        if let Some(anchor) = verification
            .anchor
            .filter(|anchor| anchor.position >= through)
        {
            return Err(AuditError::AlreadyPruned {
                anchor: anchor.position,
            });
        }
        if let Some(broken) = verification
            .broken
            .filter(|broken| broken.position <= through)
        {
            return Err(AuditError::Broken(broken));
        }
        let mut tx = self.database.begin().await?;
        let deleted = tx.prune_audit_chain(through).await?;
        tx.commit().await?;
        Ok(deleted)
    }
}
