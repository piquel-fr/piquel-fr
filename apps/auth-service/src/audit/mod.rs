//! The tamper-evident audit history: a hash chain over sealed events, signed
//! checkpoints of its head, their publication, verification and pruning. See
//! `docs/security/audit-history.md`.
//!
//! Events are recorded unsealed, so a sign-in never waits on the chain head. The
//! [`Sealer`] job, on one replica at a time, gives them their positions in safe
//! consumer order, and every five minutes with new events signs a checkpoint with
//! the audit key, which the database never sees.

/// Public checkpoint routes.
mod routes;
/// The sealer job.
mod sealer;
/// Focused tests for sealing, verification and pruning.
#[cfg(test)]
mod tests;
/// Chain verification and pruning.
mod verify;

pub(crate) use routes::AuditApplication;
pub(crate) use sealer::Sealer;

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use piquel_admin_api::{ChainBreak, ChainPoint, VerificationKeys};
use piquel_crypto::{CryptoError, Digest, NoteVerifier, NoteVerifiers};
use piquel_repository::{ChainLink, Database, DatabaseError, EventContent};
use serde::Serialize;
use thiserror::Error;

/// The verifier keys committed to the repository, one per line: each environment's
/// current audit key and those they replaced. A compromised server cannot change
/// them, since they are compiled into every build.
const COMMITTED_KEYS: &str = include_str!("../../../../docs/security/audit-key.pub");

/// Why sealing, signing, verifying or pruning failed.
#[derive(Debug, Error)]
pub enum AuditError {
    /// A database operation failed.
    #[error("audit chain database operation failed")]
    Database(#[from] DatabaseError),
    /// An event could not be canonicalized.
    #[error("could not canonicalize an event")]
    Canonical(#[source] serde_json::Error),
    /// A checkpoint could not be signed.
    #[error("could not sign the checkpoint")]
    Signing(#[source] CryptoError),
    /// A verifier key list is malformed.
    #[error("audit verifier keys must be one <name>+<hex key ID>+<base64 key> per line")]
    Keys(#[source] CryptoError),
    /// The file given with `--key` lists no key.
    #[error("the file given with --key lists no verifier key")]
    NoKeys,
    /// The cryptographic provider failed while checking a signature.
    #[error("could not check a checkpoint signature")]
    Verifying(#[source] CryptoError),
    /// The chain is broken at or before the position pruning would remove.
    #[error("the audit chain is broken at position {}: {}", .0.position, .0.problem)]
    Broken(ChainBreak),
    /// The chain was already pruned through this position or a later one.
    #[error("the audit chain is already pruned through position {anchor}")]
    AlreadyPruned {
        /// The current anchor's position.
        anchor: u64,
    },
    /// No checkpoint was signed at the position to prune through.
    #[error("no checkpoint was signed at position {0}; prune through a checkpoint's position")]
    NoCheckpoint(u64),
}

/// How the chain extends: each event's hash covers the hash before it and its
/// canonical form, `SHA-256(previous hash || SHA-256(JCS(canonical event)))`.
trait Chain: Sized {
    /// Where an unpruned chain starts: position 0 and 32 zero bytes.
    const GENESIS: Self;

    /// The link of `content`, sealed right after this one.
    fn extend(&self, content: &EventContent) -> Result<Self, AuditError>;

    /// This link as the admin API and the CLI show it.
    fn point(&self) -> ChainPoint;
}

/// The canonical event: an event's content and its position, serialized with
/// RFC 8785 (JCS) so the same row always hashes to the same bytes.
#[derive(Serialize)]
struct CanonicalEvent<'a> {
    /// The event's chain position.
    position: u64,
    /// Everything else the chain covers.
    #[serde(flatten)]
    content: &'a EventContent,
}

impl Chain for ChainLink {
    const GENESIS: Self = Self {
        position: 0,
        hash: [0; 32],
    };

    fn extend(&self, content: &EventContent) -> Result<Self, AuditError> {
        let position = self.position + 1;
        let canonical = serde_json_canonicalizer::to_vec(&CanonicalEvent { position, content })
            .map_err(AuditError::Canonical)?;
        let mut input = self.hash.to_vec();
        input.extend(Digest::sha256(&canonical).as_bytes());
        Ok(Self {
            position,
            hash: *Digest::sha256(&input).as_bytes(),
        })
    }

    fn point(&self) -> ChainPoint {
        ChainPoint {
            position: self.position,
            hash: STANDARD.encode(self.hash),
        }
    }
}

/// The text a checkpoint note signs, in the C2SP signed-note format:
///
/// ```text
/// auth.piquel.fr/audit
/// position 48211
/// head 3q2+7w…
/// time 2026-10-13T12:00:00Z
/// ```
#[derive(Debug, PartialEq, Eq)]
struct CheckpointText {
    /// The log's name, `<auth host>/audit`, which is also the key's.
    origin: String,
    /// The head it signs.
    head: ChainLink,
    /// When it was signed, to the second.
    time: DateTime<Utc>,
}

impl CheckpointText {
    /// Writes the text, ending with a newline.
    fn render(&self) -> String {
        format!(
            "{}\nposition {}\nhead {}\ntime {}\n",
            self.origin,
            self.head.position,
            STANDARD.encode(self.head.hash),
            self.time.to_rfc3339_opts(SecondsFormat::Secs, true)
        )
    }

    /// Reads text that [`Self::render`] wrote, or `None` if it is malformed.
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.strip_suffix('\n')?.split('\n');
        let origin = lines.next()?.to_owned();
        let position = lines.next()?.strip_prefix("position ")?.parse().ok()?;
        let hash = STANDARD
            .decode(lines.next()?.strip_prefix("head ")?)
            .ok()?
            .try_into()
            .ok()?;
        let time = DateTime::parse_from_rfc3339(lines.next()?.strip_prefix("time ")?)
            .ok()?
            .to_utc();
        let parsed = Self {
            origin,
            head: ChainLink { position, hash },
            time,
        };
        // Rendering again rejects extra lines and any other spelling of the values.
        (lines.next().is_none() && parsed.render() == text).then_some(parsed)
    }
}

/// The keys checkpoint signatures are verified against, and where they came from.
pub struct AuditKeys {
    /// The verifier keys.
    verifiers: NoteVerifiers,
    /// Where they came from, as the verification reports it.
    source: VerificationKeys,
}

impl AuditKeys {
    /// The keys committed to the repository, for `audit verify` and `audit prune`.
    ///
    /// # Errors
    /// Returns [`AuditError::Keys`] if the file is malformed.
    pub fn committed() -> Result<Self, AuditError> {
        Ok(Self {
            verifiers: NoteVerifiers::parse(COMMITTED_KEYS).map_err(AuditError::Keys)?,
            source: VerificationKeys::Committed,
        })
    }

    /// Keys the operator gave, one verifier key per line, e.g. a preview's.
    ///
    /// # Errors
    /// Returns [`AuditError::Keys`] if a line is malformed, or
    /// [`AuditError::NoKeys`] if none is given.
    pub fn given(lines: &str) -> Result<Self, AuditError> {
        let verifiers = NoteVerifiers::parse(lines).map_err(AuditError::Keys)?;
        if verifiers.is_empty() {
            return Err(AuditError::NoKeys);
        }
        Ok(Self {
            verifiers,
            source: VerificationKeys::Given,
        })
    }

    /// The committed keys and the server's own, for the admin API: a server that
    /// answers it could forge any answer, so it may as well use its key, and it
    /// reports whether that key is committed.
    pub(crate) fn server(own: &NoteVerifier) -> Result<Self, AuditError> {
        let mut verifiers = NoteVerifiers::parse(COMMITTED_KEYS).map_err(AuditError::Keys)?;
        let source = if verifiers.contains(own) {
            VerificationKeys::Committed
        } else {
            verifiers.insert(own.clone());
            VerificationKeys::Uncommitted
        };
        Ok(Self { verifiers, source })
    }
}

/// The audit chain of one database: verification and pruning. Sealing and
/// signing are the [`Sealer`] job's.
#[derive(Clone)]
pub struct AuditChain {
    /// Where the chain is stored.
    database: Database,
}

impl AuditChain {
    /// The chain stored in `database`.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}
