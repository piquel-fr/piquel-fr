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
/// Chain verification, and the checks before pruning.
mod verify;

pub(crate) use piquel_common::admin::{
    AuditCheckpoint, AuditPage, AuditVerification, ChainBreak, ChainPoint, ChainProblem, Pruning,
    VerificationKeys,
};
pub(crate) use routes::AuditApplication;
pub(crate) use sealer::Sealer;

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use piquel_common::config::Origin;
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
    /// No committed key has this environment's name, `<auth host>/audit`.
    #[error(
        "no audit key named {0} is committed in docs/security/audit-key.pub; pass the \
         environment's verifier key, as `keys audit` prints it, with --key"
    )]
    NoCommittedKey(String),
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

    /// This link as verification reports it.
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
    /// The keys committed to the repository for the environment at `origin`, named
    /// `<host>/audit`, for `audit verify` and `audit prune`. Another environment's
    /// key, such as staging's, cannot vouch for this one's checkpoints.
    ///
    /// # Errors
    /// Returns [`AuditError::Keys`] if the file is malformed, or
    /// [`AuditError::NoCommittedKey`] if no key has this environment's name.
    pub fn committed(origin: &Origin) -> Result<Self, AuditError> {
        let name = Self::name(origin);
        let verifiers = NoteVerifiers::parse(COMMITTED_KEYS)
            .map_err(AuditError::Keys)?
            .named(&name);
        if verifiers.is_empty() {
            return Err(AuditError::NoCommittedKey(name));
        }
        Ok(Self {
            verifiers,
            source: VerificationKeys::Committed,
        })
    }

    /// The keys the dashboard verifies with: the environment's committed keys, or,
    /// when none is committed for it, as on a preview, the server's `own` key, which
    /// the verification then reports as uncommitted.
    ///
    /// # Errors
    /// Returns [`AuditError::Keys`] if the committed file is malformed.
    pub(crate) fn for_server(origin: &Origin, own: &NoteVerifier) -> Result<Self, AuditError> {
        match Self::committed(origin) {
            Err(AuditError::NoCommittedKey(_)) => Ok(Self {
                verifiers: own.clone().into(),
                source: VerificationKeys::Uncommitted,
            }),
            keys => keys,
        }
    }

    /// The name of the audit key of the environment at `origin`, which is also its
    /// checkpoints' origin line.
    pub(crate) fn name(origin: &Origin) -> String {
        format!("{}/audit", origin.host())
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
}

/// The audit chain of one database: verification, and the checks before
/// pruning, which [`AdminService`](crate::AdminService) runs for an operator.
/// Sealing and signing are the [`Sealer`] job's.
pub(crate) struct AuditChain {
    /// Where the chain is stored.
    database: Database,
}

impl AuditChain {
    /// The chain stored in `database`.
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}
