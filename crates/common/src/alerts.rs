//! What needs an administrator's attention: a condition auth found, such as a
//! broken audit chain, which stays an alert while it holds. Unlike a
//! notification, an alert concerns no account: it is the administrators' to
//! acknowledge, and clears once its condition no longer holds.

use crate::{
    AlertId,
    admin::{ChainBreak, ChainProblem},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

crate::str_enum! {
    /// The condition an [`Alert`] is about: at most one alert of each kind holds
    /// at a time.
    pub enum AlertKind {
        /// See [`Alert::AuditChainBroken`].
        AuditChainBroken = "audit_chain_broken",
        /// See [`Alert::CheckpointRefused`].
        CheckpointRefused = "checkpoint_refused",
        /// See [`Alert::PurgesFailing`].
        PurgesFailing = "purges_failing",
    }
}

/// A condition that needs an administrator's attention, stored as it
/// serializes, e.g. `{"kind": "audit_chain_broken", "position": 5, "problem":
/// "event_changed"}`. Never rename a released kind: a newer release's kinds are
/// skipped by older ones, not misread. Like an event's payload, it holds no
/// personal data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Alert {
    /// The newest verification of the audit chain found it broken.
    AuditChainBroken(ChainBreak),
    /// The sealer refuses to sign a checkpoint: the events sealed since the
    /// latest one no longer match their hashes.
    CheckpointRefused(ChainBreak),
    /// Accounts whose deletion grace period ended keep failing to be purged.
    /// How many is left out, so a count that changes raises nothing new: the
    /// `piquel.auth.account_purge.failing` gauge counts them.
    PurgesFailing {},
}

impl Alert {
    /// What an alert a newer release raised says, since this one cannot show it.
    pub const UNKNOWN: &'static str = "An alert this release cannot show";

    /// The condition it is about.
    #[must_use]
    pub const fn kind(&self) -> AlertKind {
        match self {
            Self::AuditChainBroken(_) => AlertKind::AuditChainBroken,
            Self::CheckpointRefused(_) => AlertKind::CheckpointRefused,
            Self::PurgesFailing {} => AlertKind::PurgesFailing,
        }
    }

    /// Its payload version inside a recorded event. A new kind, or a new
    /// [`ChainProblem`], is one older releases cannot decode, so it fails to
    /// compile here until it is given the next version: [`Self::CheckpointRefused`]
    /// came in the second, [`Self::PurgesFailing`] in the third.
    #[must_use]
    pub const fn version(&self) -> i16 {
        match self {
            Self::CheckpointRefused(_) => 2,
            Self::PurgesFailing {} => 3,
            Self::AuditChainBroken(ChainBreak { problem, .. }) => match problem {
                ChainProblem::MissingEvent
                | ChainProblem::EventBeforeAnchor
                | ChainProblem::EventChanged
                | ChainProblem::OutOfOrder
                | ChainProblem::CheckpointMismatch
                | ChainProblem::CheckpointSignature
                | ChainProblem::CheckpointMalformed
                | ChainProblem::CheckpointBeyondChain => crate::events::DomainEvent::FIRST_VERSION,
            },
        }
    }

    /// What it says, in one line.
    #[must_use]
    pub const fn subject(&self) -> &'static str {
        match self {
            Self::AuditChainBroken(_) => "The audit chain is broken",
            Self::CheckpointRefused(_) => "The audit chain's checkpoints stopped",
            Self::PurgesFailing {} => "Accounts keep failing to be purged",
        }
    }

    /// What it says, below its subject.
    #[must_use]
    pub fn body(&self) -> String {
        match self {
            Self::AuditChainBroken(broken) => format!(
                "A verification found the chain broken at position {}: {}. The change \
                 may also be a removal or insertion just before it. Find out what changed \
                 before relying on the history; docs/security/audit-history.md says what each \
                 problem means.",
                broken.position, broken.problem
            ),
            Self::CheckpointRefused(broken) => format!(
                "The sealer refuses to sign a checkpoint: at position {}, {}. Events sealed \
                 since the latest checkpoint were changed or deleted, so nothing newer is \
                 signed until it is fixed. Find out what changed; \
                 docs/security/audit-history.md says what each problem means.",
                broken.position, broken.problem
            ),
            Self::PurgesFailing {} => "Accounts whose deletion grace period ended failed to be \
                purged at least 3 times in a row, so their data is kept past its deletion. \
                Each is retried with a growing delay. Their last error is on their \
                account_deletions row, and the logs of the account-purge job say more."
                .to_owned(),
        }
    }
}

/// An alert as stored, which the dashboard and the CLI show. At most one alert
/// of each kind is current, the one not cleared yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoredAlert {
    /// Alert identifier.
    pub id: AlertId,
    /// What it says; `None` for a kind a newer release raised, which this one
    /// cannot show.
    pub alert: Option<Alert>,
    /// When it was raised.
    pub raised_at: DateTime<Utc>,
    /// When auth last found its condition holding.
    pub seen_at: DateTime<Utc>,
    /// When an administrator acknowledged it, if one did.
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// When its condition stopped holding, or changed, if it did.
    pub cleared_at: Option<DateTime<Utc>>,
}

/// Where an alert stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertState {
    /// It needs an administrator's attention.
    Open,
    /// An administrator acknowledged it, and its condition still holds.
    Acknowledged,
    /// Its condition no longer holds as it says.
    Cleared,
}

impl StoredAlert {
    /// Where it stands.
    #[must_use]
    pub const fn state(&self) -> AlertState {
        match (self.cleared_at, self.acknowledged_at) {
            (Some(_), _) => AlertState::Cleared,
            (None, Some(_)) => AlertState::Acknowledged,
            (None, None) => AlertState::Open,
        }
    }
}
