//! What needs an administrator's attention: a condition auth found, such as a
//! broken audit chain, which stays an alert while it holds. Unlike a
//! notification, an alert concerns no account: it is the administrators' to
//! acknowledge, and clears once its condition no longer holds.

use crate::{
    AlertId, Handle,
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
        /// See [`Alert::CleanupBehind`].
        CleanupBehind = "cleanup_behind",
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
    /// The newest verification of the audit chain, other than one with keys given
    /// with `--key`, found it broken.
    AuditChainBroken(ChainBreak),
    /// The sealer refuses to sign a checkpoint: the events sealed since the
    /// latest one no longer match their hashes.
    CheckpointRefused(ChainBreak),
    /// Accounts whose deletion grace period ended keep failing to be purged.
    /// How many is left out, so a count that changes raises nothing new: the
    /// `piquel.auth.account_purge.failing` gauge counts them.
    PurgesFailing {},
    /// Cleanup passes keep running out of time with expired state, personal
    /// data past retention or finished deliveries left to delete.
    CleanupBehind {},
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
            Self::CleanupBehind {} => AlertKind::CleanupBehind,
        }
    }

    /// Its payload version inside a recorded event. A new kind, or a new
    /// [`ChainProblem`], is one older releases cannot decode, so it fails to
    /// compile here until it is given the next version: [`Self::CheckpointRefused`]
    /// came in the second, [`Self::PurgesFailing`] in the third and
    /// [`Self::CleanupBehind`] in the fourth.
    #[must_use]
    pub const fn version(&self) -> i16 {
        match self {
            Self::CheckpointRefused(_) => 2,
            Self::PurgesFailing {} => 3,
            Self::CleanupBehind {} => 4,
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
            Self::CleanupBehind {} => "Cleanup is falling behind",
        }
    }

    /// What it says, below its subject.
    #[must_use]
    pub fn body(&self) -> String {
        match self {
            Self::AuditChainBroken(broken) => format!(
                "A verification found the chain broken at position {}: {}. The change \
                 may also be a removal or insertion just before it. Find out what changed \
                 before relying on the history: the dashboard's Audit tab shows the chain, \
                 and the audit history documentation says what each problem means. It \
                 clears once a verification, other than one with keys given with --key, \
                 finds the chain intact.",
                broken.position, broken.problem
            ),
            Self::CheckpointRefused(broken) => format!(
                "The sealer refuses to sign a checkpoint: at position {}, {}. Events sealed \
                 since the latest checkpoint were changed or deleted, so nothing newer is \
                 signed until it is fixed. Find out what changed: the dashboard's Audit tab \
                 shows the chain, and the audit history documentation says what each \
                 problem means. It clears once the sealer signs a checkpoint again.",
                broken.position, broken.problem
            ),
            Self::PurgesFailing {} => "Accounts whose deletion grace period ended failed to be \
                purged at least 3 times in a row, so their data is kept past its deletion. \
                Each is retried with a growing delay. The account-purge job's logs name \
                each account that failed (could not purge account), and its dashboard page \
                and auth-service user show give its failures and last error. It clears \
                once no account has failed 3 times in a row."
                .to_owned(),
            Self::CleanupBehind {} => "Cleanup passes keep running out of time with expired \
                sign-in state, personal data past its retention, or finished deliveries left \
                to delete, so personal data is kept longer than it should be. The \
                piquel.auth.cleanup metrics show how much each pass deletes. It clears once \
                a pass deletes everything due."
                .to_owned(),
        }
    }
}

crate::str_enum! {
    /// Where the handling of an alert stands, as the update an administrator
    /// posted says.
    pub enum AlertStatus {
        /// Someone is finding out what happened.
        Investigating = "investigating",
        /// Someone is fixing it.
        Fixing = "fixing",
        /// It was fixed, and someone watches for the alert to clear.
        Monitoring = "monitoring",
    }
}

/// Who posted an update on an alert.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertAuthor {
    /// An administrator, on the dashboard.
    Administrator {
        /// Their handle, unless their account was purged since.
        handle: Option<Handle>,
    },
    /// An operator at the terminal.
    Operator {
        /// The operating system user.
        os_user: String,
        /// The machine's host name.
        host: String,
    },
}

/// An update an administrator posted on an alert: where its handling stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AlertUpdate {
    /// Where its handling stands.
    pub status: AlertStatus,
    /// What they added, if anything.
    pub note: Option<String>,
    /// Who posted it.
    pub author: AlertAuthor,
    /// When.
    pub posted_at: DateTime<Utc>,
}

/// An alert, with the updates administrators posted on it, oldest first, as the
/// dashboard and the CLI show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AlertDetail {
    /// The alert.
    #[serde(flatten)]
    pub alert: StoredAlert,
    /// Its updates, oldest first.
    pub updates: Vec<AlertUpdate>,
}

/// An alert as stored. At most one alert of each kind is current, the one not
/// cleared yet.
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
    /// When an administrator posted its first update, which acknowledges it.
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// When its condition stopped holding, or changed, if it did.
    pub cleared_at: Option<DateTime<Utc>>,
}

/// Which alerts a list shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertsShown {
    /// The current ones, newest first.
    Current,
    /// Those that cleared, the most recently cleared first.
    Previous,
}

/// Where an alert stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertState {
    /// It needs an administrator's attention: nobody posted an update yet.
    Open,
    /// An administrator posted an update, and its condition still holds.
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
