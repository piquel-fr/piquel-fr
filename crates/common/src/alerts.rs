//! What needs an administrator's attention: a condition auth found, such as a
//! broken audit chain, which stays an alert while it holds. Unlike a
//! notification, an alert concerns no account: it is the administrators' to
//! acknowledge, and clears once its condition no longer holds.

use crate::admin::{ChainBreak, ChainProblem};
use serde::{Deserialize, Serialize};

crate::str_enum! {
    /// The condition an [`Alert`] is about: at most one alert of each kind holds
    /// at a time.
    pub enum AlertKind {
        /// See [`Alert::AuditChainBroken`].
        AuditChainBroken = "audit_chain_broken",
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
}

impl Alert {
    /// The condition it is about.
    #[must_use]
    pub const fn kind(&self) -> AlertKind {
        match self {
            Self::AuditChainBroken(_) => AlertKind::AuditChainBroken,
        }
    }

    /// Its payload version inside a recorded event. A new kind, or a new
    /// [`ChainProblem`], is one older releases cannot decode, so it fails to
    /// compile here until it is given the next version.
    #[must_use]
    pub const fn version(&self) -> i16 {
        match self {
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
        }
    }
}
