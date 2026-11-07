//! Verifies the chain on a schedule, so the dashboard's Audit tab shows a recent
//! verification without an operator asking for one.

use super::{AuditChain, AuditError, AuditKeys, AuditVerification};
use crate::jobs::{ExclusiveJob, Shutdown};
use chrono::{TimeDelta, Utc};
use piquel_common::events::{Actor, EventContext, JobName, RequestOrigin};
use piquel_repository::{ExclusiveConnection, LockKey};
use std::time::Duration;

/// Verifies the whole chain, on one replica at a time, once the newest recorded
/// verification, whoever made it, is [`Self::VERIFY_EVERY`] old, and records
/// what it found as [`JobName::AuditVerification`].
pub(crate) struct Verifier {
    /// The keys it verifies with, the dashboard's (see [`AuditKeys::for_server`]).
    keys: AuditKeys,
}

impl Verifier {
    /// How old the newest recorded verification may get.
    const VERIFY_EVERY: TimeDelta = TimeDelta::hours(6);

    /// A verifier checking checkpoints against `keys`.
    pub(crate) const fn new(keys: AuditKeys) -> Self {
        Self { keys }
    }

    /// Verifies and records the chain, unless a verification was recorded in the
    /// last [`Self::VERIFY_EVERY`]. Returns what it found, if it verified.
    pub(super) async fn pass(
        &self,
        connection: &mut ExclusiveConnection,
    ) -> Result<Option<AuditVerification>, AuditError> {
        let newest = connection.events().newest_audit_verification().await?;
        if newest.is_some_and(|newest| Utc::now() - newest.occurred_at < Self::VERIFY_EVERY) {
            return Ok(None);
        }
        let verification = AuditChain::verify_in(connection.begin().await?, &self.keys).await?;
        let context = EventContext {
            actor: Actor::System {
                job: JobName::AuditVerification,
            },
            origin: RequestOrigin::default(),
            reason: None,
        };
        AuditChain::record(connection.begin().await?, &context, &verification).await?;
        Ok(Some(verification))
    }
}

impl ExclusiveJob for Verifier {
    const NAME: &'static str = "audit-verifier";
    const LOCK: LockKey = LockKey::AuditVerification;
    const EVERY: Duration = Duration::from_mins(10);
    type Error = AuditError;

    /// One verification reads one snapshot, so shutdown cancels it rather than
    /// stopping it early.
    async fn run(
        &self,
        connection: &mut ExclusiveConnection,
        _: &Shutdown,
    ) -> Result<(), AuditError> {
        self.pass(connection).await.map(drop)
    }
}
