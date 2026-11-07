//! The event log, the audit chain that signs it, and the outbound deliveries
//! events cause.

use super::AdminService;
use crate::{
    AuditKeys,
    admin::{AdminError, Operator},
    audit::{AuditChain, AuditPage, AuditVerification},
};
use piquel_common::{
    DeliveryId,
    admin::{Event, EventPage, EventSearch, Paging},
    events::DomainEvent,
};
use piquel_repository::{DeliveryStatus, DeliverySummary, EventFilter};

/// Events per page.
const EVENT_PAGE_SIZE: u16 = 50;

impl AdminService {
    /// Returns the page of the events matching `search`, newest first.
    pub(crate) async fn events(
        &self,
        operator: &Operator,
        search: EventSearch,
    ) -> Result<EventPage, AdminError> {
        operator.authorize_read(&self.database).await?;
        let viewed = DomainEvent::AccountViewed {}.kind();
        let mut filter = EventFilter {
            subject: search.user,
            except_kind: (!search.views && search.kind.is_none()).then(|| viewed.to_owned()),
            kind: search.kind,
            ..EventFilter::default()
        };
        let mut events = self.database.events();
        let total = events.count(&filter).await?;
        let paging = Paging::new(search.page, total, u32::from(EVENT_PAGE_SIZE));
        filter.offset = u32::try_from(paging.offset()).unwrap_or(u32::MAX);
        let stored = events.list(&filter, u32::from(EVENT_PAGE_SIZE)).await?;
        let events = stored
            .into_iter()
            .map(|stored| {
                Ok(Event {
                    id: stored.id,
                    occurred_at: stored.occurred_at,
                    actor: serde_json::to_value(stored.actor)?,
                    subject: stored.subject,
                    trace_id: stored.trace_id,
                    event: serde_json::to_value(stored.event)?,
                })
            })
            .collect::<Result<_, serde_json::Error>>()?;
        Ok(EventPage { events, paging })
    }

    /// Recomputes the audit chain and checks every checkpoint against `keys`, and
    /// records what it found, which the dashboard's audit page shows. A broken
    /// chain is a result, naming where it breaks.
    pub(crate) async fn verify_audit_chain(
        &self,
        operator: &Operator,
        keys: &AuditKeys,
    ) -> Result<AuditVerification, AdminError> {
        operator.authorize_read(&self.database).await?;
        let verification = AuditChain::new(self.database.clone()).verify(keys).await?;
        let tx = self.database.begin().await?;
        AuditChain::record(tx, &operator.context(), &verification).await?;
        Ok(verification)
    }

    /// The chain as stored, the newest verification [`Self::verify_audit_chain`]
    /// recorded, and up to 100 checkpoints after `after`, or after the anchor, with
    /// whether the chain may be pruned through each, by the rules
    /// [`Self::prune_audit_chain`] applies to that verification. Verifies nothing.
    pub(crate) async fn audit_page(
        &self,
        operator: &Operator,
        after: Option<u64>,
    ) -> Result<AuditPage, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(AuditChain::new(self.database.clone()).page(after).await?)
    }

    /// Deletes every event through the checkpoint at `through`, which becomes the
    /// anchor the remaining chain extends, once the chain verifies against `keys`
    /// through it, and returns how many events it deleted. Checkpoints are kept, so
    /// the pruned history stays signed. Auth's own role may not delete events, so
    /// this needs a connection as the schema owner.
    pub(crate) async fn prune_audit_chain(
        &self,
        operator: &Operator,
        keys: &AuditKeys,
        through: u64,
    ) -> Result<u64, AdminError> {
        operator.authorize_read(&self.database).await?;
        AuditChain::new(self.database.clone())
            .check_prunable(keys, through)
            .await?;
        let mut tx = self.database.begin().await?;
        let deleted = tx.prune_audit_chain(through).await?;
        let pruned = DomainEvent::AuditHistoryPruned { through, deleted };
        Self::finish(tx, operator, None, vec![pruned]).await?;
        Ok(deleted)
    }

    /// Lists outbound deliveries, newest first, with `status` and on `channel` when
    /// given, at most `limit`.
    pub(crate) async fn list_deliveries(
        &self,
        operator: &Operator,
        status: Option<DeliveryStatus>,
        channel: Option<&str>,
        limit: u32,
    ) -> Result<Vec<DeliverySummary>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self
            .database
            .deliveries()
            .list(status, channel, limit)
            .await?)
    }

    /// Attempts a failed delivery, or a cancelled unordered one, again now.
    pub(crate) async fn retry_delivery(
        &self,
        operator: &Operator,
        id: DeliveryId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        tx.deliveries()
            .retry(id)
            .await
            .map_err(AdminError::delivery(id, "failed or cancelled unordered"))?;
        let retried = DomainEvent::DeliveryRetried { delivery_id: id };
        Self::finish(tx, operator, None, vec![retried]).await
    }

    /// Cancels a pending or failed delivery, which unblocks the deliveries ordered
    /// after it.
    pub(crate) async fn cancel_delivery(
        &self,
        operator: &Operator,
        id: DeliveryId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        tx.deliveries()
            .cancel(id)
            .await
            .map_err(AdminError::delivery(id, "pending or failed"))?;
        let cancelled = DomainEvent::DeliveryCancelled { delivery_id: id };
        Self::finish(tx, operator, None, vec![cancelled]).await
    }
}
