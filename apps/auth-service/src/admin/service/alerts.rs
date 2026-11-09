//! The alerts administrators are shown, and the updates they post on them.

use super::AdminService;
use crate::admin::{AdminError, Operator, Reason};
use piquel_common::{
    AlertId,
    alerts::{AlertDetail, AlertStatus, AlertUpdate, AlertsShown, StoredAlert},
    events::{DomainEvent, EventContext},
};
use piquel_repository::{DatabaseError, DatabaseTransaction};
use std::collections::HashMap;

/// How many alerts a list shows.
pub(crate) const ALERTS_SHOWN: u32 = 100;

impl AdminService {
    /// Up to [`ALERTS_SHOWN`] alerts, as `shown` says, each with its updates.
    pub(crate) async fn alerts(
        &self,
        operator: &Operator,
        shown: AlertsShown,
    ) -> Result<Vec<AlertDetail>, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut snapshot = self.database.begin_snapshot().await?;
        let alerts = snapshot.alerts().list(shown, ALERTS_SHOWN).await?;
        Ok(Self::with_updates(&mut snapshot, alerts).await?)
    }

    /// Posts an update on the current alert `id`, saying where its handling
    /// stands, with an optional `note`. The first acknowledges it: it stops
    /// counting as a warning, though it stays current while its condition holds.
    /// If the condition changes, or clears and comes back, a new alert is raised.
    pub(crate) async fn update_alert(
        &self,
        operator: &Operator,
        id: AlertId,
        status: AlertStatus,
        note: Option<Reason>,
    ) -> Result<(), AdminError> {
        // The note is the event's reason, so it is deleted with the event's
        // personal data.
        let context = EventContext {
            reason: note.map(Reason::into_inner),
            ..operator.context()
        };
        let mut tx = self.database.begin().await?;
        // Holding the operator's rights before the event's personal data locks
        // their account: a purge of them, which takes the rights first, waits
        // rather than deadlocks. `finish` checks them again before committing.
        operator.authorize(&mut tx).await?;
        // A kind this release cannot read, it cannot record either.
        let Some(StoredAlert {
            alert: Some(alert), ..
        }) = tx.alerts().acknowledge(id).await?
        else {
            return Err(AdminError::AlertNotFound);
        };
        let updated = DomainEvent::AlertUpdated {
            alert_id: id,
            alert,
            status,
        };
        let event = tx.record(&context, None, updated).await?;
        tx.alerts()
            .add_update(id, event, status, &context.actor)
            .await?;
        Self::finish(tx, operator, None, vec![]).await
    }

    /// `alerts`, each with the updates posted on it, oldest first, read in the
    /// `snapshot` that read them: an alert never shows an update its own row
    /// does not count.
    async fn with_updates(
        snapshot: &mut DatabaseTransaction<'_>,
        alerts: Vec<StoredAlert>,
    ) -> Result<Vec<AlertDetail>, DatabaseError> {
        let ids: Vec<_> = alerts.iter().map(|alert| alert.id).collect();
        let mut posted: HashMap<AlertId, Vec<AlertUpdate>> = HashMap::new();
        for (id, update) in snapshot.alerts().updates(&ids).await? {
            posted.entry(id).or_default().push(update);
        }
        Ok(alerts
            .into_iter()
            .map(|alert| AlertDetail {
                updates: posted.remove(&alert.id).unwrap_or_default(),
                alert,
            })
            .collect())
    }
}
