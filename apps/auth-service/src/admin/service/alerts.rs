//! The alerts administrators are shown, and acknowledging them.

use super::AdminService;
use crate::admin::{AdminError, Operator, Reason};
use piquel_common::{AlertId, alerts::StoredAlert, events::DomainEvent};

/// How many alerts the list shows.
pub(crate) const ALERTS_SHOWN: u32 = 100;

impl AdminService {
    /// The current alerts, then those that cleared, each newest first, at most
    /// 100.
    pub(crate) async fn list_alerts(
        &self,
        operator: &Operator,
    ) -> Result<Vec<StoredAlert>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self.database.alerts().list(ALERTS_SHOWN).await?)
    }

    /// Acknowledges the open alert `id`, with `reason`: it needs no attention
    /// while its condition holds as it says. If the condition changes, or clears
    /// and comes back, a new alert is raised.
    pub(crate) async fn acknowledge_alert(
        &self,
        operator: &Operator,
        id: AlertId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        // A kind this release cannot read, it cannot record either.
        let Some(StoredAlert {
            alert: Some(alert), ..
        }) = tx.alerts().acknowledge(id).await?
        else {
            return Err(AdminError::AlertNotFound);
        };
        let acknowledged = DomainEvent::AlertAcknowledged {
            alert_id: id,
            alert,
        };
        tx.record(&Self::context(operator, reason), None, acknowledged)
            .await?;
        Self::finish(tx, operator, None, vec![]).await
    }
}
