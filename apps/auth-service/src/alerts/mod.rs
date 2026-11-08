//! Alerts: conditions that need an administrator's attention, such as a broken
//! audit chain. Whatever finds a condition raises its alert while it holds, and
//! clears it once it no longer does, each change recorded as an event.

use piquel_common::{
    alerts::{Alert, AlertKind},
    events::{DomainEvent, EventContext},
};
use piquel_repository::{DatabaseError, DatabaseTransaction, StoredAlert};

/// Raises and clears alerts in a transaction, recording each change as caused
/// as its context says.
pub(crate) struct Alerts<'t, 'c> {
    /// The transaction the changes and their events are made in.
    tx: &'t mut DatabaseTransaction<'c>,
    /// Who found the condition.
    context: &'t EventContext,
}

impl<'t, 'c> Alerts<'t, 'c> {
    /// Changes alerts in `tx`, as `context`.
    pub(crate) const fn new(
        tx: &'t mut DatabaseTransaction<'c>,
        context: &'t EventContext,
    ) -> Self {
        Self { tx, context }
    }

    /// Says `alert` holds. When the current alert of its kind says the same, it
    /// was seen again, and stays acknowledged if it was. Otherwise that one clears
    /// and `alert` is raised.
    pub(crate) async fn raise(&mut self, alert: Alert) -> Result<(), DatabaseError> {
        match self.tx.alerts().current(alert.kind()).await? {
            Some(current) if current.alert.as_ref() == Some(&alert) => {
                return self.tx.alerts().seen(current.id).await;
            }
            Some(current) => self.cleared(current).await?,
            None => {}
        }
        let alert_id = self.tx.alerts().raise(&alert).await?;
        let raised = DomainEvent::AlertRaised { alert_id, alert };
        self.tx.record(self.context, None, raised).await
    }

    /// Says no alert of `kind` holds: its current one, if any, clears.
    pub(crate) async fn clear(&mut self, kind: AlertKind) -> Result<(), DatabaseError> {
        match self.tx.alerts().current(kind).await? {
            Some(current) => self.cleared(current).await,
            None => Ok(()),
        }
    }

    /// Clears `current`, whose condition no longer holds as it says.
    async fn cleared(&mut self, current: StoredAlert) -> Result<(), DatabaseError> {
        self.tx.alerts().clear(current.id).await?;
        // A release that cannot read an alert cannot record it either.
        let Some(alert) = current.alert else {
            return Ok(());
        };
        let cleared = DomainEvent::AlertCleared {
            alert_id: current.id,
            alert,
        };
        self.tx.record(self.context, None, cleared).await
    }
}

#[cfg(test)]
mod tests;
