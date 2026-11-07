//! The alerts administrators are shown. Auth raises one while its condition
//! holds and clears it once it no longer does; at most one alert of each kind is
//! current, the one not cleared yet.

use super::{AlertRepository, KindProbe, RepositoryExecutor};
use crate::{DatabaseError, LockKey};
use chrono::{DateTime, Utc};
use piquel_common::{
    AlertId,
    alerts::{Alert, AlertKind},
    events::DomainEvent,
};
use serde_json::Value;

/// An alert, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// An alert as the queries return it, before its payload decodes.
struct AlertRow {
    /// Alert identifier.
    id: AlertId,
    /// The serialized [`Alert`].
    payload: Value,
    /// Its version.
    version: i16,
    /// When it was raised.
    raised_at: DateTime<Utc>,
    /// When its condition was last found holding.
    seen_at: DateTime<Utc>,
    /// When it was acknowledged.
    acknowledged_at: Option<DateTime<Utc>>,
    /// When it cleared.
    cleared_at: Option<DateTime<Utc>>,
}

impl TryFrom<AlertRow> for StoredAlert {
    type Error = DatabaseError;

    /// Decodes the payload, as events' are: a kind or version this release does
    /// not write reads as `None`, and a known one that does not decode fails.
    fn try_from(row: AlertRow) -> Result<Self, DatabaseError> {
        let known = row
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(KindProbe::knows::<Alert>);
        let alert = match known.then(|| serde_json::from_value::<Alert>(row.payload)) {
            Some(Ok(alert)) if alert.version() == row.version => Some(alert),
            Some(Err(source)) if row.version == DomainEvent::FIRST_VERSION => {
                return Err(DatabaseError::InvalidStoredData {
                    column: "payload".into(),
                    source: source.into(),
                });
            }
            Some(_) | None => None,
        };
        Ok(Self {
            id: row.id,
            alert,
            raised_at: row.raised_at,
            seen_at: row.seen_at,
            acknowledged_at: row.acknowledged_at,
            cleared_at: row.cleared_at,
        })
    }
}

impl AlertRepository<'_> {
    /// The current alert of `kind`, if any. Run in the transaction that changes
    /// alerts: it takes [`LockKey::Alerts`] until the transaction ends, so whatever
    /// raises or clears an alert next waits, and finds what this one left, even
    /// when none was current.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails or its payload does not decode.
    pub async fn current(&mut self, kind: AlertKind) -> Result<Option<StoredAlert>, DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!("SELECT pg_advisory_xact_lock($1)", LockKey::Alerts.id())
        )?;
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                AlertRow,
                r#"SELECT id AS "id: AlertId", payload, version, raised_at, seen_at,
                    acknowledged_at, cleared_at
                FROM alerts
                WHERE payload ->> 'kind' = $1 AND cleared_at IS NULL
                FOR UPDATE"#,
                kind.as_str(),
            )
        )?
        .map(StoredAlert::try_from)
        .transpose()
    }

    /// Raises `alert`, open and current from now. The current alert of its kind
    /// must be cleared first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if it cannot be serialized or written, such as
    /// while an alert of its kind is current.
    pub async fn raise(&mut self, alert: &Alert) -> Result<AlertId, DatabaseError> {
        let payload = serde_json::to_value(alert)
            .map_err(|error| DatabaseError::Operation(Box::new(error)))?;
        let id = AlertId::new();
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO alerts (id, payload, version) VALUES ($1, $2, $3)",
                id.as_uuid(),
                payload,
                alert.version(),
            )
        )?;
        Ok(id)
    }

    /// Notes that the condition of alert `id` still holds.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn seen(&mut self, id: AlertId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE alerts SET seen_at = now() WHERE id = $1",
                id.as_uuid()
            )
        )?;
        Ok(())
    }

    /// Clears alert `id`, whose condition no longer holds, or holds differently.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn clear(&mut self, id: AlertId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE alerts SET cleared_at = now() WHERE id = $1 AND cleared_at IS NULL",
                id.as_uuid()
            )
        )?;
        Ok(())
    }
}
