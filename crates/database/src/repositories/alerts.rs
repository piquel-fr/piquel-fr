//! The alerts administrators are shown. Auth raises one while its condition
//! holds and clears it once it no longer does; at most one alert of each kind is
//! current, the one not cleared yet.

use super::{AlertRepository, KindProbe, RepositoryExecutor};
use crate::{DatabaseError, LockKey};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sourceorigin_common::{
    AlertId, EventId, Handle,
    alerts::{Alert, AlertAuthor, AlertKind, AlertStatus, AlertUpdate, AlertsShown, StoredAlert},
    events::{Actor, DomainEvent},
};
use sqlx::types::{Json, Uuid};

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

/// An update as the queries return it, before its author decodes.
struct UpdateRow {
    /// The alert it was posted on.
    alert_id: AlertId,
    /// Where the alert's handling stands.
    status: AlertStatus,
    /// The note, until its event's personal data is erased.
    note: Option<String>,
    /// Who posted it, as an event's actor.
    author: Json<Actor>,
    /// The administrator's handle, unless their account was purged.
    handle: Option<Handle>,
    /// When.
    posted_at: DateTime<Utc>,
}

impl UpdateRow {
    /// The update, with its alert.
    fn decode(self) -> Result<(AlertId, AlertUpdate), DatabaseError> {
        let author = match self.author.0 {
            Actor::Admin { .. } => AlertAuthor::Administrator {
                handle: self.handle,
            },
            Actor::Cli { os_user, host } => AlertAuthor::Operator { os_user, host },
            _ => {
                return Err(DatabaseError::InvalidStoredData {
                    column: "author".into(),
                    source: "not an administrator or operator".into(),
                });
            }
        };
        let update = AlertUpdate {
            status: self.status,
            note: self.note,
            author,
            posted_at: self.posted_at,
        };
        Ok((self.alert_id, update))
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

    /// Acknowledges alert `id`, if it is current and not yet acknowledged, and
    /// returns it while it is current. It stays locked until the transaction
    /// ends, so updates posted on it are written in turn.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or its payload does not decode.
    pub async fn acknowledge(&mut self, id: AlertId) -> Result<Option<StoredAlert>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                AlertRow,
                r#"UPDATE alerts SET acknowledged_at = coalesce(acknowledged_at, now())
                WHERE id = $1 AND cleared_at IS NULL
                RETURNING id AS "id: AlertId", payload, version, raised_at, seen_at,
                    acknowledged_at, cleared_at"#,
                id.as_uuid(),
            )
        )?
        .map(StoredAlert::try_from)
        .transpose()
    }

    /// Adds an update on alert `id`, which [`Self::acknowledge`] locked, saying
    /// where its handling stands, recorded as `event`, whose reason is its note.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn add_update(
        &mut self,
        id: AlertId,
        event: EventId,
        status: AlertStatus,
        author: &Actor,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO alert_updates (id, alert_id, event_id, status, author)
                VALUES ($1, $2, $3, $4, $5)",
                Uuid::now_v7(),
                id.as_uuid(),
                event.as_uuid(),
                status.as_str(),
                Json(author) as _,
            )
        )?;
        Ok(())
    }

    /// Up to `limit` alerts, as `shown` says: the current ones, newest first,
    /// or those that cleared, the most recently cleared first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a payload does not decode.
    pub async fn list(
        &mut self,
        shown: AlertsShown,
        limit: u32,
    ) -> Result<Vec<StoredAlert>, DatabaseError> {
        let rows = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                AlertRow,
                r#"SELECT id AS "id: AlertId", payload, version, raised_at, seen_at,
                    acknowledged_at, cleared_at
                FROM alerts
                WHERE (cleared_at IS NOT NULL) = $1
                ORDER BY coalesce(cleared_at, raised_at) DESC, id DESC
                LIMIT $2"#,
                shown == AlertsShown::Previous,
                i64::from(limit),
            )
        )?;
        rows.into_iter().map(StoredAlert::try_from).collect()
    }

    /// The updates posted on `alerts`, each with its alert, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row does not decode.
    pub async fn updates(
        &mut self,
        alerts: &[AlertId],
    ) -> Result<Vec<(AlertId, AlertUpdate)>, DatabaseError> {
        let ids: Vec<_> = alerts.iter().map(|id| id.as_uuid()).collect();
        let rows = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                UpdateRow,
                r#"SELECT u.alert_id AS "alert_id: AlertId", u.status AS "status: AlertStatus",
                    p.reason AS "note?", u.author AS "author: Json<Actor>",
                    h.handle AS "handle?: Handle", u.posted_at
                FROM alert_updates u
                LEFT JOIN event_personal_data p ON p.event_id = u.event_id
                LEFT JOIN handles h
                    ON h.user_id = (u.author ->> 'user_id')::uuid AND h.released_at IS NULL
                WHERE u.alert_id = ANY($1)
                ORDER BY u.posted_at, u.id"#,
                &ids,
            )
        )?;
        rows.into_iter().map(UpdateRow::decode).collect()
    }

    /// How many alerts are open: current, and with no update posted on them.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn open_count(&mut self) -> Result<u64, DatabaseError> {
        let count = run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "count!" FROM alerts
                WHERE cleared_at IS NULL AND acknowledged_at IS NULL"#,
            )
        )?;
        Ok(count.try_into().unwrap_or_default())
    }

    /// Stores alert `id` as written at payload `version`, as a newer release
    /// writing a payload this one does not would: a fixture for reading one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn set_version(&mut self, id: AlertId, version: i16) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE alerts SET version = $2 WHERE id = $1",
                id.as_uuid(),
                version,
            )
        )?;
        Ok(())
    }
}
