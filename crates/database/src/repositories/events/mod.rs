//! Storage for typed domain events, and the personal data kept apart from them.
//!
//! An event row holds only non-identifying content, so it can be kept and later
//! hashed (#31). Personal data, the client IP, user agent family and every
//! [`Personal`] payload value, lives in a separate row that retention and account
//! purges delete; reads then return [`Personal::Erased`] in its place.

use super::{EventRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{
    ClientId, EventId, Personal, SessionId, UserId,
    events::{Actor, DomainEvent, EventContext, RequestOrigin, UserAgentFamily},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::types::Json;
use std::net::IpAddr;

/// Payload version recorded with every event. A kind whose payload changes shape
/// gets a new version, and reads keep accepting the old one.
const EVENT_VERSION: i16 = 1;
/// Key under which a [`Personal`] value serializes; matches its serde rename.
const PERSONAL_KEY: &str = "$personal";
/// What a [`Personal`] value leaves in the stored payload; matches the serde
/// rename of [`Personal::Erased`].
const ERASED: &str = "$erased";

/// A consumer's position in the event stream: everything up to and including the
/// event it was read from. See [`EventRepository::read_after`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventCursor {
    /// The writing transaction's ID.
    txid: i64,
    /// The event's position in insertion order.
    sequence: i64,
}

/// A recorded event with its personal data merged back in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    /// Event identifier.
    pub id: EventId,
    /// Position to pass to [`EventRepository::acknowledge`] once handled.
    pub cursor: EventCursor,
    /// When it was recorded.
    pub occurred_at: DateTime<Utc>,
    /// Who caused it.
    pub actor: Actor,
    /// The account it concerns, if any. The account may no longer exist.
    pub subject: Option<UserId>,
    /// What happened.
    pub event: DomainEvent,
    /// Where the request came from, until its personal data is deleted.
    pub origin: Personal<RequestOrigin>,
}

/// An event joined with its personal data, as the read queries return it.
struct EventRow {
    /// Event identifier.
    id: EventId,
    /// The writing transaction's ID.
    txid: i64,
    /// Insertion order.
    sequence: i64,
    /// When it was recorded.
    occurred_at: DateTime<Utc>,
    /// The serde tag of the [`DomainEvent`] variant.
    kind: String,
    /// The variant's data, with `"$erased"` where personal values were.
    payload: Value,
    /// Who caused it.
    actor: Json<Actor>,
    /// The account it concerns.
    subject_user_id: Option<UserId>,
    /// Whether the personal data row still exists.
    personal: bool,
    /// The client's IP address.
    client_ip: Option<IpAddr>,
    /// The client's browser family.
    user_agent_family: Option<UserAgentFamily>,
    /// Personal payload values by JSON pointer.
    details: Option<Value>,
}

impl TryFrom<EventRow> for StoredEvent {
    type Error = DatabaseError;

    /// Restores the event's personal values, if they are still stored, and decodes it.
    fn try_from(row: EventRow) -> Result<Self, DatabaseError> {
        let invalid = |column: &str, source: serde_json::Error| DatabaseError::InvalidStoredData {
            column: column.into(),
            source: source.into(),
        };
        let mut payload = row.payload;
        let origin = if row.personal {
            serde_json::from_value::<PersonalDetails>(row.details.unwrap_or_default())
                .map_err(|source| invalid("details", source))?
                .restore(&mut payload);
            Personal::Value(RequestOrigin {
                client_ip: row.client_ip,
                user_agent_family: row.user_agent_family,
            })
        } else {
            Personal::Erased
        };
        let event = serde_json::from_value(Value::Object(Map::from_iter([
            ("kind".to_owned(), Value::String(row.kind)),
            ("data".to_owned(), payload),
        ])))
        .map_err(|source| invalid("payload", source))?;
        Ok(Self {
            id: row.id,
            cursor: EventCursor {
                txid: row.txid,
                sequence: row.sequence,
            },
            occurred_at: row.occurred_at,
            actor: row.actor.0,
            subject: row.subject_user_id,
            event,
            origin,
        })
    }
}

/// A serialized [`DomainEvent`], split into its kind and data.
#[derive(Deserialize)]
struct TaggedEvent {
    /// The variant's serde tag.
    kind: String,
    /// The variant's data.
    data: Value,
}

/// The [`Personal`] values of one payload, keyed by their JSON pointer, as stored
/// in `event_personal_data.details`.
#[derive(Default, Serialize, Deserialize)]
struct PersonalDetails(Map<String, Value>);

impl PersonalDetails {
    /// Moves every `{"$personal": value}` out of `payload`, leaving `"$erased"`.
    fn extract(payload: &mut Value) -> Self {
        let mut details = Self::default();
        details.walk(payload, String::new());
        details
    }

    /// Extracts the personal values under `value`, found at `pointer`.
    fn walk(&mut self, value: &mut Value, pointer: String) {
        match value {
            Value::Object(object) if object.len() == 1 && object.contains_key(PERSONAL_KEY) => {
                let personal = object.remove(PERSONAL_KEY).unwrap_or_default();
                self.0.insert(pointer, personal);
                *value = Value::String(ERASED.to_owned());
            }
            Value::Object(object) => {
                for (key, child) in object {
                    // RFC 6901 escaping.
                    let key = key.replace('~', "~0").replace('/', "~1");
                    self.walk(child, format!("{pointer}/{key}"));
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    self.walk(child, format!("{pointer}/{index}"));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    /// Puts each stored value back where [`Self::extract`] found it.
    fn restore(self, payload: &mut Value) {
        for (pointer, personal) in self.0 {
            if let Some(slot) = payload.pointer_mut(&pointer) {
                *slot = Value::Object(Map::from_iter([(PERSONAL_KEY.to_owned(), personal)]));
            }
        }
    }
}

impl EventRepository<'_> {
    /// Writes an event and its personal data, and returns the event's ID. Only
    /// [`DatabaseTransaction::record`](crate::DatabaseTransaction::record) calls it,
    /// so both rows always commit or roll back with the change they describe.
    pub(crate) async fn insert(
        &mut self,
        context: &EventContext,
        subject: Option<UserId>,
        event: &DomainEvent,
    ) -> Result<EventId, DatabaseError> {
        let serialization = |error| DatabaseError::Operation(Box::new(error));
        let TaggedEvent { kind, mut data } =
            serde_json::from_value(serde_json::to_value(event).map_err(serialization)?)
                .map_err(serialization)?;
        let details = PersonalDetails::extract(&mut data);
        let id = EventId::new();
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO domain_events (
                    id, kind, version, payload, actor, subject_user_id, client_id, session_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                id.as_uuid(),
                kind,
                EVENT_VERSION,
                data,
                Json(&context.actor) as _,
                subject.map(UserId::as_uuid),
                event
                    .client_id()
                    .or(context.actor.client_id())
                    .map(ClientId::as_str),
                event
                    .session_id()
                    .or(context.actor.session_id())
                    .map(SessionId::as_uuid),
            )
        )?;
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO event_personal_data (event_id, client_ip, user_agent_family, details)
                VALUES ($1, $2, $3, $4)",
                id.as_uuid(),
                context.origin.client_ip as _,
                context
                    .origin
                    .user_agent_family
                    .map(UserAgentFamily::as_str),
                Json(&details) as _,
            )
        )?;
        Ok(id)
    }

    /// Lists the events concerning an account, newest first, for its security history.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored event does not decode.
    pub async fn history_for_user(
        &mut self,
        user_id: UserId,
        limit: u32,
    ) -> Result<Vec<StoredEvent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                EventRow,
                r#"SELECT
                    e.id AS "id: EventId", e.txid::text::bigint AS "txid!", e.sequence,
                    e.occurred_at, e.kind, e.payload, e.actor AS "actor: Json<Actor>",
                    e.subject_user_id AS "subject_user_id: UserId",
                    p.event_id IS NOT NULL AS "personal!", p.client_ip AS "client_ip?: IpAddr",
                    p.user_agent_family AS "user_agent_family?: UserAgentFamily",
                    p.details AS "details?"
                FROM domain_events e
                LEFT JOIN event_personal_data p ON p.event_id = e.id
                WHERE e.subject_user_id = $1
                ORDER BY e.sequence DESC
                LIMIT $2"#,
                user_id.as_uuid(),
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(StoredEvent::try_from)
        .collect()
    }

    /// Returns up to `limit` events after `consumer`'s acknowledged cursor, in a
    /// safe order, for consumers such as the sealer (#31) or alerts (#83).
    ///
    /// Sequence order alone is not safe: a transaction can take sequence 10 and
    /// commit after another took 11, so a reader that saw 11 would skip 10. Events
    /// are read in `(txid, sequence)` order instead, and only from transactions
    /// older than every transaction still running. Those have all finished, so no
    /// event can later appear before the cursor. The cost is that a long-running
    /// transaction holds back every consumer until it ends.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored event does not decode.
    pub async fn read_after(
        &mut self,
        consumer: &'static str,
        limit: u32,
    ) -> Result<Vec<StoredEvent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                EventRow,
                r#"SELECT
                    e.id AS "id: EventId", e.txid::text::bigint AS "txid!", e.sequence,
                    e.occurred_at, e.kind, e.payload, e.actor AS "actor: Json<Actor>",
                    e.subject_user_id AS "subject_user_id: UserId",
                    p.event_id IS NOT NULL AS "personal!", p.client_ip AS "client_ip?: IpAddr",
                    p.user_agent_family AS "user_agent_family?: UserAgentFamily",
                    p.details AS "details?"
                FROM domain_events e
                LEFT JOIN event_personal_data p ON p.event_id = e.id
                LEFT JOIN event_consumers c ON c.name = $1
                WHERE (e.txid, e.sequence) > (COALESCE(c.txid, '0'::xid8), COALESCE(c.sequence, 0))
                AND e.txid < pg_snapshot_xmin(pg_current_snapshot())
                ORDER BY e.txid, e.sequence
                LIMIT $2"#,
                consumer,
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(StoredEvent::try_from)
        .collect()
    }

    /// Moves `consumer`'s cursor to `cursor`, so [`Self::read_after`] continues after
    /// it. Run it in the transaction that applies the consumer's effects. A cursor
    /// never moves backwards.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn acknowledge(
        &mut self,
        consumer: &'static str,
        cursor: EventCursor,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO event_consumers (name, txid, sequence)
                VALUES ($1, $2::bigint::text::xid8, $3)
                ON CONFLICT (name) DO UPDATE
                SET txid = EXCLUDED.txid, sequence = EXCLUDED.sequence
                WHERE (event_consumers.txid, event_consumers.sequence)
                    < (EXCLUDED.txid, EXCLUDED.sequence)",
                consumer,
                cursor.txid,
                cursor.sequence,
            )
        )?;
        Ok(())
    }
}

/// Database tests for recording, personal data, the consumer cursor and the migration.
#[cfg(test)]
mod tests;
