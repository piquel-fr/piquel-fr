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
use serde::{Deserialize, Serialize, de::value::MapDeserializer};
use serde_json::{Map, Value};
use sqlx::types::Json;
use std::{fmt::Display, iter, net::IpAddr};

/// Payload version recorded with every event. Versions are per kind: a kind whose
/// payload changes shape gets a new version of its own, never a new value of this
/// constant for every kind, and reads keep accepting the old one. A newer version
/// was written by a newer release, so it reads as [`RecordedEvent::Unknown`].
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

/// Which events [`EventRepository::list`] returns. The default matches every event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventFilter {
    /// Only events concerning this account.
    pub subject: Option<UserId>,
    /// Only events of this kind, the serde tag of a [`DomainEvent`] variant, e.g.
    /// `session_revoked`.
    pub kind: Option<String>,
    /// Only events recorded before this one, to page through older events. With a
    /// `subject`, the cursor must be one of that account's events.
    pub before: Option<EventId>,
    /// Only this event.
    pub id: Option<EventId>,
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
    pub event: RecordedEvent,
    /// Where the request came from, until its personal data is deleted.
    pub origin: Personal<RequestOrigin>,
}

/// What a stored event says happened. A deploy keeps the previous release serving
/// while the next one starts, and a rollback runs it again, so a release reads
/// events newer releases wrote: kinds it does not know, or a known kind in a newer
/// payload version. Those read as [`Self::Unknown`] instead of failing, and each
/// reader decides what to do with them. Only reads produce one: `record` takes a
/// [`DomainEvent`], so this release never writes an unknown event.
///
/// Serializes as stored: `{"kind": …, "data": …}`, with the `version` of unknown events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum RecordedEvent {
    /// An event this release knows.
    Known(DomainEvent),
    /// An event a newer release wrote.
    Unknown {
        /// The serde tag of its [`DomainEvent`] variant in that release.
        kind: String,
        /// Its payload version.
        version: i16,
        /// Its data, with personal values merged back as for a known event.
        data: Value,
    },
}

impl RecordedEvent {
    /// The event, if this release knows it.
    #[must_use]
    pub const fn known(&self) -> Option<&DomainEvent> {
        match self {
            Self::Known(event) => Some(event),
            Self::Unknown { .. } => None,
        }
    }
}

/// How decoding `{"kind": …}` alone as a [`DomainEvent`] fails, which tells
/// whether this release knows the kind. Only serde's derive knows the variant
/// names, and it reports an unknown one through [`serde::de::Error::unknown_variant`].
#[derive(Debug, thiserror::Error)]
enum KindProbe {
    /// The kind is no variant of this release's [`DomainEvent`].
    #[error("unknown event kind")]
    Unknown,
    /// Anything else, such as the missing data of a known kind.
    #[error("{0}")]
    Other(String),
}

impl serde::de::Error for KindProbe {
    /// Keeps the message, for the error to be complete.
    fn custom<T: Display>(message: T) -> Self {
        Self::Other(message.to_string())
    }

    /// Marks the kind as unknown.
    fn unknown_variant(_: &str, _: &'static [&'static str]) -> Self {
        Self::Unknown
    }
}

impl KindProbe {
    /// Whether `kind` is the serde tag of a [`DomainEvent`] variant of this release.
    fn knows(kind: &str) -> bool {
        let tag = MapDeserializer::<_, Self>::new(iter::once(("kind", kind)));
        !matches!(DomainEvent::deserialize(tag), Err(Self::Unknown))
    }
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
    /// The payload version it was written in.
    version: i16,
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

    /// Restores the event's personal values, if they are still stored, and decodes
    /// it. A kind or version this release does not know reads as
    /// [`RecordedEvent::Unknown`]; a known one whose payload does not decode fails.
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
        let event = if row.version > EVENT_VERSION || !KindProbe::knows(&row.kind) {
            RecordedEvent::Unknown {
                kind: row.kind,
                version: row.version,
                data: payload,
            }
        } else {
            RecordedEvent::Known(
                serde_json::from_value(Value::Object(Map::from_iter([
                    ("kind".to_owned(), Value::String(row.kind)),
                    ("data".to_owned(), payload),
                ])))
                .map_err(|source| invalid("payload", source))?,
            )
        };
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
        let filter = EventFilter {
            subject: Some(user_id),
            ..EventFilter::default()
        };
        self.list(&filter, limit).await
    }

    /// Lists up to `limit` events matching `filter`, newest first. A `before` event
    /// that does not exist, or concerns another account than `subject`, matches nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored event does not decode.
    pub async fn list(
        &mut self,
        filter: &EventFilter,
        limit: u32,
    ) -> Result<Vec<StoredEvent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                EventRow,
                r#"SELECT
                    e.id AS "id: EventId", e.txid::text::bigint AS "txid!", e.sequence,
                    e.occurred_at, e.kind, e.version, e.payload, e.actor AS "actor: Json<Actor>",
                    e.subject_user_id AS "subject_user_id: UserId",
                    p.event_id IS NOT NULL AS "personal!", p.client_ip AS "client_ip?: IpAddr",
                    p.user_agent_family AS "user_agent_family?: UserAgentFamily",
                    p.details AS "details?"
                FROM domain_events e
                LEFT JOIN event_personal_data p ON p.event_id = e.id
                WHERE ($1::uuid IS NULL OR e.subject_user_id = $1)
                AND ($2::text IS NULL OR e.kind = $2)
                AND (
                    $3::uuid IS NULL
                    OR e.sequence < (
                        SELECT sequence FROM domain_events
                        WHERE id = $3
                        AND ($1::uuid IS NULL OR subject_user_id = $1)
                    )
                )
                AND ($5::uuid IS NULL OR e.id = $5)
                ORDER BY e.sequence DESC
                LIMIT $4"#,
                filter.subject.map(UserId::as_uuid),
                filter.kind.as_deref(),
                filter.before.map(EventId::as_uuid),
                i64::from(limit),
                filter.id.map(EventId::as_uuid),
            )
        )?
        .into_iter()
        .map(StoredEvent::try_from)
        .collect()
    }

    /// Lists the events concerning a client, newest first, for tests of client changes.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored event does not decode.
    #[cfg(feature = "test-support")]
    pub async fn history_for_client(
        &mut self,
        client_id: &ClientId,
        limit: u32,
    ) -> Result<Vec<StoredEvent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                EventRow,
                r#"SELECT
                    e.id AS "id: EventId", e.txid::text::bigint AS "txid!", e.sequence,
                    e.occurred_at, e.kind, e.version, e.payload, e.actor AS "actor: Json<Actor>",
                    e.subject_user_id AS "subject_user_id: UserId",
                    p.event_id IS NOT NULL AS "personal!", p.client_ip AS "client_ip?: IpAddr",
                    p.user_agent_family AS "user_agent_family?: UserAgentFamily",
                    p.details AS "details?"
                FROM domain_events e
                LEFT JOIN event_personal_data p ON p.event_id = e.id
                WHERE e.client_id = $1
                ORDER BY e.sequence DESC
                LIMIT $2"#,
                client_id.as_str(),
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(StoredEvent::try_from)
        .collect()
    }

    /// Writes an event about `subject` as another release would, with any `kind`,
    /// `version` and `payload` and no personal data, for tests of what this
    /// release reads back.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn insert_written_elsewhere(
        &mut self,
        subject: UserId,
        kind: &str,
        version: i16,
        payload: &Value,
    ) -> Result<EventId, DatabaseError> {
        let id = EventId::new();
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO domain_events (id, kind, version, payload, actor, subject_user_id)
                VALUES ($1, $2, $3, $4, $5, $6)",
                id.as_uuid(),
                kind,
                version,
                payload,
                Json(&Actor::Unrecorded) as _,
                subject.as_uuid(),
            )
        )?;
        Ok(id)
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
                    e.occurred_at, e.kind, e.version, e.payload, e.actor AS "actor: Json<Actor>",
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
