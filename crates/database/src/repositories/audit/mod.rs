//! Storage for the tamper-evident audit chain: the position and hash each sealed
//! event carries, signed checkpoints of the chain head, and the anchor that pruning
//! leaves. See `docs/security/audit-history.md`.
//!
//! The repository stores what auth computes. Auth hashes [`EventContent`], signs
//! checkpoints and verifies the chain; nothing here trusts a stored hash.

use super::{AuditRepository, Bytes32, RepositoryExecutor, Unsigned};
use crate::{DatabaseError, DatabaseTransaction};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

/// What the chain covers of one `domain_events` row: everything but its storage
/// order (`txid`, `sequence`) and its chain columns. Personal data lives in
/// `event_personal_data`, so it is not covered, and erasing it never breaks the chain.
///
/// Its serialization, with the event's position added, is the canonical event the
/// chain hashes. Changing a field's name or format breaks every existing chain.
/// Values stay as stored, with plain UUIDs, rather than decoded into typed IDs, so
/// a tampered row reads back and fails verification instead of failing to decode.
/// RFC 8785 writes every JSON number as a double, so a payload integer beyond
/// 2^53 would be covered only approximately; no event holds one.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EventContent {
    /// The event's ID.
    id: Uuid,
    /// The serde tag of its `DomainEvent` variant.
    kind: String,
    /// Its payload version.
    version: i16,
    /// When it was recorded, in UTC with microseconds, as `PostgreSQL` stores it.
    #[serde(serialize_with = "EventContent::timestamp")]
    occurred_at: DateTime<Utc>,
    /// Who caused it, as stored.
    actor: Value,
    /// The account it concerns.
    subject: Option<Uuid>,
    /// The client it concerns.
    client: Option<String>,
    /// The session it concerns.
    session: Option<Uuid>,
    /// The request's trace ID.
    trace_id: Option<String>,
    /// The payload as stored, with `"$erased"` where personal values were.
    payload: Value,
}

impl EventContent {
    /// Writes `occurred_at` as RFC 3339 in UTC with exactly six fractional digits,
    /// e.g. `2026-10-13T12:00:00.000000Z`, so it never depends on serde defaults.
    fn timestamp<S: Serializer>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Micros, true))
    }
}

/// A point on the chain: an event's position, from 1, and the chain hash through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainLink {
    /// The position.
    pub position: u64,
    /// `SHA-256(previous hash || SHA-256(canonical event))`.
    pub hash: [u8; 32],
}

/// A sealed event, or one to seal: its content and its link.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedEvent {
    /// Its position and chain hash.
    pub link: ChainLink,
    /// What the hash covers.
    pub content: EventContent,
}

/// A signed checkpoint of the chain head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The head's position.
    pub position: u64,
    /// The chain hash at that position.
    pub head: [u8; 32],
    /// When it was signed; also the note's `time`.
    pub created_at: DateTime<Utc>,
    /// The signed note.
    pub note: String,
}

/// A sealed event as chain reads return it.
struct SealedRow {
    /// Its position.
    position: Unsigned,
    /// Its chain hash.
    hash: Bytes32,
    /// Event identifier.
    id: Uuid,
    /// Variant tag.
    kind: String,
    /// Payload version.
    version: i16,
    /// When it was recorded.
    occurred_at: DateTime<Utc>,
    /// Who caused it.
    actor: Value,
    /// The account it concerns.
    subject: Option<Uuid>,
    /// The client it concerns.
    client: Option<String>,
    /// The session it concerns.
    session: Option<Uuid>,
    /// The request's trace ID.
    trace_id: Option<String>,
    /// The stored payload.
    payload: Value,
}

impl From<SealedRow> for SealedEvent {
    /// Splits the row into its link and content.
    fn from(row: SealedRow) -> Self {
        Self {
            link: ChainLink {
                position: row.position.into(),
                hash: row.hash.into(),
            },
            content: EventContent {
                id: row.id,
                kind: row.kind,
                version: row.version,
                occurred_at: row.occurred_at,
                actor: row.actor,
                subject: row.subject,
                client: row.client,
                session: row.session,
                trace_id: row.trace_id,
                payload: row.payload,
            },
        }
    }
}

/// A checkpoint as stored.
struct CheckpointRow {
    /// The head's position.
    position: Unsigned,
    /// The chain hash at that position.
    head: Bytes32,
    /// When it was signed.
    created_at: DateTime<Utc>,
    /// The signed note.
    note: String,
}

impl From<CheckpointRow> for Checkpoint {
    /// Unwraps the decoded columns.
    fn from(row: CheckpointRow) -> Self {
        Self {
            position: row.position.into(),
            head: row.head.into(),
            created_at: row.created_at,
            note: row.note,
        }
    }
}

impl AuditRepository<'_> {
    /// Returns up to `limit` unsealed events in the order to seal them: the safe
    /// consumer order of [`EventRepository::read_after`](crate::EventRepository::read_after),
    /// `(txid, sequence)`, and only events of transactions older than every running
    /// one. No event can later appear before one returned here, so positions never
    /// need to be reassigned. The rows stay locked until the transaction ends, so
    /// none changes between being hashed and being sealed.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn unsealed(&mut self, limit: u32) -> Result<Vec<EventContent>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                EventContent,
                r#"SELECT
                    id, kind, version, occurred_at, actor, subject_user_id AS subject,
                    client_id AS client, session_id AS session, trace_id, payload
                FROM domain_events
                WHERE chain_position IS NULL
                AND txid < pg_snapshot_xmin(pg_current_snapshot())
                ORDER BY txid, sequence
                LIMIT $1
                FOR UPDATE"#,
                i64::from(limit),
            )
        )
    }

    /// Counts the events not sealed yet.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn unsealed_count(&mut self) -> Result<u64, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "count!: Unsigned"
                FROM domain_events WHERE chain_position IS NULL"#
            )
        )
        .map(Into::into)
    }

    /// The chain head: the newest sealed event, or the anchor if every sealed event
    /// was pruned, or `None` before the first event is sealed.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn head(&mut self) -> Result<Option<ChainLink>, DatabaseError> {
        Ok(run!(
            self,
            fetch_optional,
            sqlx::query!(
                r#"SELECT position AS "position!: Unsigned", hash AS "hash!: Bytes32"
                FROM (
                    (SELECT chain_position AS position, chain_hash AS hash
                    FROM domain_events
                    WHERE chain_position IS NOT NULL
                    ORDER BY chain_position DESC
                    LIMIT 1)
                    UNION ALL
                    (SELECT c.position, c.head
                    FROM audit_anchor a JOIN audit_checkpoints c USING (position))
                ) head
                ORDER BY position DESC
                LIMIT 1"#
            )
        )?
        .map(|row| ChainLink {
            position: row.position.into(),
            hash: row.hash.into(),
        }))
    }

    /// Gives each event its position and chain hash.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if an event is missing or already sealed,
    /// which only a concurrent sealer could cause, or another [`DatabaseError`] if
    /// the query fails. Run it in a transaction, so nothing is sealed then.
    pub async fn seal(&mut self, events: &[SealedEvent]) -> Result<(), DatabaseError> {
        let ids: Vec<_> = events.iter().map(|event| event.content.id).collect();
        let positions = events
            .iter()
            .map(|event| Unsigned::bind(event.link.position))
            .collect::<Result<Vec<_>, _>>()?;
        let hashes: Vec<_> = events
            .iter()
            .map(|event| event.link.hash.to_vec())
            .collect();
        let sealed = run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE domain_events e
                SET chain_position = s.position, chain_hash = s.hash
                FROM UNNEST($1::uuid[], $2::bigint[], $3::bytea[]) AS s(id, position, hash)
                WHERE e.id = s.id AND e.chain_position IS NULL",
                &ids,
                &positions,
                &hashes,
            )
        )?;
        if sealed.rows_affected() == ids.len() as u64 {
            Ok(())
        } else {
            Err(DatabaseError::NotFound)
        }
    }

    /// Returns up to `limit` sealed events after position `after`, in chain order.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn chain(
        &mut self,
        after: u64,
        limit: u32,
    ) -> Result<Vec<SealedEvent>, DatabaseError> {
        Ok(run!(
            self,
            fetch_all,
            sqlx::query_as!(
                SealedRow,
                r#"SELECT
                    chain_position AS "position!: Unsigned", chain_hash AS "hash!: Bytes32",
                    id, kind, version, occurred_at, actor, subject_user_id AS subject,
                    client_id AS client, session_id AS session, trace_id, payload
                FROM domain_events
                WHERE chain_position > $1
                ORDER BY chain_position
                LIMIT $2"#,
                Unsigned::bind(after)?,
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(SealedEvent::from)
        .collect())
    }

    /// Stores a signed checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if one exists at its position, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn insert_checkpoint(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO audit_checkpoints (position, head, created_at, note)
                VALUES ($1, $2, $3, $4)",
                Unsigned::bind(checkpoint.position)?,
                &checkpoint.head[..],
                checkpoint.created_at,
                checkpoint.note,
            )
        )?;
        Ok(())
    }

    /// The checkpoint at the highest position, if any.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn latest_checkpoint(&mut self) -> Result<Option<Checkpoint>, DatabaseError> {
        Ok(run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                CheckpointRow,
                r#"SELECT position AS "position: Unsigned", head AS "head: Bytes32", created_at, note
                FROM audit_checkpoints
                ORDER BY position DESC
                LIMIT 1"#
            )
        )?
        .map(Checkpoint::from))
    }

    /// Returns up to `limit` checkpoints after position `after`, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn checkpoints(
        &mut self,
        after: u64,
        limit: u32,
    ) -> Result<Vec<Checkpoint>, DatabaseError> {
        Ok(run!(
            self,
            fetch_all,
            sqlx::query_as!(
                CheckpointRow,
                r#"SELECT position AS "position: Unsigned", head AS "head: Bytes32", created_at, note
                FROM audit_checkpoints
                WHERE position > $1
                ORDER BY position
                LIMIT $2"#,
                Unsigned::bind(after)?,
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(Checkpoint::from)
        .collect())
    }

    /// The checkpoint the chain was last pruned through, if it ever was.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn anchor(&mut self) -> Result<Option<Checkpoint>, DatabaseError> {
        Ok(run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                CheckpointRow,
                r#"SELECT c.position AS "position: Unsigned", c.head AS "head: Bytes32",
                    c.created_at, c.note
                FROM audit_anchor a JOIN audit_checkpoints c USING (position)"#
            )
        )?
        .map(Checkpoint::from))
    }

    /// Makes this transaction see one snapshot of the whole database, read only, so
    /// a verification reads checkpoints and events as of the same moment. Must be
    /// the transaction's first statement. Without a transaction ID, it never holds
    /// back sealing.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the statement fails, e.g. when it is not first.
    pub async fn read_snapshot(&mut self) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        )?;
        Ok(())
    }
}

impl DatabaseTransaction<'_> {
    /// Deletes every sealed event up to and including `through`, which must be a
    /// checkpoint's position, and makes that checkpoint the anchor the remaining
    /// chain extends. Their personal data goes with them. Returns how many events
    /// were deleted. The caller verifies the chain through `through` first.
    ///
    /// The guard triggers let only this transaction delete sealed events and move
    /// the anchor, and only until this returns. The anchor only moves forward, so
    /// of two concurrent prunes, the one that would move it back fails.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails, e.g. when `through` is not a
    /// checkpoint's position.
    pub async fn prune_audit_chain(&mut self, through: u64) -> Result<u64, DatabaseError> {
        let through = Unsigned::bind(through)?;
        let connection = &mut *self.inner;
        sqlx::query!("SELECT set_config('piquel.audit_prune', 'on', true)")
            .fetch_one(&mut *connection)
            .await?;
        let deleted = sqlx::query!(
            "DELETE FROM domain_events WHERE chain_position <= $1",
            through
        )
        .execute(&mut *connection)
        .await?
        .rows_affected();
        sqlx::query!(
            "INSERT INTO audit_anchor (position) VALUES ($1)
            ON CONFLICT (singleton) DO UPDATE SET position = EXCLUDED.position",
            through
        )
        .execute(&mut *connection)
        .await?;
        sqlx::query!("SELECT set_config('piquel.audit_prune', 'off', true)")
            .fetch_one(&mut *connection)
            .await?;
        Ok(deleted)
    }
}

/// A change an attacker with database access could make, for verification tests.
/// [`AuditRepository::tamper`] applies it with the guard triggers disabled, so run
/// it only on a database of its own (see `Database::isolated`).
#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
pub enum Tamper {
    /// Replaces the payload of the event at a position.
    EditPayload(u64, Value),
    /// Deletes the event at a position.
    DeleteEvent(u64),
    /// Inserts an event at a position, moving the later ones up by one. It copies
    /// the hash its position had.
    InsertEvent(u64),
    /// Swaps the positions, and so the order, of two events.
    SwapEvents(u64, u64),
    /// Replaces the stored chain hash of the event at a position, as an attacker
    /// recomputing the chain after an edit would.
    SetHash(u64, [u8; 32]),
    /// Moves the anchor to the checkpoint at a position without deleting the
    /// events before it, hiding them from a verification that trusts the anchor.
    SetAnchor(u64),
    /// Replaces the head of the checkpoint at a position.
    EditCheckpointHead(u64, [u8; 32]),
    /// Replaces the note of the checkpoint at a position.
    EditCheckpointNote(u64, String),
    /// Deletes the personal data of the event at a position, as retention does.
    ErasePersonalData(u64),
}

#[cfg(feature = "test-support")]
impl AuditRepository<'_> {
    /// Applies `tamper` with the guard triggers disabled.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails.
    pub async fn tamper(&mut self, tamper: Tamper) -> Result<(), DatabaseError> {
        self.guards(false).await?;
        match tamper {
            Tamper::EditPayload(position, payload) => run!(
                self,
                execute,
                sqlx::query!(
                    "UPDATE domain_events SET payload = $2 WHERE chain_position = $1",
                    Unsigned::bind(position)?,
                    payload,
                )
            ),
            Tamper::DeleteEvent(position) => run!(
                self,
                execute,
                sqlx::query!(
                    "DELETE FROM domain_events WHERE chain_position = $1",
                    Unsigned::bind(position)?,
                )
            ),
            Tamper::InsertEvent(position) => self.insert_event(Unsigned::bind(position)?).await,
            Tamper::SwapEvents(first, second) => {
                self.swap_events(Unsigned::bind(first)?, Unsigned::bind(second)?)
                    .await
            }
            Tamper::SetHash(position, hash) => run!(
                self,
                execute,
                sqlx::query!(
                    "UPDATE domain_events SET chain_hash = $2 WHERE chain_position = $1",
                    Unsigned::bind(position)?,
                    &hash[..],
                )
            ),
            Tamper::SetAnchor(position) => run!(
                self,
                execute,
                sqlx::query!(
                    "INSERT INTO audit_anchor (position) VALUES ($1)
                    ON CONFLICT (singleton) DO UPDATE SET position = EXCLUDED.position",
                    Unsigned::bind(position)?,
                )
            ),
            Tamper::EditCheckpointHead(position, head) => run!(
                self,
                execute,
                sqlx::query!(
                    "UPDATE audit_checkpoints SET head = $2 WHERE position = $1",
                    Unsigned::bind(position)?,
                    &head[..],
                )
            ),
            Tamper::EditCheckpointNote(position, note) => run!(
                self,
                execute,
                sqlx::query!(
                    "UPDATE audit_checkpoints SET note = $2 WHERE position = $1",
                    Unsigned::bind(position)?,
                    note,
                )
            ),
            Tamper::ErasePersonalData(position) => run!(
                self,
                execute,
                sqlx::query!(
                    "DELETE FROM event_personal_data
                    WHERE event_id = (SELECT id FROM domain_events WHERE chain_position = $1)",
                    Unsigned::bind(position)?,
                )
            ),
        }?;
        self.guards(true).await?;
        Ok(())
    }

    /// Enables or disables the guard triggers of every audit table, for
    /// [`Self::tamper`].
    async fn guards(&mut self, enabled: bool) -> Result<(), DatabaseError> {
        let toggle = if enabled { "ENABLE" } else { "DISABLE" };
        for table in ["domain_events", "audit_checkpoints", "audit_anchor"] {
            // DDL takes no bind parameters; every name is a literal here.
            let statement = format!("ALTER TABLE {table} {toggle} TRIGGER USER");
            run!(self, execute, sqlx::raw_sql(&statement))?;
        }
        Ok(())
    }

    /// Positions move this far out of the way while renumbering, since a unique
    /// constraint is checked row by row.
    const RENUMBERING_OFFSET: i64 = 1 << 40;

    /// Inserts an event at `position`, moving the later ones up by one, with the
    /// hash its position had.
    async fn insert_event(
        &mut self,
        position: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE domain_events SET chain_position = chain_position + $2
                WHERE chain_position >= $1",
                position,
                Self::RENUMBERING_OFFSET,
            )
        )?;
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE domain_events SET chain_position = chain_position - $1 + 1
                WHERE chain_position >= $1",
                Self::RENUMBERING_OFFSET,
            )
        )?;
        run!(
            self,
            execute,
            sqlx::query!(
                r#"INSERT INTO domain_events (
                    id, kind, version, payload, actor, chain_position, chain_hash
                )
                SELECT $2, 'imported', 1, '{}', '{"type": "unrecorded"}', $1::bigint, chain_hash
                FROM domain_events WHERE chain_position = $1::bigint + 1"#,
                position,
                Uuid::now_v7(),
            )
        )
    }

    /// Swaps the positions of two events.
    async fn swap_events(
        &mut self,
        first: i64,
        second: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE domain_events SET chain_position = chain_position + $3
                WHERE chain_position IN ($1, $2)",
                first,
                second,
                Self::RENUMBERING_OFFSET,
            )
        )?;
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE domain_events
                SET chain_position =
                    CASE chain_position - $3::bigint WHEN $1::bigint THEN $2::bigint ELSE $1 END
                WHERE chain_position IN ($1::bigint + $3::bigint, $2::bigint + $3::bigint)",
                first,
                second,
                Self::RENUMBERING_OFFSET,
            )
        )
    }
}

/// Sealing order, the guard trigger, pruning and the isolated test schema.
#[cfg(test)]
mod tests;
