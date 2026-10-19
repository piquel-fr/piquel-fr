//! The outbound delivery queue: messages for other systems, created in the
//! transaction of the event that causes them and sent later by workers.
//!
//! Delivery is at least once. A worker claims a delivery with a lease, sends it
//! outside any transaction, then records the outcome only if it still holds the
//! lease. Deliveries sharing an ordering key are sent one at a time, in the order
//! their transactions committed. See `docs/architecture/delivery-queue.md`.

use super::{DeliveryRepository, RepositoryExecutor, Unsigned};
use crate::{DatabaseError, DatabaseTransaction, DomainEvent};
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{DeliveryId, EventId, UserId};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

/// What a claimed delivery that does not decode into its channel's types records
/// as its error before it fails.
const UNDECODABLE: &str = "stored recipient or payload does not decode";

/// A kind of outbound message, such as back-channel logout tokens: its stored
/// name, the facts it copies about each recipient, and the deliveries an event
/// causes. Auth-service implements how to send each one.
pub trait Channel: Sized + Send + Sync + 'static {
    /// Stored in `deliveries.channel`. Never rename a released channel.
    const NAME: &'static str;
    /// Facts about the recipient copied at creation, such as `client_id`, `sub` and
    /// `sid`, so a send never reads rows that may have changed since.
    type Recipient: Serialize + DeserializeOwned + Send + Sync;
    /// The message. Never a plaintext secret: payloads are stored as they are.
    type Payload: Serialize + DeserializeOwned + Send + Sync;

    /// The deliveries `event`, concerning `subject`, causes. Runs inside the
    /// event's transaction, which sees the rows as the change left them, so a
    /// committed event has all its deliveries and a rolled-back one has none.
    fn deliveries(
        event: &DomainEvent,
        subject: Option<UserId>,
        tx: &mut DatabaseTransaction<'_>,
    ) -> impl Future<Output = Result<Vec<NewDelivery<Self>>, DatabaseError>> + Send;
}

/// The channels [`DatabaseTransaction::record`] fans out to, as a nested list:
/// `()`, `(A, ())`, `(A, (B, ()))`. A list rather than a slice, so each channel's
/// types stay known at compile time.
pub(crate) trait Channels {
    /// Creates every listed channel's deliveries for the event `event_id`.
    fn fan_out(
        tx: &mut DatabaseTransaction<'_>,
        event_id: EventId,
        subject: Option<UserId>,
        event: &DomainEvent,
    ) -> impl Future<Output = Result<(), DatabaseError>> + Send;
}

/// Every channel `record` fans out to. Add a channel here once it is implemented.
pub(crate) type Registered = ();

impl Channels for () {
    /// The end of the list.
    fn fan_out(
        _: &mut DatabaseTransaction<'_>,
        _: EventId,
        _: Option<UserId>,
        _: &DomainEvent,
    ) -> impl Future<Output = Result<(), DatabaseError>> + Send {
        std::future::ready(Ok(()))
    }
}

impl<C: Channel, Rest: Channels> Channels for (C, Rest) {
    /// Inserts `C`'s deliveries, then the rest's.
    async fn fan_out(
        tx: &mut DatabaseTransaction<'_>,
        event_id: EventId,
        subject: Option<UserId>,
        event: &DomainEvent,
    ) -> Result<(), DatabaseError> {
        for delivery in C::deliveries(event, subject, tx).await? {
            tx.deliveries().insert(Some(event_id), delivery).await?;
        }
        Rest::fan_out(tx, event_id, subject, event).await
    }
}

/// A delivery to create, with everything its sends need copied into it.
pub struct NewDelivery<C: Channel> {
    /// Where it goes: an endpoint URL or an address.
    pub destination: String,
    /// Facts about the recipient.
    pub recipient: C::Recipient,
    /// The message.
    pub payload: C::Payload,
    /// Deliveries sharing a key are sent one at a time, in the order their
    /// transactions committed, and a failed one holds back those after it until an
    /// operator retries or cancels it. `None` for unordered deliveries.
    pub ordering_key: Option<String>,
}

/// A delivery a worker has claimed. Only it can record the attempt's outcome, and
/// only while no other worker has claimed the delivery since.
pub struct Delivery<C: Channel> {
    /// Its identity on every attempt: receivers deduplicate on it as a `jti` or
    /// `Message-ID`.
    pub id: DeliveryId,
    /// The event that caused it, if any.
    pub event_id: Option<EventId>,
    /// Where it goes.
    pub destination: String,
    /// Facts about the recipient, copied at creation.
    pub recipient: C::Recipient,
    /// The message.
    pub payload: C::Payload,
    /// Attempts so far, this one included.
    pub attempts: u64,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When an operator last retried it, which restarts its channel's maximum age.
    pub retried_at: Option<DateTime<Utc>>,
    /// Proves this claim when the outcome is recorded.
    claim_token: Uuid,
}

/// A claimed delivery as stored, before its JSON decodes into the channel's types.
struct ClaimedRow {
    /// Delivery identifier.
    id: DeliveryId,
    /// The causing event.
    event_id: Option<EventId>,
    /// Where it goes.
    destination: String,
    /// The channel's recipient JSON.
    recipient: Value,
    /// The channel's payload JSON.
    payload: Value,
    /// Attempts so far, this one included.
    attempts: Unsigned,
    /// When it was created.
    created_at: DateTime<Utc>,
    /// When an operator last retried it.
    retried_at: Option<DateTime<Utc>>,
}

/// How an attempt ended, as [`DeliveryRepository::finish`] records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The receiver accepted it.
    Succeeded,
    /// It is attempted again at `at`.
    Retry {
        /// When the next attempt is due.
        at: DateTime<Utc>,
        /// What went wrong: a status code or an error kind, never a response body.
        error: String,
    },
    /// It is not attempted again unless an operator retries it.
    Failed {
        /// What went wrong: a status code or an error kind, never a response body.
        error: String,
    },
}

impl DeliveryOutcome {
    /// The status, next attempt and error that the outcome stores.
    fn columns(&self) -> (DeliveryStatus, Option<DateTime<Utc>>, Option<&str>) {
        match self {
            Self::Succeeded => (DeliveryStatus::Succeeded, None, None),
            Self::Retry { at, error } => (DeliveryStatus::Pending, Some(*at), Some(error)),
            Self::Failed { error } => (DeliveryStatus::Failed, None, Some(error)),
        }
    }
}

piquel_common::str_enum! {
    /// Where a delivery is in its life.
    pub enum DeliveryStatus {
        /// Waiting for its next attempt, or being attempted.
        Pending = "pending",
        /// The receiver accepted it.
        Succeeded = "succeeded",
        /// A permanent error, or retryable errors past the channel's maximum age.
        Failed = "failed",
        /// An operator cancelled it.
        Cancelled = "cancelled",
    }
}

/// A delivery as operators list it, without its recipient or payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliverySummary {
    /// Delivery identifier.
    pub id: DeliveryId,
    /// Its channel's name.
    pub channel: String,
    /// Where it goes.
    pub destination: String,
    /// Where it is in its life.
    pub status: DeliveryStatus,
    /// Attempts so far.
    pub attempts: u64,
    /// Its ordering key and its place in that order, if it is ordered.
    pub ordering: Option<(String, i64)>,
    /// When the next attempt is due, while pending.
    pub next_attempt_at: DateTime<Utc>,
    /// The latest attempt's error.
    pub last_error: Option<String>,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When it succeeded, failed or was cancelled.
    pub finished_at: Option<DateTime<Utc>>,
}

/// A listed delivery as stored.
struct SummaryRow {
    /// Delivery identifier.
    id: DeliveryId,
    /// Channel name.
    channel: String,
    /// Where it goes.
    destination: String,
    /// Life-cycle status.
    status: DeliveryStatus,
    /// Attempts so far.
    attempts: Unsigned,
    /// Ordering key, if ordered.
    ordering_key: Option<String>,
    /// Place in the key's order, if ordered.
    ordinal: Option<i64>,
    /// Next attempt.
    next_attempt_at: DateTime<Utc>,
    /// Latest error.
    last_error: Option<String>,
    /// Creation time.
    created_at: DateTime<Utc>,
    /// Finish time.
    finished_at: Option<DateTime<Utc>>,
}

impl From<SummaryRow> for DeliverySummary {
    /// Pairs the ordering key with its ordinal, which the schema sets together.
    fn from(row: SummaryRow) -> Self {
        Self {
            id: row.id,
            channel: row.channel,
            destination: row.destination,
            status: row.status,
            attempts: row.attempts.into(),
            ordering: row.ordering_key.zip(row.ordinal),
            next_attempt_at: row.next_attempt_at,
            last_error: row.last_error,
            created_at: row.created_at,
            finished_at: row.finished_at,
        }
    }
}

impl DeliveryRepository<'_> {
    /// Queues a delivery on channel `C`. Events' deliveries are inserted by
    /// [`DatabaseTransaction::record`]; insert directly only deliveries no event
    /// causes. An ordered delivery takes the next ordinal of its key, which locks
    /// the key until the transaction ends, so ordinals follow commit order.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the recipient or payload cannot be serialized,
    /// or a query fails.
    pub async fn insert<C: Channel>(
        &mut self,
        event_id: Option<EventId>,
        delivery: NewDelivery<C>,
    ) -> Result<DeliveryId, DatabaseError> {
        let serialization = |error| DatabaseError::Operation(Box::new(error));
        let recipient = serde_json::to_value(&delivery.recipient).map_err(serialization)?;
        let payload = serde_json::to_value(&delivery.payload).map_err(serialization)?;
        let id = DeliveryId::new();
        // One statement, so the ordinal and the delivery commit together even
        // outside a transaction. Taking the ordinal locks the key's row until then.
        run!(
            self,
            execute,
            sqlx::query!(
                "WITH ordinal AS (
                    INSERT INTO delivery_orderings (ordering_key, next_ordinal)
                    SELECT $6, 2 WHERE $6::text IS NOT NULL
                    ON CONFLICT (ordering_key) DO UPDATE
                    SET next_ordinal = delivery_orderings.next_ordinal + 1
                    RETURNING next_ordinal - 1 AS value
                )
                INSERT INTO deliveries (
                    id, event_id, channel, destination, recipient, ordering_key, ordinal,
                    payload, status
                ) VALUES ($1, $2, $3, $4, $5, $6, (SELECT value FROM ordinal), $7, $8)",
                id.as_uuid(),
                event_id.map(EventId::as_uuid),
                C::NAME,
                delivery.destination,
                recipient,
                delivery.ordering_key,
                payload,
                DeliveryStatus::Pending.as_str(),
            )
        )?;
        Ok(id)
    }

    /// Claims the longest-due delivery of channel `C` for `lease`, or returns
    /// `None` when none is due. Concurrent workers never claim the same delivery
    /// while its lease lasts. An ordered delivery is due only once every earlier
    /// one with its key succeeded or was cancelled, and no attempt of a cancelled
    /// one may still be in progress. Run it outside a transaction,
    /// so the claim commits before the send starts.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::InvalidStoredData`] for a delivery whose recipient
    /// or payload does not decode into `C`'s types; it is marked failed, since no
    /// attempt could ever send it. Returns another [`DatabaseError`] if a query fails.
    pub async fn claim<C: Channel>(
        &mut self,
        lease: Duration,
    ) -> Result<Option<Delivery<C>>, DatabaseError> {
        let claim_token = Uuid::now_v7();
        // In READ COMMITTED, a row another worker claimed after this statement's
        // snapshot is skipped while locked, and rechecked against its new lease once
        // that claim commits, so two workers never hold the same lease.
        let Some(row) = run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                ClaimedRow,
                r#"UPDATE deliveries
                SET claim_token = $2, leased_until = now() + $3, attempts = attempts + 1
                WHERE id = (
                    SELECT d.id
                    FROM deliveries d
                    WHERE d.channel = $1
                    AND d.status = 'pending'
                    AND d.next_attempt_at <= now()
                    AND (d.leased_until IS NULL OR d.leased_until < now())
                    AND (d.ordering_key IS NULL OR NOT EXISTS (
                        SELECT 1
                        FROM deliveries e
                        WHERE e.ordering_key = d.ordering_key
                        AND e.ordinal < d.ordinal
                        AND (e.status IN ('pending', 'failed') OR e.leased_until > now())
                    ))
                    ORDER BY d.next_attempt_at
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING
                    id AS "id: DeliveryId", event_id AS "event_id: EventId", destination,
                    recipient, payload, attempts::bigint AS "attempts!: Unsigned", created_at,
                    retried_at"#,
                C::NAME,
                claim_token,
                lease as _,
            )
        )?
        else {
            return Ok(None);
        };
        let decoded = serde_json::from_value(row.recipient)
            .and_then(|recipient| Ok((recipient, serde_json::from_value(row.payload)?)));
        match decoded {
            Ok((recipient, payload)) => Ok(Some(Delivery {
                id: row.id,
                event_id: row.event_id,
                destination: row.destination,
                recipient,
                payload,
                attempts: row.attempts.into(),
                created_at: row.created_at,
                retried_at: row.retried_at,
                claim_token,
            })),
            Err(source) => {
                let failed = DeliveryOutcome::Failed {
                    error: UNDECODABLE.into(),
                };
                self.record_outcome(row.id, claim_token, &failed).await?;
                Err(DatabaseError::InvalidStoredData {
                    column: "recipient or payload".into(),
                    source: source.into(),
                })
            }
        }
    }

    /// Records how `delivery`'s attempt ended, unless its lease was lost: another
    /// worker has claimed it since, or an operator cancelled it. A lost lease's
    /// outcome is discarded, so a stale worker never overwrites a newer result.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the lease was lost, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn finish<C: Channel>(
        &mut self,
        delivery: &Delivery<C>,
        outcome: &DeliveryOutcome,
    ) -> Result<(), DatabaseError> {
        self.record_outcome(delivery.id, delivery.claim_token, outcome)
            .await
    }

    /// Records `outcome` for the delivery `id` if `claim_token` still holds it.
    async fn record_outcome(
        &mut self,
        id: DeliveryId,
        claim_token: Uuid,
        outcome: &DeliveryOutcome,
    ) -> Result<(), DatabaseError> {
        let (status, next_attempt_at, error) = outcome.columns();
        let recorded = run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE deliveries
                SET status = $3,
                    next_attempt_at = COALESCE($4, next_attempt_at),
                    last_error = COALESCE($5, last_error),
                    finished_at = CASE WHEN $3 = 'pending' THEN NULL ELSE now() END,
                    claim_token = NULL,
                    leased_until = NULL
                WHERE id = $1 AND claim_token = $2",
                id.as_uuid(),
                claim_token,
                status.as_str(),
                next_attempt_at,
                error,
            )
        )?;
        if recorded.rows_affected() == 0 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }

    /// Lists up to `limit` deliveries, newest first, optionally only those with
    /// `status` or on `channel`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn list(
        &mut self,
        status: Option<DeliveryStatus>,
        channel: Option<&str>,
        limit: u32,
    ) -> Result<Vec<DeliverySummary>, DatabaseError> {
        Ok(run!(
            self,
            fetch_all,
            sqlx::query_as!(
                SummaryRow,
                r#"SELECT
                    id AS "id: DeliveryId", channel, destination,
                    status AS "status: DeliveryStatus", attempts::bigint AS "attempts!: Unsigned",
                    ordering_key, ordinal, next_attempt_at, last_error, created_at, finished_at
                FROM deliveries
                WHERE ($1::text IS NULL OR status = $1)
                AND ($2::text IS NULL OR channel = $2)
                ORDER BY created_at DESC, id DESC
                LIMIT $3"#,
                status.map(DeliveryStatus::as_str),
                channel,
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(DeliverySummary::from)
        .collect())
    }

    /// Makes a failed delivery, or a cancelled unordered one, due again now, and
    /// restarts its channel's maximum age. Cancelling an ordered delivery is
    /// final: the deliveries after it may already have been sent.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if no failed delivery or cancelled
    /// unordered delivery has this ID, or another [`DatabaseError`] if the query fails.
    pub async fn retry(&mut self, id: DeliveryId) -> Result<(), DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "UPDATE deliveries
                SET status = 'pending', next_attempt_at = now(), finished_at = NULL,
                    retried_at = now()
                WHERE id = $1
                AND (status = 'failed' OR (status = 'cancelled' AND ordering_key IS NULL))
                RETURNING id",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Cancels a pending or failed delivery, which unblocks the deliveries ordered
    /// after it. An attempt in progress may still reach the receiver, but its
    /// outcome is discarded, and its lease keeps holding back the deliveries
    /// ordered after it until it expires, so none overtakes it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if no pending or failed delivery has
    /// this ID, or another [`DatabaseError`] if the query fails.
    pub async fn cancel(&mut self, id: DeliveryId) -> Result<(), DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "UPDATE deliveries
                SET status = 'cancelled', finished_at = now(), claim_token = NULL
                WHERE id = $1 AND status IN ('pending', 'failed')
                RETURNING id",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }
}

/// Database tests for fan-out, claims, leases and ordering.
#[cfg(test)]
mod tests;
