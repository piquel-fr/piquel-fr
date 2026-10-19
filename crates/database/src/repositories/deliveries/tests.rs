//! Fan-out with the event, exclusive claims, lost leases and per-key ordering.
//!
//! Tests share one database, so each claims from a channel of its own.
use super::*;
use crate::{Database, EventRepository, MaintenanceRepository, StoredEvent};
use piquel_common::{
    Personal,
    events::{Actor, EventContext, RequestOrigin},
};
use sqlx::PgPool;
use std::collections::HashSet;

/// A lease no test outlives.
const LEASE: Duration = Duration::from_mins(1);

/// Declares channels whose deliveries tests insert themselves.
macro_rules! test_channels {
    ($($(#[doc = $doc:literal])* $name:ident = $value:literal;)*) => {$(
        $(#[doc = $doc])*
        struct $name;

        impl Channel for $name {
            const NAME: &'static str = $value;
            type Recipient = String;
            type Payload = u32;

            /// Causes nothing: tests insert deliveries directly.
            fn deliveries(
                _: &DomainEvent,
                _: Option<UserId>,
                _: &mut DatabaseTransaction<'_>,
            ) -> impl Future<Output = Result<Vec<NewDelivery<Self>>, DatabaseError>> + Send {
                std::future::ready(Ok(vec![]))
            }
        }
    )*};
}

test_channels! {
    /// Claimed by many workers at once.
    Concurrent = "test_concurrent";
    /// Claimed again once its lease expires.
    Leased = "test_leased";
    /// Sent in order.
    Ordered = "test_ordered";
    /// Cancelled while being sent.
    Interrupted = "test_interrupted";
    /// Stuck behind an old failure.
    Abandoned = "test_abandoned";
}

/// Copies the subject's username into each event's delivery, as back-channel
/// logout copies a session's `sid` before purges can delete it.
struct Recorder;

impl Channel for Recorder {
    const NAME: &'static str = "test_recorder";
    type Recipient = String;
    type Payload = u32;

    /// One delivery per event about an account, naming its username.
    async fn deliveries(
        _: &DomainEvent,
        subject: Option<UserId>,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
        let Some(subject) = subject else {
            return Ok(vec![]);
        };
        let username = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(subject.as_uuid())
            .fetch_one(&mut *tx.inner)
            .await?;
        Ok(vec![NewDelivery {
            destination: "https://rp.example/logout".into(),
            recipient: username,
            payload: 1,
            ordering_key: None,
        }])
    }
}

/// Deletes the deliveries a previous run left on `C`.
async fn clear<C: Channel>(pool: &PgPool) {
    sqlx::query("DELETE FROM deliveries WHERE channel = $1")
        .bind(C::NAME)
        .execute(pool)
        .await
        .expect("clear channel");
}

/// Queues a delivery on `C`, ordered by `key` if given.
async fn insert<C: Channel<Recipient = String, Payload = u32>>(
    pool: &PgPool,
    key: Option<&str>,
) -> DeliveryId {
    DeliveryRepository::from_pool(pool)
        .insert::<C>(
            None,
            NewDelivery {
                destination: "https://receiver.example".into(),
                recipient: "recipient".into(),
                payload: 7,
                ordering_key: key.map(Into::into),
            },
        )
        .await
        .expect("insert")
}

/// Claims the next due delivery of `C`.
async fn claim<C: Channel>(pool: &PgPool, lease: Duration) -> Option<Delivery<C>> {
    DeliveryRepository::from_pool(pool)
        .claim::<C>(lease)
        .await
        .expect("claim")
}

/// Records `outcome` for `delivery`.
async fn finish<C: Channel>(
    pool: &PgPool,
    delivery: &Delivery<C>,
    outcome: &DeliveryOutcome,
) -> Result<(), DatabaseError> {
    DeliveryRepository::from_pool(pool)
        .finish(delivery, outcome)
        .await
}

/// A permanent failure.
fn failed() -> DeliveryOutcome {
    DeliveryOutcome::Failed {
        error: "HTTP 400".into(),
    }
}

/// An event's deliveries commit with it, copying the facts they need, and a
/// rolled-back event has none. Deleting the account afterwards leaves them as they were.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn deliveries_commit_with_their_event_and_outlive_the_account() {
    let pool = Database::test_pool().await;
    let user = UserId::new();
    let username = format!("delivery_{user}");
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Delivery test')")
        .bind(user.as_uuid())
        .bind(&username)
        .execute(&pool)
        .await
        .expect("user");
    let record = async |commit: bool| {
        let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        let context = EventContext {
            actor: Actor::Anonymous,
            origin: RequestOrigin::default(),
        };
        let event = DomainEvent::IdentityUnlinked {
            provider: piquel_common::Provider::GitHub,
        };
        tx.record_to::<(Recorder, ())>(&context, Some(user), event)
            .await
            .expect("record");
        if commit {
            tx.commit().await.expect("commit");
        }
    };
    let stored = async || -> Vec<(Uuid, Value, String)> {
        sqlx::query_as(
            "SELECT event_id, recipient, status FROM deliveries
            WHERE channel = $1 AND recipient = to_jsonb($2::text)",
        )
        .bind(Recorder::NAME)
        .bind(&username)
        .fetch_all(&pool)
        .await
        .expect("deliveries")
    };

    record(false).await;
    assert!(stored().await.is_empty(), "a rolled-back event has none");

    record(true).await;
    let [event]: [StoredEvent; 1] = EventRepository::from_pool(&pool)
        .history_for_user(user, 10)
        .await
        .expect("history")
        .try_into()
        .expect("one event");
    let created = stored().await;
    assert_eq!(
        created,
        [(
            event.id.as_uuid(),
            Value::from(username.clone()),
            "pending".into()
        )]
    );
    assert_eq!(event.origin, Personal::Value(RequestOrigin::default()));

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.as_uuid())
        .execute(&pool)
        .await
        .expect("purge the account");
    assert_eq!(stored().await, created, "the purge changes nothing");
}

/// However many workers claim at once, each delivery goes to exactly one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn concurrent_workers_never_claim_the_same_delivery() {
    let pool = Database::test_pool().await;
    clear::<Concurrent>(&pool).await;
    let mut queued = HashSet::new();
    for _ in 0..10 {
        queued.insert(insert::<Concurrent>(&pool, None).await);
    }
    let claims: Vec<_> = (0..30)
        .map(|_| {
            let pool = pool.clone();
            tokio::spawn(async move { claim::<Concurrent>(&pool, LEASE).await.map(|d| d.id) })
        })
        .collect();
    let mut claimed = Vec::new();
    for claim in claims {
        claimed.extend(claim.await.expect("claim task"));
    }
    assert_eq!(claimed.len(), queued.len(), "{claimed:?}");
    assert_eq!(claimed.into_iter().collect::<HashSet<_>>(), queued);
}

/// A delivery stays claimed for its lease, is claimed again once the lease
/// expires, and only the newest claim's outcome is recorded.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn an_expired_lease_is_claimed_again_and_the_stale_outcome_discarded() {
    let pool = Database::test_pool().await;
    clear::<Leased>(&pool).await;
    let id = insert::<Leased>(&pool, None).await;

    let stale = claim::<Leased>(&pool, Duration::from_millis(1))
        .await
        .expect("first claim");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let current = claim::<Leased>(&pool, LEASE)
        .await
        .expect("the expired lease is claimed again");
    assert_eq!((stale.id, current.id), (id, id));
    assert_eq!((stale.attempts, current.attempts), (1, 2));
    assert!(
        claim::<Leased>(&pool, LEASE).await.is_none(),
        "a live lease is not claimed"
    );

    assert!(matches!(
        finish(&pool, &stale, &DeliveryOutcome::Succeeded).await,
        Err(DatabaseError::NotFound)
    ));
    finish(&pool, &current, &failed())
        .await
        .expect("the current claim records its outcome");
    let [listed] = <[DeliverySummary; 1]>::try_from(
        DeliveryRepository::from_pool(&pool)
            .list(None, Some(Leased::NAME), 10)
            .await
            .expect("list"),
    )
    .expect("one delivery");
    assert_eq!(
        (listed.status, listed.last_error.as_deref()),
        (DeliveryStatus::Failed, Some("HTTP 400"))
    );
}

/// Deliveries with one key are claimed in ordinal order, one at a time. A failed
/// one holds back the rest, through cleanup, until it is retried and succeeds, or
/// is cancelled for good.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn ordered_deliveries_go_one_at_a_time_and_a_failure_blocks_the_rest() {
    let pool = Database::test_pool().await;
    clear::<Ordered>(&pool).await;
    let key = format!("key-{}", Uuid::now_v7());
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(insert::<Ordered>(&pool, Some(&key)).await);
    }
    let unordered = insert::<Ordered>(&pool, None).await;
    let next = async || claim::<Ordered>(&pool, LEASE).await;

    let mut claimed = Vec::new();
    while let Some(delivery) = next().await {
        claimed.push(delivery);
    }
    assert_eq!(
        claimed.iter().map(|d| d.id).collect::<HashSet<_>>(),
        HashSet::from([ids[0], unordered]),
        "only the first of the key is due while it is pending"
    );
    for delivery in &claimed {
        finish(&pool, delivery, &DeliveryOutcome::Succeeded)
            .await
            .expect("succeed");
    }

    let second = next().await.expect("second");
    assert_eq!(second.id, ids[1]);
    finish(&pool, &second, &failed()).await.expect("fail");
    MaintenanceRepository::from_pool(&pool)
        .purge_expired_auth_state(1000)
        .await
        .expect("cleanup");
    assert!(next().await.is_none(), "the failure holds back the third");

    let repository = || DeliveryRepository::from_pool(&pool);
    repository().retry(ids[1]).await.expect("retry");
    let retried = next().await.expect("retried");
    assert_eq!((retried.id, retried.attempts), (ids[1], 2));
    assert!(
        retried.retried_at.is_some(),
        "retrying restarts the maximum age"
    );
    finish(&pool, &retried, &failed())
        .await
        .expect("fail again");
    repository().cancel(ids[1]).await.expect("cancel");
    assert!(
        matches!(
            repository().retry(ids[1]).await,
            Err(DatabaseError::NotFound)
        ),
        "cancelling an ordered delivery is final"
    );
    assert!(matches!(
        repository().cancel(ids[1]).await,
        Err(DatabaseError::NotFound)
    ));

    let third = next().await.expect("third");
    assert_eq!(third.id, ids[2]);
    let ordinals: Vec<_> = repository()
        .list(None, Some(Ordered::NAME), 10)
        .await
        .expect("list")
        .into_iter()
        .filter_map(|summary| summary.ordering)
        .map(|(_, ordinal)| ordinal)
        .collect();
    assert_eq!(ordinals, [3, 2, 1], "newest first");
}

/// Cancelling a delivery while it is being sent discards its outcome, but the
/// next one with its key waits for the attempt's lease, so it cannot overtake it.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_cancelled_attempt_holds_back_its_key_until_its_lease_expires() {
    let pool = Database::test_pool().await;
    clear::<Interrupted>(&pool).await;
    let key = format!("key-{}", Uuid::now_v7());
    let first = insert::<Interrupted>(&pool, Some(&key)).await;
    let second = insert::<Interrupted>(&pool, Some(&key)).await;
    let lease = Duration::from_millis(300);

    let attempt = claim::<Interrupted>(&pool, lease).await.expect("first");
    assert_eq!(attempt.id, first);
    DeliveryRepository::from_pool(&pool)
        .cancel(first)
        .await
        .expect("cancel");
    assert!(claim::<Interrupted>(&pool, lease).await.is_none());
    assert!(matches!(
        finish(&pool, &attempt, &DeliveryOutcome::Succeeded).await,
        Err(DatabaseError::NotFound)
    ));
    tokio::time::sleep(lease).await;
    let next = claim::<Interrupted>(&pool, lease).await.expect("second");
    assert_eq!(next.id, second);
}

/// Thirty days after a failure, cleanup abandons its key: the deliveries behind
/// it are cancelled, never sent out of order, and the failure is deleted. A key
/// whose next delivery is being inserted is skipped until the insert ends, and
/// the key then takes new deliveries again.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn cleanup_abandons_a_key_stuck_behind_an_old_failure() {
    let pool = Database::test_pool().await;
    clear::<Abandoned>(&pool).await;
    let key = format!("key-{}", Uuid::now_v7());
    let failed_id = insert::<Abandoned>(&pool, Some(&key)).await;
    let waiting = insert::<Abandoned>(&pool, Some(&key)).await;
    let attempt = claim::<Abandoned>(&pool, LEASE).await.expect("first");
    finish(&pool, &attempt, &failed()).await.expect("fail");
    sqlx::query("UPDATE deliveries SET finished_at = now() - interval '31 days' WHERE id = $1")
        .bind(failed_id.as_uuid())
        .execute(&pool)
        .await
        .expect("age the failure");
    let abandon = async || {
        let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        let changed = tx.abandon_stuck_deliveries(10).await.expect("abandon");
        tx.commit().await.expect("commit");
        changed
    };

    let mut inserting = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
    let inserted = inserting
        .deliveries()
        .insert::<Abandoned>(
            None,
            NewDelivery {
                destination: "https://receiver.example".into(),
                recipient: "recipient".into(),
                payload: 7,
                ordering_key: Some(key.clone()),
            },
        )
        .await
        .expect("insert");
    assert_eq!(abandon().await, 0, "a key being inserted to is skipped");
    inserting.commit().await.expect("commit the insert");

    assert_eq!(abandon().await, 3, "two cancelled and the failure deleted");
    let mut listed: Vec<_> = DeliveryRepository::from_pool(&pool)
        .list(None, Some(Abandoned::NAME), 10)
        .await
        .expect("list")
        .into_iter()
        .map(|d| (d.id, d.status))
        .collect();
    listed.sort_by_key(|&(id, _)| id.as_uuid());
    assert_eq!(
        listed,
        [
            (waiting, DeliveryStatus::Cancelled),
            (inserted, DeliveryStatus::Cancelled)
        ]
    );
    assert!(matches!(
        DeliveryRepository::from_pool(&pool).retry(failed_id).await,
        Err(DatabaseError::NotFound)
    ));

    let next = insert::<Abandoned>(&pool, Some(&key)).await;
    assert_eq!(
        claim::<Abandoned>(&pool, LEASE).await.map(|d| d.id),
        Some(next)
    );
}
