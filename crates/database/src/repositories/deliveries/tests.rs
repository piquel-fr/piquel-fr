//! Fan-out with the event, exclusive claims, lost leases and operators' changes.
//!
//! Tests share one database, so each claims from a channel of its own.
use super::*;
use crate::{Database, EventRepository, InsertUser, SessionScope, StoredEvent, UserRepository};
use sourceorigin_common::{
    SessionId,
    events::{Actor, EventContext, RequestOrigin, RevocationReason},
};
use sqlx::PgPool;
use std::collections::HashSet;

/// A lease no test outlives.
const LEASE: Duration = Duration::from_mins(1);
/// A maximum age no test outlives.
const MAX_AGE: Duration = Duration::from_hours(1);

/// Declares channels whose deliveries tests insert themselves, each with its
/// stored name and payload type.
macro_rules! test_channels {
    ($($(#[doc = $doc:literal])* $name:ident = $value:literal: $payload:ty;)*) => {$(
        $(#[doc = $doc])*
        struct $name;

        impl Channel for $name {
            const NAME: &'static str = $value;
            type Recipient = String;
            type Payload = $payload;

            /// Causes nothing: tests insert deliveries directly.
            fn deliveries(
                _: &DomainEvent,
                _: Option<UserId>,
                _: &[Notified],
                _: &mut DatabaseTransaction<'_>,
            ) -> impl Future<Output = Result<Vec<NewDelivery<Self>>, DatabaseError>> + Send {
                std::future::ready(Ok(vec![]))
            }
        }
    )*};
}

test_channels! {
    /// Claimed by many workers at once.
    Concurrent = "test_concurrent": u32;
    /// Claimed again once its lease expires.
    Leased = "test_leased": u32;
    /// Retried and cancelled by an operator.
    Operated = "test_operated": u32;
    /// Counted for the backlog gauges.
    Backlogged = "test_backlogged": u32;
    /// A channel as the previous release declares it during a deploy.
    OldRelease = "test_versions": OldMessage;
    /// The same channel as the next release declares it.
    NewRelease = "test_versions": NewMessage;
}

/// [`OldRelease`]'s messages.
#[derive(Debug, Serialize, serde::Deserialize)]
enum OldMessage {
    /// Known to both releases.
    Known,
}

/// [`NewRelease`]'s messages, with a kind the previous release does not know, as
/// a release may add an `EmailMessage` variant.
#[derive(Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
enum NewMessage {
    /// Known to both releases.
    Known,
    /// Added by the new release.
    Added,
}

/// Copies the subject's handle into each event's delivery, as back-channel
/// logout copies a session's `sid` before purges can delete it.
struct Recorder;

impl Channel for Recorder {
    const NAME: &'static str = "test_recorder";
    type Recipient = String;
    type Payload = u32;

    /// One delivery per event about an account, naming its handle.
    async fn deliveries(
        _: &DomainEvent,
        subject: Option<UserId>,
        _: &[Notified],
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
        let Some(subject) = subject else {
            return Ok(vec![]);
        };
        let handle = sqlx::query_scalar(
            "SELECT handle FROM handles WHERE user_id = $1 AND released_at IS NULL",
        )
        .bind(subject.as_uuid())
        .fetch_one(&mut *tx.inner)
        .await?;
        Ok(vec![NewDelivery {
            destination: "https://rp.example/logout".into(),
            recipient: handle,
            payload: 1,
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

/// Queues a delivery on `C`.
async fn insert<C: Channel<Recipient = String, Payload = u32>>(pool: &PgPool) -> DeliveryId {
    DeliveryRepository::from_pool(pool)
        .insert::<C>(
            None,
            NewDelivery {
                destination: "https://receiver.example".into(),
                recipient: "recipient".into(),
                payload: 7,
            },
        )
        .await
        .expect("insert")
}

/// Claims the next due delivery of `C`.
async fn claim<C: Channel>(pool: &PgPool, lease: Duration) -> Option<Delivery<C>> {
    DeliveryRepository::from_pool(pool)
        .claim::<C>(lease, MAX_AGE)
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
/// rolled-back event has none.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn deliveries_commit_with_their_event() {
    let pool = Database::test_pool().await;
    let account = InsertUser::named("delivery");
    let (user, username) = (account.id, account.handle.to_string());
    Database { pool: pool.clone() }
        .users()
        .insert(&account)
        .await
        .expect("user");
    let record = async |commit: bool| {
        let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        let context = EventContext {
            actor: Actor::Anonymous,
            origin: RequestOrigin::default(),
            reason: None,
        };
        let event = DomainEvent::IdentityUnlinked {
            provider: sourceorigin_common::Provider::GitHub,
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
    assert_eq!(
        stored().await,
        [(
            event.id.as_uuid(),
            Value::from(username.clone()),
            "pending".into()
        )]
    );
}

/// However many workers claim at once, each delivery goes to exactly one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn concurrent_workers_never_claim_the_same_delivery() {
    let pool = Database::test_pool().await;
    clear::<Concurrent>(&pool).await;
    let mut queued = HashSet::new();
    for _ in 0..10 {
        queued.insert(insert::<Concurrent>(&pool).await);
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
    let id = insert::<Leased>(&pool).await;

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

/// The backlog counts only the channel's pending deliveries, and dates the
/// oldest of them.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn the_backlog_counts_pending_deliveries_and_dates_the_oldest() {
    let pool = Database::test_pool().await;
    clear::<Backlogged>(&pool).await;
    let backlog = || async {
        DeliveryRepository::from_pool(&pool)
            .backlog::<Backlogged>()
            .await
            .expect("backlog")
    };
    assert_eq!(
        backlog().await,
        DeliveryBacklog {
            pending: 0,
            oldest: None
        }
    );

    insert::<Backlogged>(&pool).await;
    insert::<Backlogged>(&pool).await;
    let claimed = claim::<Backlogged>(&pool, LEASE).await.expect("claim");
    finish(&pool, &claimed, &DeliveryOutcome::Succeeded)
        .await
        .expect("succeeded");

    let listed = DeliveryRepository::from_pool(&pool)
        .list(Some(DeliveryStatus::Pending), Some(Backlogged::NAME), 10)
        .await
        .expect("list");
    let [pending] = <[DeliverySummary; 1]>::try_from(listed).expect("one pending delivery");
    assert_ne!(pending.id, claimed.id);
    assert_eq!(
        backlog().await,
        DeliveryBacklog {
            pending: 1,
            oldest: Some(pending.created_at)
        }
    );
}

/// An operator retries a failed or cancelled delivery, which makes it due again
/// and restarts its maximum age, and cancels a pending or failed one. Cancelling
/// an attempt in progress discards its outcome, and a retry waits for that
/// attempt's lease, so the two are never sent at once.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn operators_retry_and_cancel_deliveries() {
    let pool = Database::test_pool().await;
    clear::<Operated>(&pool).await;
    let id = insert::<Operated>(&pool).await;
    let lease = Duration::from_millis(300);
    let next = async || claim::<Operated>(&pool, lease).await;
    let repository = || DeliveryRepository::from_pool(&pool);

    let attempt = next().await.expect("first attempt");
    let first_expiry = attempt.expires_at;
    repository().cancel(id).await.expect("cancel");
    assert!(matches!(
        finish(&pool, &attempt, &DeliveryOutcome::Succeeded).await,
        Err(DatabaseError::NotFound)
    ));
    assert!(next().await.is_none(), "a cancelled delivery is not due");

    repository()
        .retry(id)
        .await
        .expect("retry the cancelled delivery");
    assert!(
        next().await.is_none(),
        "the cancelled attempt's lease holds"
    );
    tokio::time::sleep(lease).await;
    let retried = next().await.expect("retried");
    assert_eq!((retried.id, retried.attempts), (id, 2));
    assert!(
        retried.expires_at > first_expiry,
        "retrying restarts the maximum age"
    );
    finish(&pool, &retried, &failed()).await.expect("fail");
    repository()
        .retry(id)
        .await
        .expect("retry the failed delivery");
    let last = next().await.expect("retried again");
    finish(&pool, &last, &DeliveryOutcome::Succeeded)
        .await
        .expect("succeed");
    assert!(matches!(
        repository().retry(id).await,
        Err(DatabaseError::NotFound)
    ));
    assert!(matches!(
        repository().cancel(id).await,
        Err(DatabaseError::NotFound)
    ));
}

/// During a deploy, the previous release's worker leaves a delivery it cannot
/// decode for the next release, without spending an attempt, and still sends the
/// ones it can. A delivery no release decodes fails at its maximum age.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn an_older_release_leaves_a_delivery_it_cannot_decode_to_a_newer_one() {
    let pool = Database::test_pool().await;
    clear::<NewRelease>(&pool).await;
    let queue = async |payload| {
        DeliveryRepository::from_pool(&pool)
            .insert::<NewRelease>(
                None,
                NewDelivery {
                    destination: "someone@example.com".into(),
                    recipient: "recipient".into(),
                    payload,
                },
            )
            .await
            .expect("insert")
    };
    let listed = async |id| {
        DeliveryRepository::from_pool(&pool)
            .list(None, Some(NewRelease::NAME), 10)
            .await
            .expect("list")
            .into_iter()
            .find(|delivery| delivery.id == id)
            .expect("listed")
    };
    let added = queue(NewMessage::Added).await;
    let known = queue(NewMessage::Known).await;

    let old = claim::<OldRelease>(&pool, LEASE)
        .await
        .expect("the old release sends what it decodes");
    assert_eq!(old.id, known);
    finish(&pool, &old, &DeliveryOutcome::Succeeded)
        .await
        .expect("succeeded");
    assert!(
        claim::<OldRelease>(&pool, LEASE).await.is_none(),
        "the old release leaves what it cannot decode"
    );
    let waiting = listed(added).await;
    assert_eq!(
        (
            waiting.status,
            waiting.attempts,
            waiting.last_error.as_deref()
        ),
        (DeliveryStatus::Pending, 0, Some(UNDECODABLE))
    );

    // The new release claims it once it is due again.
    assert!(claim::<NewRelease>(&pool, LEASE).await.is_none());
    sqlx::query("UPDATE deliveries SET next_attempt_at = now() WHERE id = $1")
        .bind(added.as_uuid())
        .execute(&pool)
        .await
        .expect("due");
    let new = claim::<NewRelease>(&pool, LEASE)
        .await
        .expect("the new release sends it");
    assert_eq!(
        (new.id, &new.payload, new.attempts),
        (added, &NewMessage::Added, 1)
    );
    finish(&pool, &new, &DeliveryOutcome::Succeeded)
        .await
        .expect("succeeded");

    let undecoded = queue(NewMessage::Added).await;
    let expired = DeliveryRepository::from_pool(&pool)
        .claim::<OldRelease>(LEASE, Duration::ZERO)
        .await;
    assert!(matches!(
        expired,
        Err(DatabaseError::InvalidStoredData { .. })
    ));
    let failed = listed(undecoded).await;
    assert_eq!(
        (failed.status, failed.last_error.as_deref()),
        (DeliveryStatus::Failed, Some(UNDECODABLE))
    );
}

/// Ending a session queues, in the revocation's transaction, one logout token per
/// client that redeemed a code from it and registered a back-channel logout URI,
/// with the facts the token needs. Other clients are not told.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn revoking_a_session_queues_a_logout_token_for_each_client_to_tell() {
    let pool = Database::test_pool().await;
    let account = InsertUser::named("logout");
    UserRepository::from_pool(&pool)
        .insert(&account)
        .await
        .expect("user");
    let (user, session) = (account.id, SessionId::new());
    sqlx::query(
        "INSERT INTO sessions(id,user_id,authentication_methods,authenticated_at,expires_at,last_seen_at)
        VALUES($1,$2,'[\"passkey\"]',now(),now()+interval '1 hour',now())",
    )
    .bind(session.as_uuid())
    .bind(user.as_uuid())
    .execute(&pool)
    .await
    .expect("session");
    // Told; without a URI; and with a URI but no tokens from the session.
    let told = format!("told-{user}");
    let told_uri = "https://told.example/backchannel-logout";
    for (client, uri, redeemed) in [
        (told.clone(), Some(told_uri), true),
        (format!("silent-{user}"), None, true),
        (
            format!("absent-{user}"),
            Some("https://absent.example/logout"),
            false,
        ),
    ] {
        // Each client gets a code from the session, which it redeems as every
        // release does, the previous one included.
        sqlx::query(
            "WITH client AS (
                INSERT INTO oidc_clients(id,display_name,allowed_scopes,allowed_audiences,backchannel_logout_uri)
                VALUES($1,'Logout test','[]','[]',$2) RETURNING id
            )
            INSERT INTO authorization_codes(id,secret_digest,client_id,user_id,session_id,
                redirect_uri,pkce_challenge,scopes,audience,expires_at,authentication)
            SELECT gen_random_uuid(),uuid_send(gen_random_uuid()),id,$3,$4,
                'https://app.example/callback','challenge','[]',id,now()+interval '1 minute','{}'
            FROM client",
        )
        .bind(&client)
        .bind(uri)
        .bind(user.as_uuid())
        .bind(session.as_uuid())
        .execute(&pool)
        .await
        .expect("client and code");
        sqlx::query("UPDATE authorization_codes SET consumed_at=now() WHERE client_id=$1 AND $2")
            .bind(&client)
            .bind(redeemed)
            .execute(&pool)
            .await
            .expect("redeem");
    }
    let revoke = async |commit: bool| {
        let mut tx = DatabaseTransaction::new(pool.begin().await.expect("transaction"));
        let context = EventContext {
            actor: Actor::Anonymous,
            origin: RequestOrigin::default(),
            reason: None,
        };
        let revoked = tx
            .revoke_sessions(
                &context,
                user,
                SessionScope::One(session),
                &RevocationReason::Logout,
            )
            .await
            .expect("revoke");
        assert_eq!(revoked, [session]);
        if commit {
            tx.commit().await.expect("commit");
        }
    };
    let queued = async || -> Vec<(String, Value)> {
        sqlx::query_as(
            "SELECT destination, recipient FROM deliveries
            WHERE channel = $1 AND recipient->>'sid' = $2",
        )
        .bind(BackchannelLogout::NAME)
        .bind(session.to_string())
        .fetch_all(&pool)
        .await
        .expect("deliveries")
    };

    revoke(false).await;
    assert!(
        queued().await.is_empty(),
        "a rolled-back revocation tells no one"
    );
    revoke(true).await;
    assert_eq!(
        queued().await,
        [(
            told_uri.into(),
            serde_json::json!({"client_id": told, "sub": user, "sid": session}),
        )]
    );
}
