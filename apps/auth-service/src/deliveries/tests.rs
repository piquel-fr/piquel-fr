//! Retry policy, the HTTP client's safety checks and the worker loop.
use super::outbound::{OutboundClient, Reachable};
use super::*;
use crate::tests::{Replicas, TlsListener};
use axum::{
    Router,
    http::{HeaderMap, HeaderValue, Method, header::RETRY_AFTER},
    response::IntoResponse,
    routing::get,
};
use piquel_common::{DeliveryId, UserId, events::DomainEvent};
use piquel_repository::{DatabaseTransaction, DeliveryStatus, DeliverySummary, NewDelivery};
use std::{marker::PhantomData, net::IpAddr, sync::Mutex};

/// A retryable failure without `Retry-After`.
const UNAVAILABLE: DeliveryError = DeliveryError::Retryable {
    failure: Failure::Status(StatusCode::SERVICE_UNAVAILABLE),
    retry_after: None,
};

/// The outcome of `error` on a delivery's `attempts`th attempt, an hour after its
/// creation, for a channel retrying for a day.
fn outcome(error: DeliveryError, attempts: u64, jitter: f64) -> DeliveryOutcome {
    let created_at = DateTime::UNIX_EPOCH;
    let now = created_at + TimeDelta::hours(1);
    error.outcome(attempts, created_at + TimeDelta::days(1), now, jitter)
}

/// When `outcome` retries, measured from the attempt.
fn delay(outcome: &DeliveryOutcome) -> Option<TimeDelta> {
    match outcome {
        DeliveryOutcome::Retry { at, .. } => Some(*at - DateTime::UNIX_EPOCH - TimeDelta::hours(1)),
        DeliveryOutcome::Succeeded | DeliveryOutcome::Failed { .. } => None,
    }
}

/// Retries wait a random time up to a bound doubling from 10 s to an hour, or
/// longer if `Retry-After` asks; a shorter `Retry-After` does not skip the backoff. Permanent errors, and retries past the channel's
/// maximum age, fail at once.
#[test]
fn retries_back_off_and_honor_retry_after_until_the_maximum_age() {
    let halfway = |attempts| delay(&outcome(UNAVAILABLE, attempts, 0.5));
    assert_eq!(halfway(1), Some(TimeDelta::seconds(5)));
    assert_eq!(halfway(3), Some(TimeDelta::seconds(20)));
    assert_eq!(halfway(10), Some(TimeDelta::minutes(30)));
    assert_eq!(halfway(u64::MAX), Some(TimeDelta::minutes(30)));
    assert_eq!(
        outcome(UNAVAILABLE, 3, 0.0),
        DeliveryOutcome::Retry {
            at: DateTime::UNIX_EPOCH + TimeDelta::hours(1),
            error: "HTTP 503".into(),
        }
    );

    let asked = |seconds| DeliveryError::Retryable {
        failure: Failure::Timeout,
        retry_after: Some(Duration::from_secs(seconds)),
    };
    assert_eq!(
        delay(&outcome(asked(120), 1, 0.5)),
        Some(TimeDelta::seconds(120))
    );
    assert_eq!(
        delay(&outcome(asked(0), 3, 0.5)),
        Some(TimeDelta::seconds(20))
    );
    assert_eq!(
        outcome(asked(24 * 3600), 1, 0.5),
        DeliveryOutcome::Failed {
            error: "timed out".into()
        },
        "past the maximum age"
    );
    assert_eq!(
        outcome(DeliveryError::Permanent(Failure::Redirect), 1, 0.5),
        DeliveryOutcome::Failed {
            error: "redirect refused".into()
        }
    );
    let jitter = DeliveryError::jitter();
    assert!((0.0..1.0).contains(&jitter), "{jitter}");
}

/// Only public addresses are reachable, however they are written.
#[test]
fn only_public_addresses_are_reachable() {
    let allowed = |address: &str| Reachable::Public.allows(address.parse().expect("address"));
    for public in [
        "93.184.215.14",
        "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
        "64:ff9b::5db8:d70e",
        "2002:5db8:d70e::1",
    ] {
        assert!(allowed(public), "{public}");
    }
    for refused in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "::1",
        "::",
        "fd00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::7f00:1",
        "64:ff9b::a00:1",
        "64:ff9b:1::a00:1",
        "2002:a00:1::1",
        "198.18.0.1",
        "240.0.0.1",
    ] {
        assert!(!allowed(refused), "{refused}");
    }
    let loopback: IpAddr = "::1".parse().expect("address");
    assert!(Reachable::PublicOrLoopback.allows(loopback));
}

/// Only 408, 429 and 5xx are retried, after `Retry-After` in seconds or as a date
/// in any HTTP-date format.
#[test]
fn statuses_classify_and_retry_after_parses() {
    let now = DateTime::parse_from_rfc2822("Wed, 21 Oct 2026 07:28:00 GMT")
        .expect("date")
        .with_timezone(&Utc);
    let check = |status: StatusCode, retry_after: Option<&'static str>| {
        let mut headers = HeaderMap::new();
        if let Some(value) = retry_after {
            headers.insert(RETRY_AFTER, HeaderValue::from_static(value));
        }
        OutboundClient::check_status(status, &headers, now)
    };
    let retryable = |status, seconds: Option<u64>| {
        Err(DeliveryError::Retryable {
            failure: Failure::Status(status),
            retry_after: seconds.map(Duration::from_secs),
        })
    };
    assert_eq!(check(StatusCode::NO_CONTENT, None), Ok(()));
    assert_eq!(
        check(StatusCode::TOO_MANY_REQUESTS, Some("120")),
        retryable(StatusCode::TOO_MANY_REQUESTS, Some(120))
    );
    assert_eq!(
        check(
            StatusCode::SERVICE_UNAVAILABLE,
            Some("Wed, 21 Oct 2026 07:30:00 GMT")
        ),
        retryable(StatusCode::SERVICE_UNAVAILABLE, Some(120))
    );
    for obsolete in [
        "Wednesday, 21-Oct-26 07:30:00 GMT",
        "Wed Oct 21 07:30:00 2026",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(obsolete).expect("header"),
        );
        assert_eq!(
            OutboundClient::check_status(StatusCode::SERVICE_UNAVAILABLE, &headers, now),
            retryable(StatusCode::SERVICE_UNAVAILABLE, Some(120)),
            "{obsolete}"
        );
    }
    assert_eq!(
        check(StatusCode::BAD_GATEWAY, Some("soon")),
        retryable(StatusCode::BAD_GATEWAY, None)
    );
    assert_eq!(
        check(StatusCode::REQUEST_TIMEOUT, None),
        retryable(StatusCode::REQUEST_TIMEOUT, None)
    );
    assert_eq!(
        check(StatusCode::BAD_REQUEST, Some("120")),
        Err(DeliveryError::Permanent(Failure::Status(
            StatusCode::BAD_REQUEST
        )))
    );
}

/// Destinations that are not HTTPS, or are or resolve to a loopback address, are
/// refused before anything is sent.
#[tokio::test]
async fn non_public_and_plain_http_destinations_are_refused() {
    let client = OutboundClient::new().expect("client");
    for (destination, failure) in [
        ("https://localhost:9/", Failure::ForbiddenDestination),
        ("https://127.0.0.1:9/", Failure::ForbiddenDestination),
        (
            "https://[::ffff:192.168.0.1]/",
            Failure::ForbiddenDestination,
        ),
        ("http://example.com/", Failure::InvalidDestination),
        ("not a URL", Failure::InvalidDestination),
    ] {
        let result = client
            .send(Method::POST, destination, |request| request)
            .await;
        assert_eq!(
            result.err(),
            Some(DeliveryError::Permanent(failure)),
            "{destination}"
        );
    }
}

/// A redirect is refused rather than followed, a busy receiver's `Retry-After`
/// comes back with its retryable status, and a long body is cut at 64 KiB.
#[tokio::test]
async fn redirects_are_refused() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind receiver");
    let origin = format!(
        "https://localhost:{}",
        tcp.local_addr().expect("address").port()
    );
    let receiver = Router::new()
        .route(
            "/moved",
            get(|| async { axum::response::Redirect::temporary("https://example.com/") }),
        )
        .route(
            "/busy",
            get(|| async {
                (StatusCode::SERVICE_UNAVAILABLE, [(RETRY_AFTER, "30")]).into_response()
            }),
        )
        .route("/ok", get(|| async { vec![b'a'; 100 * 1024] }));
    let client = OutboundClient::local(TlsListener::serve(tcp, receiver));
    let send = async |path: &str| {
        client
            .send(Method::GET, &format!("{origin}{path}"), |request| request)
            .await
            .map(|response| (response.status, response.body.len()))
    };
    assert_eq!(send("/ok").await, Ok((StatusCode::OK, 64 * 1024)));
    assert_eq!(
        send("/moved").await,
        Err(DeliveryError::Permanent(Failure::Redirect))
    );
    assert_eq!(
        send("/busy").await,
        Err(DeliveryError::Retryable {
            failure: Failure::Status(StatusCode::SERVICE_UNAVAILABLE),
            retry_after: Some(Duration::from_secs(30)),
        })
    );
}

/// Declares channels for worker tests, whose deliveries are inserted directly.
/// Tests run at once on one database, so each worker test has its own channel.
macro_rules! worker_channels {
    ($($(#[doc = $doc:literal])* $name:ident = $value:literal;)*) => {$(
        $(#[doc = $doc])*
        struct $name;

        impl Channel for $name {
            const NAME: &'static str = $value;
            /// How [`Recorder`] answers the delivery.
            type Recipient = Behavior;
            type Payload = ();

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

worker_channels! {
    /// Retryable and permanent failures.
    Failing = "test_worker";
    /// An operator retry after a permanent failure.
    Resent = "test_worker_resent";
    /// What an attempt and an idle worker export.
    Traced = "test_worker_traced";
}

/// How [`Recorder`] answers a delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Behavior {
    /// Always retryable, asking to be retried at once.
    Unavailable,
    /// Permanently refused.
    Refused,
    /// Permanently refused on the first attempt, accepted after.
    RefusedOnce,
}

/// Sends channel `C`'s deliveries, keeping the ID each attempt carried.
struct Recorder<C>(Arc<Mutex<Vec<DeliveryId>>>, PhantomData<C>);

impl<C: Channel<Recipient = Behavior, Payload = ()>> Sender for Recorder<C> {
    type Channel = C;
    const MAX_AGE: Duration = Duration::from_hours(1);

    fn send(
        &self,
        delivery: &Delivery<C>,
    ) -> impl Future<Output = Result<(), DeliveryError>> + Send {
        let mut attempts = self.0.lock().expect("attempts");
        let first = !attempts.contains(&delivery.id);
        attempts.push(delivery.id);
        let refused = DeliveryError::Permanent(Failure::Status(StatusCode::FORBIDDEN));
        std::future::ready(match delivery.recipient {
            Behavior::Unavailable => Err(DeliveryError::Retryable {
                failure: Failure::Connection,
                retry_after: Some(Duration::ZERO),
            }),
            Behavior::Refused => Err(refused),
            Behavior::RefusedOnce if first => Err(refused),
            Behavior::RefusedOnce => Ok(()),
        })
    }
}

/// A database with no pending delivery left on `C` by an earlier run, and workers
/// sending `C`, whose attempts are recorded in the returned list.
async fn workers<C: Channel<Recipient = Behavior, Payload = ()>>()
-> (Database, Jobs, Arc<Mutex<Vec<DeliveryId>>>) {
    let database = Replicas::database().await;
    for summary in database
        .deliveries()
        .list(Some(DeliveryStatus::Pending), Some(C::NAME), 1000)
        .await
        .expect("list")
    {
        database
            .deliveries()
            .cancel(summary.id)
            .await
            .expect("clear");
    }
    let attempts = Arc::default();
    let mut jobs = Jobs::new();
    jobs.deliveries(Recorder::<C>(Arc::clone(&attempts), PhantomData), &database);
    (database, jobs, attempts)
}

/// Queues a delivery on `C` that the receiver answers with `behavior`.
async fn queue<C: Channel<Recipient = Behavior, Payload = ()>>(
    database: &Database,
    behavior: Behavior,
) -> DeliveryId {
    let delivery = NewDelivery::<C> {
        destination: "https://receiver.example".into(),
        recipient: behavior,
        payload: (),
        ordering_key: None,
    };
    database
        .deliveries()
        .insert(None, delivery)
        .await
        .expect("insert")
}

/// Polls `C`'s deliveries for up to 10 s until `done` returns `Some`.
async fn wait_for<C: Channel, T>(
    database: &Database,
    done: impl Fn(&[DeliverySummary]) -> Option<T>,
) -> T {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let listed = database
                .deliveries()
                .list(None, Some(C::NAME), 1000)
                .await
                .expect("list");
            if let Some(found) = done(&listed) {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("deliveries reach the expected state")
}

/// The listed delivery `id`, if any.
fn find(listed: &[DeliverySummary], id: DeliveryId) -> Option<DeliverySummary> {
    listed.iter().find(|d| d.id == id).cloned()
}

/// Workers record a retryable failure as a retry, with every attempt carrying
/// the delivery's ID, and fail a permanent one after one attempt.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn workers_retry_retryable_errors_and_fail_permanent_ones() {
    let (database, jobs, attempts) = workers::<Failing>().await;
    let unavailable = queue::<Failing>(&database, Behavior::Unavailable).await;
    let refused = queue::<Failing>(&database, Behavior::Refused).await;
    let (unavailable_summary, refused_summary) = wait_for::<Failing, _>(&database, |listed| {
        let (unavailable, refused) = (find(listed, unavailable)?, find(listed, refused)?);
        (unavailable.last_error.is_some() && refused.status != DeliveryStatus::Pending)
            .then_some((unavailable, refused))
    })
    .await;
    jobs.shutdown().await.expect("no worker panicked");

    assert_eq!(unavailable_summary.status, DeliveryStatus::Pending);
    assert_eq!(
        unavailable_summary.last_error.as_deref(),
        Some("connection failed")
    );
    assert!(
        unavailable_summary.next_attempt_at
            <= Utc::now() + TimeDelta::from_std(MAX_BACKOFF).expect("backoff"),
        "retried within its backoff"
    );
    assert_eq!(
        (refused_summary.status, refused_summary.attempts),
        (DeliveryStatus::Failed, 1)
    );
    assert_eq!(refused_summary.last_error.as_deref(), Some("HTTP 403"));
    let seen = attempts.lock().expect("attempts").clone();
    let count = |id| seen.iter().filter(|&&seen| seen == id).count();
    assert!(count(unavailable) >= 1);
    assert_eq!(
        (count(refused), seen.len()),
        (1, count(unavailable) + 1),
        "every attempt carries its delivery's ID"
    );
}

/// Each attempt is a trace of its own, holding its queries, and an idle worker's
/// polls export nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn each_attempt_is_a_trace_and_idle_polls_export_nothing() {
    let capture = piquel_telemetry::Telemetry::capture(crate::TELEMETRY_FILTER);
    let (database, jobs, _) = workers::<Traced>().await;
    let id = queue::<Traced>(&database, Behavior::Refused).await;
    wait_for::<Traced, _>(&database, |listed| {
        find(listed, id).filter(|d| d.status == DeliveryStatus::Failed)
    })
    .await;
    tokio::time::sleep(POLL_INTERVAL * 2).await;
    jobs.shutdown().await.expect("no worker panicked");

    let spans = capture.spans();
    let names: Vec<_> = spans.iter().map(|span| span.name.as_ref()).collect();
    let attempt = spans
        .iter()
        .find(|span| span.name == Traced::NAME)
        .unwrap_or_else(|| panic!("the attempt's span: {names:?}"));
    let trace = attempt.span_context.trace_id();
    assert!(
        spans
            .iter()
            .all(|span| span.span_context.trace_id() == trace),
        "only the attempt is traced: {names:?}"
    );
    assert!(spans.len() > 1, "the attempt's queries are in its trace");
}

/// A delivery sent again after an operator retry carries the same ID, which
/// receivers deduplicate on as its `jti` or `Message-ID`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_resent_delivery_carries_the_same_id() {
    let (database, jobs, attempts) = workers::<Resent>().await;
    let id = queue::<Resent>(&database, Behavior::RefusedOnce).await;
    wait_for::<Resent, _>(&database, |listed| {
        find(listed, id).filter(|d| d.status == DeliveryStatus::Failed)
    })
    .await;
    database.deliveries().retry(id).await.expect("retry");
    let resent = wait_for::<Resent, _>(&database, |listed| {
        find(listed, id).filter(|d| d.status == DeliveryStatus::Succeeded)
    })
    .await;
    jobs.shutdown().await.expect("no worker panicked");

    assert_eq!(resent.attempts, 2);
    assert_eq!(
        *attempts.lock().expect("attempts"),
        [id, id],
        "both sends carry the delivery's ID"
    );
}
