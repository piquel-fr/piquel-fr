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
use piquel_auth_protocol::{DeliveryId, UserId};
use piquel_repository::{DatabaseTransaction, DeliveryStatus, DomainEvent, NewDelivery};
use std::{net::IpAddr, sync::Mutex};

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

/// Retries wait a random time up to a bound doubling from 10 s to an hour, or as
/// long as `Retry-After` says. Permanent errors, and retries past the channel's
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

/// The worker test's channel; its deliveries are inserted directly.
struct Recorded;

impl Channel for Recorded {
    const NAME: &'static str = "test_worker";
    /// Which behavior [`Recorder`] shows for the delivery.
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

/// How [`Recorder`] answers a delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Behavior {
    /// Retryable at once on the first attempt, then accepted.
    Flaky,
    /// Permanently refused.
    Refused,
}

/// Sends [`Recorded`] deliveries, keeping the ID each attempt carried.
#[derive(Default)]
struct Recorder(Arc<Mutex<Vec<DeliveryId>>>);

impl Sender for Recorder {
    type Channel = Recorded;
    const MAX_AGE: Duration = Duration::from_hours(1);

    fn send(
        &self,
        delivery: &Delivery<Recorded>,
    ) -> impl Future<Output = Result<(), DeliveryError>> + Send {
        let mut attempts = self.0.lock().expect("attempts");
        attempts.push(delivery.id);
        let first = attempts.iter().filter(|&&id| id == delivery.id).count() == 1;
        std::future::ready(match delivery.recipient {
            Behavior::Flaky if first => Err(DeliveryError::Retryable {
                failure: Failure::Connection,
                retry_after: Some(Duration::ZERO),
            }),
            Behavior::Flaky => Ok(()),
            Behavior::Refused => Err(DeliveryError::Permanent(Failure::Status(
                StatusCode::FORBIDDEN,
            ))),
        })
    }
}

/// Workers retry a retryable failure with the same delivery ID until it succeeds,
/// and fail a permanent one after one attempt.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn workers_retry_with_the_same_id_and_fail_permanent_errors() {
    let database = Replicas::database().await;
    for summary in database
        .deliveries()
        .list(Some(DeliveryStatus::Pending), Some(Recorded::NAME), 1000)
        .await
        .expect("list")
    {
        database
            .deliveries()
            .cancel(summary.id)
            .await
            .expect("clear");
    }
    let insert = async |behavior| {
        let delivery = NewDelivery::<Recorded> {
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
    };
    let flaky = insert(Behavior::Flaky).await;
    let refused = insert(Behavior::Refused).await;

    let recorder = Recorder::default();
    let attempts = Arc::clone(&recorder.0);
    let mut jobs = Jobs::new();
    jobs.deliveries(recorder, &database);
    let finished = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let listed = database
                .deliveries()
                .list(None, Some(Recorded::NAME), 1000)
                .await
                .expect("list");
            let status = |id| {
                listed
                    .iter()
                    .find(|d| d.id == id)
                    .map(|d| (d.status, d.attempts))
            };
            if [status(flaky), status(refused)]
                .iter()
                .all(|s| s.is_some_and(|(status, _)| status != DeliveryStatus::Pending))
            {
                break (status(flaky), status(refused), listed);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("both deliveries finish");
    jobs.shutdown().await.expect("no worker panicked");

    let (flaky_status, refused_status, listed) = finished;
    assert_eq!(flaky_status, Some((DeliveryStatus::Succeeded, 2)));
    assert_eq!(refused_status, Some((DeliveryStatus::Failed, 1)));
    let last_error = |id| {
        listed
            .iter()
            .find(|d| d.id == id)
            .and_then(|d| d.last_error.clone())
    };
    assert_eq!(last_error(flaky).as_deref(), Some("connection failed"));
    assert_eq!(last_error(refused).as_deref(), Some("HTTP 403"));
    let seen = attempts.lock().expect("attempts").clone();
    let count = |id| seen.iter().filter(|&&seen| seen == id).count();
    assert_eq!(
        (count(flaky), count(refused), seen.len()),
        (2, 1, 3),
        "retries reuse the delivery ID"
    );
}
