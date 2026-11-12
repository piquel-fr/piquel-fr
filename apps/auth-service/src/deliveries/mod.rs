//! Sends the outbound delivery queue: every replica runs a few workers per channel.
//!
//! The repository creates deliveries in the transaction of the event that causes
//! them. A worker claims one with a lease, sends it outside any transaction, and
//! records the outcome while it still holds the lease. Delivery is at least once:
//! a worker that stops after sending but before recording lets its lease expire,
//! and the delivery is sent again. Workers count each attempt's outcome, and every
//! replica measures each channel's backlog for the queue's gauges. See
//! `docs/dev/architecture/delivery-queue.md`.

/// Back-channel logout tokens, [`BackchannelLogoutSender`].
mod backchannel;
/// Account holders' email, announcements' email and invitations' email, sent
/// over SMTP, [`EmailSender`], [`AnnouncementSender`] and [`InvitationSender`].
mod email;
/// The HTTP client for destinations third parties supply, [`OutboundClient`].
mod outbound;
/// Retry policy, the HTTP client's safety checks and the worker loop.
#[cfg(test)]
mod tests;

pub(crate) use backchannel::BackchannelLogoutSender;
pub(crate) use email::{AnnouncementSender, EmailSender, InvitationSender};
pub(crate) use outbound::OutboundClient;

use crate::jobs::{Jobs, Shutdown};
use axum::http::StatusCode;
use chrono::{DateTime, TimeDelta, Utc};
use sourceorigin_common::ErrorChain;
use sourceorigin_repository::{
    Channel, Database, DatabaseError, Delivery, DeliveryBacklog, DeliveryOutcome,
};
use sourceorigin_telemetry::{Counter, Gauge, Label};
use std::{
    collections::BTreeMap,
    hash::{BuildHasher, RandomState},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};
use thiserror::Error;
use tokio::{task::JoinSet, time::MissedTickBehavior};
use tracing::Instrument;

/// The longest one send may take, connecting and reading the response included.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an idle worker waits before looking for due deliveries again.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Workers per channel on each replica.
const WORKERS: usize = 2;
/// The bound on the first retry's delay, doubling with each further attempt.
const FIRST_BACKOFF: Duration = Duration::from_secs(10);
/// The most any retry waits, unless the receiver asks for longer with `Retry-After`.
const MAX_BACKOFF: Duration = Duration::from_hours(1);

/// How often each replica counts each channel's pending deliveries.
const BACKLOG_EVERY: Duration = Duration::from_secs(30);

/// Attempts by channel and outcome, counted where the worker records the outcome.
static ATTEMPTS: Counter<[Label; 2]> = Counter::new(
    "sourceorigin.auth.deliveries.attempts",
    "{attempt}",
    "Delivery attempts, by channel and outcome: succeeded, retried, failed, or lease_lost when the outcome was discarded.",
);
/// Pending deliveries per channel, from [`BACKLOGS`].
static PENDING: Gauge<[Label; 1]> = Gauge::new(
    "sourceorigin.auth.deliveries.pending",
    "{delivery}",
    "Deliveries waiting for an attempt or being attempted, by channel.",
);
/// How long each channel's oldest pending delivery has waited, from [`BACKLOGS`].
static OLDEST_PENDING_AGE: Gauge<[Label; 1]> = Gauge::new(
    "sourceorigin.auth.deliveries.oldest_pending_age",
    "s",
    "Time since the oldest pending delivery was created or retried by an operator, by channel.",
);
/// This replica's latest backlog counts.
static BACKLOGS: Backlogs = Backlogs(Mutex::new(BTreeMap::new()));

/// How one channel's deliveries are sent, e.g. as a signed logout token posted to
/// each client's back-channel logout URI.
pub(crate) trait Sender: Send + Sync + 'static {
    /// The channel sent, which defines what its deliveries hold.
    type Channel: Channel;
    /// How long after its creation, or an operator's last retry, a delivery keeps
    /// being retried. A retryable failure that would retry later than this fails it
    /// instead, and so does a delivery no release could decode by then.
    const MAX_AGE: Duration;
    /// How long a worker holds a claimed delivery: well beyond [`SEND_TIMEOUT`].
    /// Tests shorten it to see another replica take over a stalled attempt.
    const LEASE: Duration = Duration::from_mins(1);

    /// Attempts to send `delivery`. Every attempt carries the same
    /// [`Delivery::id`], so the receiver can recognize a repeat. Uses
    /// [`outbound::OutboundClient`] for HTTP, and finishes within [`SEND_TIMEOUT`].
    fn send(
        &self,
        delivery: &Delivery<Self::Channel>,
    ) -> impl Future<Output = Result<(), DeliveryError>> + Send;
}

/// Why an attempt failed, and whether another attempt may succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum DeliveryError {
    /// Another attempt may succeed, e.g. after a timeout or an HTTP 503.
    #[error("{failure}, retryable")]
    Retryable {
        /// What went wrong.
        failure: Failure,
        /// How long the receiver asked us to wait, from `Retry-After`.
        retry_after: Option<Duration>,
    },
    /// Another attempt would fail the same way, e.g. after an HTTP 400.
    #[error("{0}")]
    Permanent(Failure),
}

/// What went wrong in an attempt. Its text is the delivery's `last_error`, so it
/// holds a status code or a kind, never anything the receiver sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum Failure {
    /// The receiver answered with an unsuccessful status.
    #[error("HTTP {}", .0.as_u16())]
    Status(StatusCode),
    /// The receiver answered with a redirect, which is never followed.
    #[error("redirect refused")]
    Redirect,
    /// The destination is not an HTTPS URL.
    #[error("invalid destination")]
    InvalidDestination,
    /// The destination is, or resolves to, a loopback, private, link-local or
    /// otherwise non-public address.
    #[error("non-public destination address")]
    ForbiddenDestination,
    /// The destination's name did not resolve.
    #[error("DNS resolution failed")]
    Resolution,
    /// No connection could be made, or it broke.
    #[error("connection failed")]
    Connection,
    /// The attempt took longer than its timeout.
    #[error("timed out")]
    Timeout,
    /// The delivery was still unsent at its channel's maximum age, so it was not
    /// attempted again.
    #[error("maximum age exceeded")]
    Expired,
    /// The message could not be signed.
    #[error("signing failed")]
    Signing,
    /// The SMTP relay answered with an unsuccessful reply code.
    #[error("SMTP {0}")]
    Smtp(u16),
    /// The stored address is not one the SMTP client can send to.
    #[error("invalid recipient address")]
    InvalidAddress,
    /// The message could not be rendered or built.
    #[error("message could not be built")]
    Message,
    /// The recipient could not be read from the database.
    #[error("recipient lookup failed")]
    Database,
}

impl DeliveryError {
    /// What to record for a delivery's `attempts`th attempt, which failed with
    /// this error at `now`. A retry later than `expires` fails it instead.
    /// `jitter`, in `[0, 1)`, scales the backoff: a retry waits a random time up to
    /// the bound, which doubles from [`FIRST_BACKOFF`] to [`MAX_BACKOFF`] ("full
    /// jitter"), or longer if the receiver's `Retry-After` asks. `Retry-After` is
    /// only a minimum, so a receiver cannot ask for retries without backoff.
    fn outcome(
        self,
        attempts: u64,
        expires: DateTime<Utc>,
        now: DateTime<Utc>,
        jitter: f64,
    ) -> DeliveryOutcome {
        let (failure, retry_after) = match self {
            Self::Retryable {
                failure,
                retry_after,
            } => (failure, retry_after),
            Self::Permanent(failure) => {
                return DeliveryOutcome::Failed {
                    error: failure.to_string(),
                };
            }
        };
        let doublings = u32::try_from(attempts.saturating_sub(1)).unwrap_or(u32::MAX);
        let bound = FIRST_BACKOFF
            .saturating_mul(2_u32.saturating_pow(doublings))
            .min(MAX_BACKOFF);
        let backoff = bound.mul_f64(jitter);
        let delay = retry_after.map_or(backoff, |asked| asked.max(backoff));
        let at = TimeDelta::from_std(delay)
            .ok()
            .and_then(|delay| now.checked_add_signed(delay));
        match at {
            Some(at) if at <= expires => DeliveryOutcome::Retry {
                at,
                error: failure.to_string(),
            },
            _ => DeliveryOutcome::Failed {
                error: failure.to_string(),
            },
        }
    }

    /// A uniformly distributed fraction in `[0, 1)` to spread retries out. Not for
    /// secrets: each `RandomState` hashes with fresh keys, which is random enough.
    fn jitter() -> f64 {
        // The top 53 bits fill an `f64` mantissa exactly.
        #[expect(
            clippy::cast_precision_loss,
            reason = "A 53-bit integer converts to f64 exactly."
        )]
        let fraction = (RandomState::new().hash_one(()) >> 11) as f64 / (1_u64 << 53) as f64;
        fraction
    }
}

/// One of a channel's workers on this replica.
struct Worker<S: Sender> {
    /// Sends the channel's deliveries; shared by the channel's workers.
    sender: Arc<S>,
    /// Where deliveries are claimed and their outcomes recorded.
    database: Database,
}

impl Jobs {
    /// Starts [`WORKERS`] workers sending `sender`'s channel on this replica, and
    /// the count of its pending deliveries for the backlog gauges. The workers stop
    /// claiming once shutdown is requested, and finish the attempt in progress.
    pub(crate) fn deliveries<S: Sender>(&mut self, sender: S, database: &Database) {
        let sender = Arc::new(sender);
        for _ in 0..WORKERS {
            let worker = Worker {
                sender: Arc::clone(&sender),
                database: database.clone(),
            };
            self.spawn(|shutdown| worker.run(shutdown));
        }
        BACKLOGS.observe();
        let database = database.clone();
        self.spawn(|shutdown| BACKLOGS.count::<S::Channel>(database, shutdown));
    }
}

impl<S: Sender> Worker<S> {
    /// Claims and attempts deliveries until shutdown, polling every
    /// [`POLL_INTERVAL`] while none is due.
    async fn run(self, shutdown: Shutdown) {
        loop {
            let mut deliveries = self.database.deliveries();
            let claimed = tokio::select! {
                biased;
                () = shutdown.requested() => return,
                claimed = deliveries.claim::<S::Channel>(S::LEASE, S::MAX_AGE) => claimed,
            };
            match claimed {
                Ok(Some(delivery)) => {
                    self.attempt(delivery).await;
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::error!(
                        error = %ErrorChain(&error),
                        channel = S::Channel::NAME,
                        "could not claim delivery"
                    );
                }
            }
            tokio::select! {
                biased;
                () = shutdown.requested() => return,
                () = tokio::time::sleep(POLL_INTERVAL) => {}
            }
        }
    }

    /// Sends `delivery` once and records the outcome. The attempt runs on its own
    /// task, so a panic ends only the attempt: its lease expires and it is retried.
    /// Each attempt is a trace of its own: its send, its queries and its outcome.
    async fn attempt(&self, delivery: Delivery<S::Channel>) {
        let span = tracing::info_span!(
            parent: None,
            "delivery",
            otel.name = S::Channel::NAME,
            channel = S::Channel::NAME,
            delivery.id = %delivery.id,
        );
        let mut attempt = JoinSet::new();
        attempt.spawn(
            Self::send(Arc::clone(&self.sender), self.database.clone(), delivery).instrument(span),
        );
        if let Some(Err(error)) = attempt.join_next().await {
            tracing::error!(
                error = %ErrorChain(&error),
                channel = S::Channel::NAME,
                "delivery attempt panicked"
            );
        }
    }

    /// Sends `delivery` within [`SEND_TIMEOUT`], unless it expired while it waited,
    /// and records the outcome, which is discarded if the lease was lost meanwhile.
    async fn send(sender: Arc<S>, database: Database, delivery: Delivery<S::Channel>) {
        let expires = delivery.expires_at;
        let result = if Utc::now() > expires {
            Err(DeliveryError::Permanent(Failure::Expired))
        } else {
            tokio::time::timeout(SEND_TIMEOUT, sender.send(&delivery))
                .await
                .unwrap_or(Err(DeliveryError::Retryable {
                    failure: Failure::Timeout,
                    retry_after: None,
                }))
        };
        let outcome = match result {
            Ok(()) => DeliveryOutcome::Succeeded,
            Err(error) => error.outcome(
                delivery.attempts,
                expires,
                Utc::now(),
                DeliveryError::jitter(),
            ),
        };
        let (id, channel) = (delivery.id, S::Channel::NAME);
        let counted = match database.deliveries().finish(&delivery, &outcome).await {
            Ok(()) => match outcome {
                DeliveryOutcome::Succeeded => {
                    tracing::debug!(%id, channel, "delivery succeeded");
                    "succeeded"
                }
                DeliveryOutcome::Retry { at, error } => {
                    tracing::warn!(%id, channel, %at, error, "delivery will be retried");
                    "retried"
                }
                DeliveryOutcome::Failed { error } => {
                    tracing::error!(%id, channel, error, "delivery failed");
                    "failed"
                }
            },
            Err(DatabaseError::NotFound) => {
                tracing::warn!(%id, channel, "delivery lease lost; outcome discarded");
                "lease_lost"
            }
            Err(error) => {
                tracing::error!(error = %ErrorChain(&error), %id, channel, "could not record delivery outcome");
                return;
            }
        };
        ATTEMPTS.add(1, &[("channel", channel), ("outcome", counted)]);
    }
}

/// Every channel's pending deliveries at its latest count, which the backlog
/// gauges report. Every replica counts, so each reports the same backlog.
struct Backlogs(Mutex<BTreeMap<&'static str, DeliveryBacklog>>);

impl Backlogs {
    /// Registers the backlog gauges. Only the first call registers.
    fn observe(&'static self) {
        PENDING.observe(|| {
            self.lock()
                .iter()
                .map(|(&channel, backlog)| (backlog.pending, [("channel", channel)]))
                .collect::<Vec<_>>()
        });
        OLDEST_PENDING_AGE.observe(|| {
            let now = Utc::now();
            self.lock()
                .iter()
                .map(|(&channel, backlog)| {
                    let age = backlog.oldest.map_or(0, |oldest| {
                        u64::try_from((now - oldest).num_seconds()).unwrap_or(0)
                    });
                    (age, [("channel", channel)])
                })
                .collect::<Vec<_>>()
        });
    }

    /// Counts `C`'s pending deliveries every [`BACKLOG_EVERY`] until shutdown. A
    /// failed count drops the channel's backlog, so the gauges never report a
    /// stale one.
    async fn count<C: Channel>(&self, database: Database, shutdown: Shutdown) {
        let mut interval = tokio::time::interval(BACKLOG_EVERY);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = shutdown.requested() => return,
                _ = interval.tick() => {}
            }
            let mut deliveries = database.deliveries();
            let counted = tokio::select! {
                biased;
                () = shutdown.requested() => return,
                counted = deliveries.backlog::<C>() => counted,
            };
            match counted {
                Ok(backlog) => {
                    self.lock().insert(C::NAME, backlog);
                }
                Err(error) => {
                    self.lock().remove(C::NAME);
                    tracing::error!(
                        error = %ErrorChain(&error),
                        channel = C::NAME,
                        "could not count pending deliveries"
                    );
                }
            }
        }
    }

    /// The latest counts. A panic while they were held cannot leave them half
    /// written, so a poisoned lock is still read.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<&'static str, DeliveryBacklog>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
