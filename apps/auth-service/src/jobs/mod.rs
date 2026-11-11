//! Background work: periodic jobs coordinated across replicas, and the delivery
//! workers every replica runs (see `crate::deliveries`).

use crate::{
    AuditKeys, AuthConfig, KeyStore, SigningKeys, StartupError,
    alerts::Alerts,
    audit::{Sealer, Verifier},
    deletion::{DeletionError, Deletions},
    deliveries::{AnnouncementSender, BackchannelLogoutSender, EmailSender, OutboundClient},
};
use chrono::Utc;
use sourceorigin_common::{
    AccountStatus, ErrorChain, UserId,
    alerts::{Alert, AlertKind},
    events::{EventContext, JobName},
};
use sourceorigin_repository::{
    Database, DatabaseError, DatabaseTransaction, ExclusiveConnection, LockKey,
};
use sourceorigin_telemetry::{Counter, Gauge, Histogram};
use std::{
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::watch,
    task::{JoinError, JoinSet},
    time::{Instant, MissedTickBehavior},
};
use tracing::Instrument;

/// A periodic task that runs on at most one replica at a time. It receives only the
/// locked connection, never the pool, so all its work happens while it holds the lock.
pub(crate) trait ExclusiveJob: Send + Sync + 'static {
    /// Names the job in logs.
    const NAME: &'static str;
    /// Keeps other replicas from running the job at the same time.
    const LOCK: LockKey;
    /// How often each replica tries to run the job.
    const EVERY: Duration;
    /// Why a run failed.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Runs the job once. A long run should stop early once `shutdown` is requested;
    /// otherwise it is cancelled after [`Jobs::SHUTDOWN_GRACE`].
    fn run(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: &Shutdown,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Tells running jobs that the service is shutting down.
#[derive(Clone)]
pub(crate) struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// Resolves once shutdown has been requested.
    pub(crate) async fn requested(&self) {
        // An error means the runner is gone, which is a shutdown too.
        let _ = self.0.clone().wait_for(|&requested| requested).await;
    }

    /// Whether shutdown has been requested, without waiting, for work that
    /// checks between steps.
    pub(crate) fn is_requested(&self) -> bool {
        *self.0.borrow()
    }
}

/// Every background job of the service, running until [`Self::shutdown`].
pub struct Jobs {
    /// One task per job.
    tasks: JoinSet<()>,
    /// Set to `true` on shutdown.
    shutdown: watch::Sender<bool>,
}

impl Jobs {
    /// How long running jobs may take to finish once shutdown starts. `serve` gives
    /// open connections the same time, concurrently.
    pub(crate) const SHUTDOWN_GRACE: Duration = Duration::from_secs(6);

    /// Starts every job on `database`: signing key rotation in `store` and the
    /// reloads of this replica's `keys`, audit chain sealing with `config`'s audit
    /// key and its verification, and the delivery workers of every channel,
    /// configured by `config`.
    ///
    /// # Errors
    /// Fails if the committed audit keys are malformed, or the outbound HTTP
    /// client cannot initialize.
    pub fn start(
        database: &Database,
        config: &AuthConfig,
        store: &KeyStore,
        keys: &SigningKeys,
    ) -> Result<Self, StartupError> {
        let mut jobs = Self::new();
        jobs.exclusive(Cleanup::new(), database.clone());
        FAILING_PURGES.observe();
        jobs.exclusive(AccountPurge, database.clone());
        jobs.exclusive(Sealer::new(&config.audit), database.clone());
        let audit_keys = AuditKeys::for_server(&config.passkey.origin, config.audit.verifier())
            .map_err(StartupError::AuditKeys)?;
        Verifier::observe();
        jobs.exclusive(Verifier::new(audit_keys), database.clone());
        let (store, reloaded) = (store.clone(), keys.clone());
        jobs.spawn(|shutdown| store.run(reloaded, shutdown));
        let logout = BackchannelLogoutSender::new(
            config.oidc.origin.serialized(),
            keys.clone(),
            OutboundClient::new().map_err(StartupError::Outbound)?,
        );
        jobs.deliveries(logout, database);
        let email = EmailSender::new(database.clone(), &config.email, config.dashboard.as_ref());
        jobs.deliveries(email, database);
        jobs.deliveries(
            AnnouncementSender::new(database.clone(), &config.email),
            database,
        );
        Ok(jobs)
    }

    /// A runner without jobs.
    pub(crate) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            shutdown: watch::Sender::new(false),
        }
    }

    /// Stops starting runs, waits up to `SHUTDOWN_GRACE` for running ones, then
    /// cancels the rest. Cancelling a job drops its connection, which releases its lock;
    /// cancelling a delivery attempt leaves its lease to expire, so it is sent again.
    ///
    /// # Errors
    /// Returns the first job loop that panicked. Runs that panic are only logged.
    pub async fn shutdown(mut self) -> Result<(), JoinError> {
        self.shutdown.send_replace(true);
        let mut panicked = None;
        let drained = tokio::time::timeout(
            Self::SHUTDOWN_GRACE,
            Self::drain(&mut self.tasks, &mut panicked),
        )
        .await;
        if drained.is_err() {
            tracing::warn!("cancelling background jobs still running after the grace period");
            self.tasks.abort_all();
            Self::drain(&mut self.tasks, &mut panicked).await;
        }
        panicked.map_or(Ok(()), Err)
    }

    /// Waits for every task in `tasks` to end, keeping the first panic in `panicked`.
    /// Cancellations are expected at shutdown and ignored.
    async fn drain(tasks: &mut JoinSet<()>, panicked: &mut Option<JoinError>) {
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result
                && error.is_panic()
            {
                panicked.get_or_insert(error);
            }
        }
    }

    /// Runs the task `start` returns until it ends. It should end soon after the
    /// [`Shutdown`] it receives is requested.
    pub(crate) fn spawn<F>(&mut self, start: impl FnOnce(Shutdown) -> F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tasks.spawn(start(Shutdown(self.shutdown.subscribe())));
    }

    /// Every [`ExclusiveJob::EVERY`], runs `job` if no other replica is running it.
    fn exclusive<J: ExclusiveJob>(&mut self, job: J, database: Database) {
        let job = Arc::new(job);
        self.spawn(|shutdown| async move {
            let mut interval = tokio::time::interval(J::EVERY);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.requested() => return,
                    _ = interval.tick() => {}
                }
                // Dropping a half-opened connection on shutdown releases its lock.
                let connection = tokio::select! {
                    biased;
                    () = shutdown.requested() => return,
                    connection = database.try_exclusive(J::LOCK) => connection,
                };
                match connection {
                    Ok(Some(connection)) => {
                        // Each run is a trace of its own: its queries, the events it
                        // records, and how it ended.
                        let span = tracing::info_span!(
                            parent: None,
                            "job",
                            otel.name = J::NAME,
                            job = J::NAME,
                        );
                        Self::run(Arc::clone(&job), connection, shutdown.clone())
                            .instrument(span)
                            .await;
                    }
                    Ok(None) => tracing::debug!(job = J::NAME, "another replica runs this job"),
                    Err(error) => {
                        tracing::error!(error = %ErrorChain(&error), job = J::NAME, "could not take job lock");
                    }
                }
            }
        });
    }

    /// Runs `job` once on its own task, so a panic ends only this run: the job runs
    /// again at its next interval. The task lives in a set that aborts it when
    /// dropped, so cancelling the caller cancels the run and frees the lock. The
    /// run's task stays in the caller's span.
    async fn run<J: ExclusiveJob>(
        job: Arc<J>,
        mut connection: ExclusiveConnection,
        shutdown: Shutdown,
    ) {
        let mut run = JoinSet::new();
        run.spawn(
            async move {
                let result = job.run(&mut connection, &shutdown).await;
                (connection, result)
            }
            .in_current_span(),
        );
        match run.join_next().await {
            Some(Ok((connection, result))) => {
                if let Err(error) = result {
                    tracing::error!(error = %ErrorChain(&error), job = J::NAME, "background job failed");
                }
                if let Err(error) = connection.release().await {
                    tracing::error!(error = %ErrorChain(&error), job = J::NAME, "could not release job lock");
                }
            }
            // Unwinding dropped the connection, which releases the lock.
            Some(Err(error)) => {
                tracing::error!(error = %ErrorChain(&error), job = J::NAME, "background job panicked");
            }
            // The set holds exactly one task.
            None => {}
        }
    }
}

/// Rows each cleanup pass deleted or changed.
static CLEANUP_CHANGED: Counter = Counter::new(
    "sourceorigin.auth.cleanup.changed",
    "{row}",
    "Rows cleanup deleted or changed: expired state, personal data past retention and finished deliveries.",
);
/// How long each cleanup pass took.
static CLEANUP_DURATION: Histogram = Histogram::new(
    "sourceorigin.auth.cleanup.duration",
    "s",
    "Duration of cleanup passes.",
    &[0.01, 0.1, 1.0, 5.0, 15.0, 30.0, 60.0, 90.0],
);
/// Cleanup passes that ran out of budget with rows left.
static CLEANUP_OVERRUNS: Counter = Counter::new(
    "sourceorigin.auth.cleanup.overruns",
    "{pass}",
    "Cleanup passes that stopped at their time budget with rows left to clean.",
);

/// Drains expired authentication state, event personal data and finished
/// deliveries past their retention, in bounded batches until a pass finds nothing
/// or a one-minute budget runs out.
/// Short pauses between batches keep cleanup from monopolizing the database under
/// heavy churn.
struct Cleanup {
    /// Maximum time spent draining one pass.
    budget: Duration,
    /// Passes in a row on this replica that ran out of time.
    overruns: Streak,
    /// Passes in a row on this replica that failed.
    failures: Streak,
}

impl Cleanup {
    /// Maximum time spent draining one pass in production.
    const BUDGET: Duration = Duration::from_mins(1);
    /// Passes in a row that run out of time before the [`Alert::CleanupBehind`]
    /// alert is raised: the next pass picks up what one leaves, so a single
    /// burst is no problem.
    const BEHIND_AFTER: u32 = 3;
    /// Passes in a row that fail before the [`Alert::CleanupFailing`] alert is
    /// raised: a single one may be the database's passing failure.
    const FAILING_AFTER: u32 = 3;

    /// Pause between full batches, allowing live requests to use the pool.
    const PAUSE: Duration = Duration::from_millis(100);
    /// Per-table batch bound.
    const BATCH_SIZE: u32 = 1_000;

    /// Cleanup with the production budget.
    const fn new() -> Self {
        Self {
            budget: Self::BUDGET,
            overruns: Streak::new(Self::BEHIND_AFTER),
            failures: Streak::new(Self::FAILING_AFTER),
        }
    }

    /// Drains one pass, until it finds nothing, runs out of time or shutdown is
    /// requested. Returns whether it ran out of time, or `None` when shutdown
    /// stopped it.
    async fn drain(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: &Shutdown,
    ) -> Result<Option<bool>, DatabaseError> {
        let started = Instant::now();
        let deadline = started + self.budget;
        let mut behind = Some(false);
        let mut changed = Self::batch(connection).await?;
        while changed > 0 {
            CLEANUP_CHANGED.add(changed, &());
            if Instant::now() >= deadline {
                CLEANUP_OVERRUNS.add(1, &());
                tracing::warn!("expired authentication state cleanup is falling behind");
                behind = Some(true);
                break;
            }
            tokio::select! {
                biased;
                () = shutdown.requested() => {
                    behind = None;
                    break;
                },
                () = tokio::time::sleep(Self::PAUSE) => {}
            }
            changed = Self::batch(connection).await?;
        }
        CLEANUP_DURATION.record(started.elapsed().as_secs_f64(), &());
        Ok(behind)
    }

    /// Changes the alerts after a pass that ended with `drained`, and returns
    /// how it ended. The [`Self::FAILING_AFTER`]th pass in a row that fails
    /// raises [`Alert::CleanupFailing`], and one that works clears it. The
    /// [`Self::BEHIND_AFTER`]th in a row that runs out of time raises
    /// [`Alert::CleanupBehind`], and one that deletes everything due clears it. A
    /// pass that shutdown stopped changes neither.
    async fn ended(
        &self,
        connection: &mut ExclusiveConnection,
        drained: Result<Option<bool>, DatabaseError>,
    ) -> Result<(), DatabaseError> {
        let behind = match drained {
            Ok(Some(behind)) => behind,
            Ok(None) => return Ok(()),
            Err(error) => {
                let alert = Alert::CleanupFailing {};
                self.failures
                    .failed(connection, JobName::Cleanup, alert)
                    .await;
                return Err(error);
            }
        };
        // The pass counts before anything that may fail: its alerts change in a
        // transaction that may not commit, and the streaks must still see it.
        self.failures.reset();
        let due = if behind {
            self.overruns.extend()
        } else {
            self.overruns.reset();
            None
        };
        let mut tx = connection.begin().await?;
        let context = EventContext::system(JobName::Cleanup);
        let mut alerts = Alerts::new(&mut tx, &context);
        alerts.clear(AlertKind::CleanupFailing).await?;
        let mut holds = None;
        if let Some(due) = due {
            holds = Some(due.apply(&mut alerts, Alert::CleanupBehind {}).await?);
        } else if !behind {
            alerts.clear(AlertKind::CleanupBehind).await?;
        }
        tx.commit().await?;
        if let Some(holds) = holds {
            self.overruns.settle(holds);
        }
        Ok(())
    }

    /// Runs one batch and returns how many rows it deleted.
    async fn batch(connection: &mut ExclusiveConnection) -> Result<u64, DatabaseError> {
        connection
            .maintenance()
            .purge_expired_auth_state(Self::BATCH_SIZE)
            .await
    }
}

impl ExclusiveJob for Cleanup {
    const NAME: &'static str = "cleanup";
    const LOCK: LockKey = LockKey::Cleanup;
    const EVERY: Duration = Duration::from_mins(5);
    type Error = DatabaseError;

    /// Stops after the current batch once shutdown is requested. Raises and
    /// clears its alerts as [`Self::ended`] says.
    async fn run(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: &Shutdown,
    ) -> Result<(), DatabaseError> {
        let drained = self.drain(connection, shutdown).await;
        self.ended(connection, drained).await
    }
}

/// What a streak long enough calls for after another run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Due {
    /// Raising its alert.
    Raise,
    /// Marking the alert it raised seen, while that is current.
    Seen,
}

impl Due {
    /// Raises `alert` in `alerts`, or marks it seen, as due, and says whether it
    /// holds as raised: `false` when it was no longer current to be seen, as it
    /// cleared meanwhile, such as by another replica's run or an operator's
    /// verification.
    async fn apply(self, alerts: &mut Alerts<'_, '_>, alert: Alert) -> Result<bool, DatabaseError> {
        match self {
            Self::Raise => alerts.raise(alert).await.map(|()| true),
            Self::Seen => alerts.seen(&alert).await,
        }
    }
}

/// Runs in a row on this replica that ended one way, such as cleanup passes that
/// ran out of time, which raise an alert once there are enough of them. A job's
/// lock may move between replicas, so it counts this replica's runs only, and a
/// count lasts until this replica's next run. A streak raises its alert once,
/// then only marks it seen while it is current. Once it clears meanwhile, such
/// as by another replica's run or an operator's verification, the run that
/// found it cleared starts a new streak, so it takes as many runs again to raise
/// it, and email every administrator, again.
pub(crate) struct Streak {
    /// Runs in the streak so far.
    runs: AtomicU32,
    /// Runs in a row that raise the alert.
    alert_after: u32,
    /// Whether this streak raised its alert.
    raised: AtomicBool,
}

impl Streak {
    /// A streak that raises its alert after `alert_after` runs in a row.
    pub(crate) const fn new(alert_after: u32) -> Self {
        Self {
            runs: AtomicU32::new(0),
            alert_after,
            raised: AtomicBool::new(false),
        }
    }

    /// Counts one more run, and says what it calls for once the streak is long
    /// enough: raising the alert, until it was raised, then marking it seen.
    fn extend(&self) -> Option<Due> {
        if self.runs.fetch_add(1, Ordering::Relaxed) + 1 < self.alert_after {
            None
        } else if self.raised.load(Ordering::Relaxed) {
            Some(Due::Seen)
        } else {
            Some(Due::Raise)
        }
    }

    /// Settles a run whose alert was raised or seen, once that committed: the
    /// streak goes on while the alert `holds`, and once it cleared, this run
    /// starts a new one.
    fn settle(&self, holds: bool) {
        if !holds {
            self.runs.store(1, Ordering::Relaxed);
        }
        self.raised.store(holds, Ordering::Relaxed);
    }

    /// Ends the streak.
    pub(crate) fn reset(&self) {
        self.runs.store(0, Ordering::Relaxed);
        self.raised.store(false, Ordering::Relaxed);
    }

    /// Counts a run of `job` that failed, and raises `alert` on `connection`
    /// once enough failed in a row, or marks it seen once raised. Raising may
    /// fail as the run did, such as while the database is down: that is logged,
    /// since the run returns its own failure.
    pub(crate) async fn failed(
        &self,
        connection: &mut ExclusiveConnection,
        job: JobName,
        alert: Alert,
    ) {
        let Some(due) = self.extend() else {
            return;
        };
        let context = EventContext::system(job);
        let applied = async {
            let mut tx = connection.begin().await?;
            let holds = due
                .apply(&mut Alerts::new(&mut tx, &context), alert)
                .await?;
            tx.commit().await?;
            Ok::<_, DatabaseError>(holds)
        };
        match applied.await {
            Ok(holds) => self.settle(holds),
            Err(error) => {
                let error = ErrorChain(&error);
                tracing::error!(%error, ?job, "could not raise the alert of a failing job");
            }
        }
    }
}

/// A count the replica running a periodic job takes after each run, which its
/// gauge reports. Every replica runs the job in turn, so each reports the count
/// of its own latest run, at most one run older than the newest; one whose count
/// is older than two runs, because it stopped running the job, reports none.
/// Alerts read the minimum across replicas, or wait one run, before taking a
/// count as current.
pub(crate) struct JobCount {
    /// The gauge reporting it.
    gauge: Gauge,
    /// How often the job runs.
    every: Duration,
    /// The latest count on this replica, and when it was taken.
    counted: Mutex<Option<(u64, Instant)>>,
}

impl JobCount {
    /// A count `gauge` reports, of a job that runs `every` so often.
    pub(crate) const fn new(gauge: Gauge, every: Duration) -> Self {
        Self {
            gauge,
            every,
            counted: Mutex::new(None),
        }
    }

    /// Registers the gauge.
    pub(crate) fn observe(&'static self) {
        self.gauge.observe(|| {
            let counted = *self.counted.lock().unwrap_or_else(PoisonError::into_inner);
            counted
                .filter(|(_, at)| at.elapsed() < self.every * 2)
                .map(|(count, _)| (count, ()))
        });
    }

    /// Keeps `count`, taken now.
    pub(crate) fn set(&self, count: u64) {
        *self.counted.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((count, Instant::now()));
    }
}

/// Accounts whose purge keeps failing, counted after each purge run.
static FAILING_PURGES: JobCount = JobCount::new(
    Gauge::new(
        "sourceorigin.auth.account_purge.failing",
        "{account}",
        "Accounts scheduled for deletion whose purge failed at least 3 times in a row.",
    ),
    AccountPurge::EVERY,
);

/// Purges the accounts whose deletion grace period ended, each in a transaction of
/// its own, attributed to [`JobName::AccountPurge`]. One run purges at most
/// [`Self::BATCH_SIZE`] accounts; the next run continues. A failed purge is
/// recorded with its error and retried after a backoff, so accounts that keep
/// failing never hold back the others, and [`FAILING_PURGES`] counts them.
pub(crate) struct AccountPurge;

impl AccountPurge {
    /// Accounts one run purges at most.
    const BATCH_SIZE: u32 = 100;
    /// The delay after a first failure, doubled after each further one.
    const BACKOFF: chrono::Duration = chrono::Duration::minutes(5);
    /// The longest delay between attempts.
    const MAX_BACKOFF: chrono::Duration = chrono::Duration::days(1);
    /// Failures in a row after which [`FAILING_PURGES`] counts an account.
    const FAILING_ATTEMPTS: u16 = 3;

    /// Purges `user_id` in `tx` if it is still scheduled for deletion and due,
    /// rechecked under the account lock, since it may have been restored meanwhile.
    pub(crate) async fn purge(
        mut tx: DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<(), DeletionError> {
        let user = Deletions::lock(&mut tx, user_id).await?;
        let due = tx
            .deletions()
            .find(user_id)
            .await?
            .is_some_and(|deletion| deletion.purge_after <= Utc::now());
        if user.status != AccountStatus::Deleting || !due {
            return Ok(());
        }
        Deletions::new(&mut tx, EventContext::system(JobName::AccountPurge))
            .purge(&user)
            .await?;
        Ok(tx.commit().await?)
    }
}

impl ExclusiveJob for AccountPurge {
    const NAME: &'static str = "account-purge";
    const LOCK: LockKey = LockKey::AccountPurge;
    const EVERY: Duration = Duration::from_mins(5);
    type Error = DeletionError;

    /// Stops after the current account once shutdown is requested. A failing
    /// account is logged and recorded, which delays its next attempt, so it cannot
    /// hold back the others. Then counts the accounts that keep failing, which
    /// raise the [`Alert::PurgesFailing`] alert, or clear it once there are none.
    async fn run(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: &Shutdown,
    ) -> Result<(), DeletionError> {
        for user_id in connection.deletions().due(Self::BATCH_SIZE).await? {
            if shutdown.is_requested() {
                break;
            }
            let tx = connection.begin().await?;
            if let Err(error) = Self::purge(tx, user_id).await {
                tracing::error!(error = %ErrorChain(&error), %user_id, "could not purge account");
                let message = ErrorChain(&error).to_string();
                connection
                    .deletions()
                    .record_failure(user_id, &message, Self::BACKOFF, Self::MAX_BACKOFF)
                    .await?;
            }
        }
        let failing = connection
            .deletions()
            .count_failing(Self::FAILING_ATTEMPTS)
            .await?;
        FAILING_PURGES.set(failing);
        let mut tx = connection.begin().await?;
        let context = EventContext::system(JobName::AccountPurge);
        let mut alerts = Alerts::new(&mut tx, &context);
        match failing {
            0 => alerts.clear(AlertKind::PurgesFailing).await,
            _ => alerts.raise(Alert::PurgesFailing {}).await,
        }?;
        Ok(tx.commit().await?)
    }
}

#[cfg(test)]
mod tests;
