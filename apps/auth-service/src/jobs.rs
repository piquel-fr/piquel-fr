//! Background work: periodic jobs coordinated across replicas, and the delivery
//! workers every replica runs (see `crate::deliveries`).

use crate::{
    AuthConfig, KeyStore, SigningKeys, StartupError,
    deliveries::{BackchannelLogoutSender, EmailSender, OutboundClient},
};
use piquel_repository::{Database, DatabaseError, ExclusiveConnection, LockKey};
use piquel_telemetry::{Counter, Histogram};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    task::{JoinError, JoinSet},
    time::{Instant, MissedTickBehavior},
};
use tracing::Instrument;

/// How long running jobs may take to finish after shutdown starts.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// A periodic task that runs on at most one replica at a time. It receives only the
/// locked connection, never the pool, so all its work happens while it holds the lock.
trait ExclusiveJob: Send + Sync + 'static {
    /// Names the job in logs.
    const NAME: &'static str;
    /// Keeps other replicas from running the job at the same time.
    const LOCK: LockKey;
    /// How often each replica tries to run the job.
    const EVERY: Duration;
    /// Why a run failed.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Runs the job once. A long run should stop early once `shutdown` is requested;
    /// otherwise it is cancelled after [`SHUTDOWN_GRACE`].
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
}

/// Every background job of the service, running until [`Self::shutdown`].
pub struct Jobs {
    /// One task per job.
    tasks: JoinSet<()>,
    /// Set to `true` on shutdown.
    shutdown: watch::Sender<bool>,
}

impl Jobs {
    /// Starts every job on `database`: signing key rotation in `store` and the
    /// reloads of this replica's `keys`, and the delivery workers of every
    /// channel, configured by `config`.
    ///
    /// # Errors
    /// Fails if the outbound HTTP client cannot initialize.
    pub fn start(
        database: &Database,
        config: &AuthConfig,
        store: &KeyStore,
        keys: &SigningKeys,
    ) -> Result<Self, StartupError> {
        let mut jobs = Self::new();
        jobs.exclusive(Cleanup, database.clone());
        let (store, reloaded) = (store.clone(), keys.clone());
        jobs.spawn(|shutdown| store.run(reloaded, shutdown));
        let logout = BackchannelLogoutSender::new(
            config.oidc.origin.serialized(),
            keys.clone(),
            OutboundClient::new().map_err(StartupError::Outbound)?,
        );
        jobs.deliveries(logout, database);
        jobs.deliveries(EmailSender::new(database.clone(), &config.email), database);
        Ok(jobs)
    }

    /// A runner without jobs.
    pub(crate) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            shutdown: watch::Sender::new(false),
        }
    }

    /// Stops starting runs, waits up to the `SHUTDOWN_GRACE` period for running ones, then
    /// cancels the rest. Cancelling a job drops its connection, which releases its lock;
    /// cancelling a delivery attempt leaves its lease to expire, so it is sent again.
    ///
    /// # Errors
    /// Returns the first job loop that panicked. Runs that panic are only logged.
    pub async fn shutdown(mut self) -> Result<(), JoinError> {
        self.shutdown.send_replace(true);
        let mut panicked = None;
        let drained =
            tokio::time::timeout(SHUTDOWN_GRACE, Self::drain(&mut self.tasks, &mut panicked)).await;
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
                        tracing::error!(?error, job = J::NAME, "could not take job lock");
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
                    tracing::error!(?error, job = J::NAME, "background job failed");
                }
                if let Err(error) = connection.release().await {
                    tracing::error!(?error, job = J::NAME, "could not release job lock");
                }
            }
            // Unwinding dropped the connection, which releases the lock.
            Some(Err(error)) => tracing::error!(?error, job = J::NAME, "background job panicked"),
            // The set holds exactly one task.
            None => {}
        }
    }
}

/// Rows each cleanup pass deleted or changed.
static CLEANUP_CHANGED: Counter = Counter::new(
    "piquel.auth.cleanup.changed",
    "{row}",
    "Rows cleanup deleted or changed: expired state, personal data past retention and stuck deliveries.",
);
/// How long each cleanup pass took.
static CLEANUP_DURATION: Histogram = Histogram::new(
    "piquel.auth.cleanup.duration",
    "s",
    "Duration of cleanup passes.",
    &[0.01, 0.1, 1.0, 5.0, 15.0, 30.0, 60.0, 90.0],
);
/// Cleanup passes that ran out of budget with rows left.
static CLEANUP_OVERRUNS: Counter = Counter::new(
    "piquel.auth.cleanup.overruns",
    "{pass}",
    "Cleanup passes that stopped at their time budget with rows left to clean.",
);

/// Drains expired authentication state, event personal data and finished
/// deliveries past their retention, and abandons delivery ordering keys stuck
/// behind an old failure, in bounded batches until a pass finds nothing or a
/// one-minute budget runs out.
/// Short pauses between batches keep cleanup from monopolizing the database under
/// heavy churn.
struct Cleanup;

impl Cleanup {
    /// Maximum time spent draining one pass.
    const BUDGET: Duration = Duration::from_mins(1);
    /// Pause between full batches, allowing live requests to use the pool.
    const PAUSE: Duration = Duration::from_millis(100);
    /// Per-table batch bound.
    const BATCH_SIZE: u32 = 1_000;

    /// Runs one batch and returns how many rows it changed. Abandoning stuck keys
    /// needs a transaction of its own, so its locks last until it decides.
    async fn batch(connection: &mut ExclusiveConnection) -> Result<u64, DatabaseError> {
        let mut tx = connection.begin().await?;
        let abandoned = tx.abandon_stuck_deliveries(Self::BATCH_SIZE).await?;
        tx.commit().await?;
        let purged = connection
            .maintenance()
            .purge_expired_auth_state(Self::BATCH_SIZE)
            .await?;
        Ok(abandoned + purged)
    }
}

impl ExclusiveJob for Cleanup {
    const NAME: &'static str = "cleanup";
    const LOCK: LockKey = LockKey::Cleanup;
    const EVERY: Duration = Duration::from_mins(5);
    type Error = DatabaseError;

    /// Stops after the current batch once shutdown is requested.
    async fn run(
        &self,
        connection: &mut ExclusiveConnection,
        shutdown: &Shutdown,
    ) -> Result<(), DatabaseError> {
        let started = Instant::now();
        let deadline = started + Self::BUDGET;
        let mut changed = Self::batch(connection).await?;
        while changed > 0 {
            CLEANUP_CHANGED.add(changed, &());
            if Instant::now() >= deadline {
                CLEANUP_OVERRUNS.add(1, &());
                tracing::warn!("expired authentication state cleanup is falling behind");
                break;
            }
            tokio::select! {
                biased;
                () = shutdown.requested() => break,
                () = tokio::time::sleep(Self::PAUSE) => {}
            }
            changed = Self::batch(connection).await?;
        }
        CLEANUP_DURATION.record(started.elapsed().as_secs_f64(), &());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Job runner failure isolation.
    use super::*;
    use piquel_repository::DatabaseConfig;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Panics on its first run and counts every run.
    struct PanicsOnce(Arc<AtomicU32>);

    impl ExclusiveJob for PanicsOnce {
        const NAME: &'static str = "panics-once";
        const LOCK: LockKey = LockKey::Test;
        const EVERY: Duration = Duration::from_millis(20);
        type Error = DatabaseError;

        fn run(
            &self,
            _: &mut ExclusiveConnection,
            _: &Shutdown,
        ) -> impl Future<Output = Result<(), DatabaseError>> + Send {
            assert_ne!(self.0.fetch_add(1, Ordering::SeqCst), 0, "first run panics");
            std::future::ready(Ok(()))
        }
    }

    /// A run that panics ends only that run: its lock is freed, the job runs again,
    /// and shutdown reports nothing because the job's loop survived.
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn a_panicking_run_releases_its_lock_and_the_job_runs_again() {
        let url = piquel_common::config::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 2, Duration::from_secs(5)).expect("database configuration"),
        )
        .await
        .expect("database");
        let runs = Arc::new(AtomicU32::new(0));
        let mut jobs = Jobs::new();
        jobs.exclusive(PanicsOnce(Arc::clone(&runs)), database);
        tokio::time::timeout(Duration::from_secs(5), async {
            while runs.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the job runs again after panicking");
        jobs.shutdown().await.expect("no job loop panicked");
    }
}
