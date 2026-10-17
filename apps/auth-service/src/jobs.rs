//! Periodic background work, coordinated across replicas.

use piquel_repository::{Database, DatabaseError, ExclusiveConnection, LockKey};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    task::{JoinError, JoinSet},
    time::{Instant, MissedTickBehavior},
};

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
struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// Resolves once shutdown has been requested.
    async fn requested(&self) {
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
    /// Starts every job on `database`.
    #[must_use]
    pub fn start(database: &Database) -> Self {
        let mut jobs = Self::new();
        jobs.exclusive(Cleanup, database.clone());
        jobs
    }

    /// A runner without jobs.
    fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            shutdown: watch::Sender::new(false),
        }
    }

    /// Stops starting runs, waits up to [`SHUTDOWN_GRACE`] for running ones, then
    /// cancels the rest. Cancelling a job drops its connection, which releases its lock.
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

    /// Every [`ExclusiveJob::EVERY`], runs `job` if no other replica is running it.
    fn exclusive<J: ExclusiveJob>(&mut self, job: J, database: Database) {
        let shutdown = Shutdown(self.shutdown.subscribe());
        let job = Arc::new(job);
        self.tasks.spawn(async move {
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
                        Self::run(Arc::clone(&job), connection, shutdown.clone()).await;
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
    /// dropped, so cancelling the caller cancels the run and frees the lock.
    async fn run<J: ExclusiveJob>(
        job: Arc<J>,
        mut connection: ExclusiveConnection,
        shutdown: Shutdown,
    ) {
        let mut run = JoinSet::new();
        run.spawn(async move {
            let result = job.run(&mut connection, &shutdown).await;
            (connection, result)
        });
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

/// Drains expired authentication state, and event personal data past its retention,
/// in bounded batches until a pass finds nothing or a one-minute budget runs out.
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
        let deadline = Instant::now() + Self::BUDGET;
        while connection
            .maintenance()
            .purge_expired_auth_state(Self::BATCH_SIZE)
            .await?
            > 0
        {
            if Instant::now() >= deadline {
                tracing::warn!("expired authentication state cleanup is falling behind");
                break;
            }
            tokio::select! {
                biased;
                () = shutdown.requested() => break,
                () = tokio::time::sleep(Self::PAUSE) => {}
            }
        }
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
        let url = piquel_common::Variable::new("TEST_DATABASE_URL")
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
