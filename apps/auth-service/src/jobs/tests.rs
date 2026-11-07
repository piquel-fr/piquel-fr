//! Job runner failure isolation and exclusivity across runners, and the alert
//! of failing purges.
use super::*;
use crate::tests::Replicas;
use std::sync::{
    Mutex,
    atomic::{AtomicU32, Ordering},
};

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
    let runs = Arc::new(AtomicU32::new(0));
    let mut jobs = Jobs::new();
    jobs.exclusive(PanicsOnce(Arc::clone(&runs)), Replicas::database().await);
    tokio::time::timeout(Duration::from_secs(5), async {
        while runs.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the job runs again after panicking");
    jobs.shutdown().await.expect("no job loop panicked");
}

/// A run of [`Held`] by the runner it names starting, finishing or being
/// cancelled.
#[derive(Clone, Debug)]
enum Event {
    Started(usize),
    Finished(usize),
    Cancelled(usize),
}

/// Every [`Event`] of the runners sharing it, in order.
#[derive(Default)]
struct Log(Mutex<Vec<Event>>);

impl Log {
    fn push(&self, event: Event) {
        self.0.lock().expect("log").push(event);
    }

    fn events(&self) -> Vec<Event> {
        self.0.lock().expect("log").clone()
    }

    /// Waits until `found` returns something for the events so far.
    async fn wait_for<T>(&self, found: impl Fn(&[Event]) -> Option<T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(found) = found(&self.0.lock().expect("log")) {
                    break found;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the awaited events never happened: {:?}", self.events()))
    }
}

/// Holds its lock for [`Self::HOLD`], several periods, logging when each run
/// of `runner` starts and how it ends.
struct Held {
    runner: usize,
    log: Arc<Log>,
}

impl Held {
    const HOLD: Duration = Duration::from_millis(100);
}

/// Logs how a [`Held`] run ended when dropped, so a cancelled run is logged
/// too. The run drops it before its connection, so before the lock is freed.
struct Running<'a> {
    job: &'a Held,
    finished: bool,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let runner = self.job.runner;
        self.job.log.push(if self.finished {
            Event::Finished(runner)
        } else {
            Event::Cancelled(runner)
        });
    }
}

impl ExclusiveJob for Held {
    const NAME: &'static str = "held";
    const LOCK: LockKey = LockKey::ExclusivityTest;
    const EVERY: Duration = Duration::from_millis(20);
    type Error = DatabaseError;

    async fn run(&self, _: &mut ExclusiveConnection, _: &Shutdown) -> Result<(), DatabaseError> {
        self.log.push(Event::Started(self.runner));
        let mut running = Running {
            job: self,
            finished: false,
        };
        tokio::time::sleep(Self::HOLD).await;
        running.finished = true;
        Ok(())
    }
}

/// Two runners, as two replicas, never run the same exclusive job at once,
/// and dropping the one mid-run cancels its run, freeing the lock for the
/// other's next tick.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn runners_never_overlap_and_a_dropped_holder_hands_over() {
    let database = Replicas::database().await;
    let log = Arc::new(Log::default());
    let mut runners = [0, 1].map(|runner| {
        let mut jobs = Jobs::new();
        let log = Arc::clone(&log);
        jobs.exclusive(Held { runner, log }, database.clone());
        Some(jobs)
    });
    // A few runs in, cancel whichever runner is mid-run.
    let holder = log
        .wait_for(|events| match events {
            [.., Event::Started(holder)] if events.len() > 6 => Some(*holder),
            _ => None,
        })
        .await;
    drop(runners[holder].take());
    let other = 1 - holder;
    log.wait_for(|events| {
        events
            .windows(2)
            .any(|pair| {
                matches!(
                    pair,
                    [Event::Cancelled(cancelled), Event::Started(started)]
                        if *cancelled == holder && *started == other
                )
            })
            .then_some(())
    })
    .await;
    runners[other]
        .take()
        .expect("the other runner")
        .shutdown()
        .await
        .expect("no job loop panicked");
    let events = log.events();
    assert!(
        events.chunks(2).all(|run| matches!(
            run,
            [Event::Started(started), Event::Finished(ended) | Event::Cancelled(ended)]
                if started == ended
        )),
        "runs overlapped: {events:?}"
    );
}

/// A purge run raises the alert of accounts that keep failing to be purged, and
/// a run with none clears it. The schema is its own, since the count is every
/// account's.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn failing_purges_raise_their_alert_until_none_fail() {
    let harness = crate::admin::tests::Harness::isolated().await;
    let database = &harness.database;
    let user_id = harness.account().await.user_id;
    // Failing, and waiting a day for its next attempt, so the run purges nothing.
    let mut deletions = database.deletions();
    deletions
        .schedule(user_id, Utc::now() - chrono::Duration::days(1))
        .await
        .expect("schedule");
    for _ in 0..AccountPurge::FAILING_ATTEMPTS {
        let day = chrono::Duration::days(1);
        deletions
            .record_failure(user_id, "boom", day, day)
            .await
            .expect("failure");
    }
    let mut lock = database
        .try_exclusive(LockKey::AccountPurge)
        .await
        .expect("lock")
        .expect("no other test purges");
    let shutdown = Shutdown(watch::Sender::new(false).subscribe());
    let current = async || {
        let mut tx = database.begin().await.expect("transaction");
        let current = tx
            .alerts()
            .current(AlertKind::PurgesFailing)
            .await
            .expect("current");
        tx.commit().await.expect("commit");
        current.and_then(|current| current.alert)
    };
    AccountPurge.run(&mut lock, &shutdown).await.expect("run");
    assert_eq!(current().await, Some(Alert::PurgesFailing {}));
    assert!(database.deletions().cancel(user_id).await.expect("cancel"));
    AccountPurge.run(&mut lock, &shutdown).await.expect("run");
    assert_eq!(current().await, None);
    lock.release().await.expect("release");
}

/// The third cleanup pass in a row that runs out of time raises the alert of
/// cleanup falling behind, and a pass that deletes everything due clears it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn cleanup_that_keeps_falling_behind_raises_its_alert() {
    let database = crate::admin::tests::Harness::isolated().await.database;
    // The database crate's lock tests take the same lock, on the same cluster.
    let mut lock = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(lock) = database
                .try_exclusive(LockKey::Cleanup)
                .await
                .expect("lock")
            {
                return lock;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the cleanup lock");
    let shutdown = Shutdown(watch::Sender::new(false).subscribe());
    // Out of time as soon as it deletes anything.
    let cleanup = Cleanup {
        budget: Duration::ZERO,
        overruns: AtomicU32::new(0),
    };
    let current = async || {
        let mut tx = database.begin().await.expect("transaction");
        let current = tx
            .alerts()
            .current(AlertKind::CleanupBehind)
            .await
            .expect("current");
        tx.commit().await.expect("commit");
        current.and_then(|current| current.alert)
    };
    for pass in 1..=Cleanup::BEHIND_AFTER {
        // An expired invitation, for the pass to delete.
        let digest = UserId::new().as_uuid().as_u128().to_be_bytes().repeat(2);
        let expired = Utc::now() - chrono::Duration::days(1);
        database
            .security()
            .create_invitation(piquel_common::TokenId::new(), &digest, expired)
            .await
            .expect("invitation");
        cleanup.run(&mut lock, &shutdown).await.expect("run");
        let raised = (pass == Cleanup::BEHIND_AFTER).then_some(Alert::CleanupBehind {});
        assert_eq!(current().await, raised, "after pass {pass}");
    }
    cleanup.run(&mut lock, &shutdown).await.expect("run");
    assert_eq!(current().await, None);
    lock.release().await.expect("release");
}
