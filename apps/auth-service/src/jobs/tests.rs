//! Job runner failure isolation and exclusivity across runners.
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
