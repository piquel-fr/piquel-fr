//! `check_backend`: whether an application's [`SessionBackend`] keeps the contract
//! the login routes rely on, for its own tests against a real database.

use super::{
    KEY_BYTES, SessionBackend, SessionRecord,
    backend::{BackendError, BackendFuture},
    random,
};
use chrono::{TimeDelta, Utc};
use std::sync::Arc;

/// How a backend failed [`check_backend`].
#[derive(Debug, thiserror::Error)]
pub enum BackendCheckError {
    /// An operation failed.
    #[error("the backend failed")]
    Backend(#[source] BackendError),
    /// An operation succeeded but broke the [`SessionBackend`] contract.
    #[error("the backend breaks its contract: {0}")]
    Contract(&'static str),
}

/// Rounds of contention [`check_backend`] runs.
const CHECK_ROUNDS: usize = 25;
/// Concurrent callers in each round of contention.
const CHECK_COMPETITORS: usize = 4;

/// Checks that `backend` keeps the [`SessionBackend`] contract the login routes rely
/// on. Run it in a test against the real database, on a multi-threaded runtime with
/// at least two workers:
///
/// ```
/// use piquel_auth::axum::{MemoryBackend, check_backend};
///
/// # let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
/// # runtime.block_on(async {
/// // In a `#[tokio::test(flavor = "multi_thread")]`:
/// check_backend(&MemoryBackend::default()).await.expect("a sound backend");
/// # });
/// ```
///
/// It checks that records round-trip, that `insert` stores only where no record is,
/// that `replace` and `remove` refuse missing records and never create one, and that
/// of several callers racing `insert` of one key, `replace` at one version, or
/// `remove`, exactly one wins, and the stored record is the winner's.
/// The races run on separate tasks over 25 rounds, which catches a
/// read-then-write backend in practice but cannot prove atomicity: keep each
/// operation a single atomic statement. It writes and removes records under random
/// keys.
///
/// # Errors
/// [`BackendCheckError`] naming the first failed check, or saying the runtime has
/// fewer than two workers, since racing calls could not overlap.
pub async fn check_backend<B: SessionBackend>(backend: &B) -> Result<(), BackendCheckError> {
    use BackendCheckError::Contract;
    use tokio::runtime::{Handle, RuntimeFlavor};
    let runtime = Handle::current();
    if runtime.runtime_flavor() != RuntimeFlavor::MultiThread || runtime.metrics().num_workers() < 2
    {
        return Err(Contract(
            "run check_backend on a multi-threaded runtime with at least two workers, \
             so racing calls overlap",
        ));
    }
    let failed = |error: B::Error| BackendCheckError::Backend(Box::new(error));
    let record = |version, data: String| SessionRecord {
        version,
        data,
        expires_at: Utc::now() + TimeDelta::minutes(5),
    };
    let key = check_key()?;
    if backend.load(&key).await.map_err(failed)?.is_some() {
        return Err(Contract("load found a record that was never inserted"));
    }
    let missing = record(2, "missing".into());
    if backend.replace(&key, 1, &missing).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.is_some()
    {
        return Err(Contract("replace wrote a record that does not exist"));
    }
    if backend.remove(&key).await.map_err(failed)? {
        return Err(Contract("remove reported a record that does not exist"));
    }
    let first = record(1, "first".into());
    if !backend.insert(&key, &first).await.map_err(failed)? {
        return Err(Contract("insert refused a key that holds no record"));
    }
    if backend.load(&key).await.map_err(failed)?.as_ref() != Some(&first) {
        return Err(Contract(
            "load did not return the inserted record unchanged",
        ));
    }
    if backend
        .insert(&key, &record(1, "again".into()))
        .await
        .map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.as_ref() != Some(&first)
    {
        return Err(Contract("insert replaced a record already there"));
    }
    let second = record(2, "second".into());
    if backend.replace(&key, 7, &second).await.map_err(failed)? {
        return Err(Contract("replace wrote although the version did not match"));
    }
    if !backend.replace(&key, 1, &second).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.as_ref() != Some(&second)
    {
        return Err(Contract("replace did not write at the matching version"));
    }
    if !backend.remove(&key).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.is_some()
        || backend.replace(&key, 2, &second).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.is_some()
    {
        return Err(Contract("a removed record came back"));
    }
    for _ in 0..CHECK_ROUNDS {
        race(backend).await?;
    }
    Ok(())
}

/// A fresh random key for [`check_backend`].
fn check_key() -> Result<String, BackendCheckError> {
    random(KEY_BYTES)
        .map(|key| format!("check:{key}"))
        .map_err(|error| BackendCheckError::Backend(Box::new(error)))
}

/// The record competitor `competitor` writes at `version` in [`race`].
fn competitor_record(version: u64, competitor: usize) -> SessionRecord {
    SessionRecord {
        version,
        data: format!("competitor {competitor}"),
        expires_at: Utc::now() + TimeDelta::minutes(5),
    }
}

/// One round of contention on a fresh key: racing `insert` calls, then racing
/// `replace` calls at one version, then racing `remove` calls, each on its own task,
/// released together.
async fn race<B: SessionBackend>(backend: &B) -> Result<(), BackendCheckError> {
    use BackendCheckError::{Backend, Contract};
    use tokio::sync::Barrier;
    let key = Arc::new(check_key()?);
    // Every competitor starts its call at once, on its own task.
    let spawn = |call: fn(B, Arc<String>, usize) -> BackendFuture<'static, bool>| {
        let barrier = Arc::new(Barrier::new(CHECK_COMPETITORS));
        (0..CHECK_COMPETITORS)
            .map(|competitor| {
                let (backend, key, barrier) = (backend.clone(), key.clone(), barrier.clone());
                tokio::spawn(async move {
                    barrier.wait().await;
                    call(backend, key, competitor).await
                })
            })
            .collect::<Vec<_>>()
    };
    // The one competitor whose call succeeded, or `message`.
    let winner = |tasks: Vec<tokio::task::JoinHandle<Result<bool, BackendError>>>,
                  message: &'static str| async move {
        let mut winners = Vec::new();
        for (competitor, task) in tasks.into_iter().enumerate() {
            if task
                .await
                .map_err(|error| Backend(Box::new(error)))?
                .map_err(Backend)?
            {
                winners.push(competitor);
            }
        }
        match winners[..] {
            [winner] => Ok(winner),
            _ => Err(Contract(message)),
        }
    };
    // The data of the stored record, if any.
    let stored = || async {
        let record = backend
            .load(&key)
            .await
            .map_err(|error| Backend(Box::new(error)))?;
        Ok::<_, BackendCheckError>(record.map(|record| record.data))
    };
    let insert_calls = spawn(|backend, key, competitor| {
        Box::pin(async move {
            let record = competitor_record(1, competitor);
            Ok(backend.insert(&key, &record).await?)
        })
    });
    let inserter = winner(
        insert_calls,
        "of racing inserts of one key, exactly one must store",
    )
    .await?;
    if stored().await? != Some(format!("competitor {inserter}")) {
        return Err(Contract("the stored record is not the winning insert's"));
    }
    let replace_calls = spawn(|backend, key, competitor| {
        Box::pin(async move {
            let record = competitor_record(2, competitor);
            Ok(backend.replace(&key, 1, &record).await?)
        })
    });
    let replacer = winner(
        replace_calls,
        "of racing replaces at one version, exactly one must write",
    )
    .await?;
    if stored().await? != Some(format!("competitor {replacer}")) {
        return Err(Contract("the stored record is not the winning replace's"));
    }
    let remove_calls =
        spawn(|backend, key, _| Box::pin(async move { Ok(backend.remove(&key).await?) }));
    winner(
        remove_calls,
        "of racing removes, exactly one must report the record",
    )
    .await?;
    if stored().await?.is_some() {
        return Err(Contract("a record survived the racing removes"));
    }
    Ok(())
}
