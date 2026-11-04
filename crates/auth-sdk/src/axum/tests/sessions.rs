//! The session store: leases, backends that break the contract, and sealing.

use super::*;

/// The lease is taken only at the version read, by one attempt at a time; only that
/// attempt can save; and a lease that expires unreleased marks the session abandoned.
#[tokio::test]
async fn leases_are_fenced() {
    let backend = MemoryBackend::default();
    let sessions = sessions(backend.clone());
    let login = stored_login(USER, SessionId::new(), 300);
    let (key, _) = session(&backend, &login).await;
    let (first, second) = (
        LeaseId::generate().expect("lease"),
        LeaseId::generate().expect("lease"),
    );
    let minute = Duration::from_secs(60);
    let lease = |version, id, ttl| sessions.lease(&key, version, id, ttl, Utc::now());
    let save = |id| sessions.save(&key, id, login.clone(), Utc::now);
    assert!(matches!(
        lease(1, &first, minute).await.expect("lease"),
        Lease::Acquired(_)
    ));
    assert_eq!(lease(2, &second, minute).await.expect("lease"), Lease::Busy);
    assert!(
        save(&second).await.expect("save").is_none(),
        "not the holder"
    );
    let saved = save(&first).await.expect("save").expect("the holder saves");
    assert_eq!((saved.version, saved.leased), (3, false));
    assert!(save(&first).await.expect("save").is_none(), "given back");
    // A request that read version 1 must not redeem the token version 3 replaced.
    assert_eq!(
        lease(1, &second, minute).await.expect("lease"),
        Lease::Changed
    );
    assert!(matches!(
        lease(3, &second, Duration::ZERO).await.expect("lease"),
        Lease::Acquired(_)
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    // Past its expiry, even the holder cannot save: the lease may be found abandoned.
    assert!(save(&second).await.expect("save").is_none(), "expired");
    assert_eq!(
        lease(4, &first, minute).await.expect("lease"),
        Lease::Abandoned
    );
    sessions.delete(&key).await.expect("delete");
    assert_eq!(
        lease(4, &first, minute).await.expect("lease"),
        Lease::Missing
    );
}

/// A flaw of a [`Flawed`] backend.
#[derive(Clone, Copy)]
enum Flaw {
    /// Reads are slow.
    SlowReads,
    /// `replace` reads, pauses, then writes: not atomic.
    ReadThenWrite,
    /// `replace` inserts a missing record, which could resurrect a logged-out session.
    Upserting,
    /// `insert` replaces a record already there.
    Overwriting,
}

/// A memory backend with one flaw.
#[derive(Clone)]
struct Flawed(Flaw, MemoryBackend);

impl Flawed {
    /// An empty backend with `flaw`.
    fn new(flaw: Flaw) -> Self {
        Self(flaw, MemoryBackend::default())
    }
}

impl SessionBackend for Flawed {
    type Error = std::convert::Infallible;

    async fn load(&self, key: &str) -> Result<Option<SessionRecord>, Self::Error> {
        if matches!(self.0, Flaw::SlowReads) {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        self.1.load(key).await
    }

    async fn insert(&self, key: &str, record: &SessionRecord) -> Result<bool, Self::Error> {
        if matches!(self.0, Flaw::Overwriting) {
            self.1.remove(key).await?;
        }
        self.1.insert(key, record).await
    }

    async fn replace(
        &self,
        key: &str,
        expected: u64,
        record: &SessionRecord,
    ) -> Result<bool, Self::Error> {
        match self.0 {
            Flaw::ReadThenWrite => {
                let current = self.1.load(key).await?;
                std::thread::sleep(Duration::from_millis(2));
                if current.is_none_or(|stored| stored.version != expected) {
                    return Ok(false);
                }
                self.1.remove(key).await?;
                self.1.insert(key, record).await?;
                Ok(true)
            }
            Flaw::Upserting if self.1.load(key).await?.is_none() => {
                self.1.insert(key, record).await
            }
            _ => self.1.replace(key, expected, record).await,
        }
    }

    async fn remove(&self, key: &str) -> Result<bool, Self::Error> {
        self.1.remove(key).await
    }
}

/// A lease that expires while its save reads the session cannot save: the clock is
/// read again after the backend answers.
#[tokio::test]
async fn saves_recheck_expiry_after_slow_reads() {
    let sessions = sessions(Flawed::new(Flaw::SlowReads));
    let login = stored_login(USER, SessionId::new(), 300);
    let key = SessionKey::generate().expect("key");
    sessions
        .insert(&key, &login, Utc::now() + TimeDelta::hours(1), Utc::now())
        .await
        .expect("insert");
    let lease = LeaseId::generate().expect("lease");
    let acquired = sessions
        .lease(&key, 1, &lease, Duration::from_millis(250), Utc::now())
        .await
        .expect("lease");
    assert!(matches!(acquired, Lease::Acquired(_)));
    // The lease is still valid when the save starts, but not once its read returns.
    let saved = sessions
        .save(&key, &lease, login, Utc::now)
        .await
        .expect("save");
    assert!(saved.is_none(), "an expired lease must not save");
}

/// The check refuses a non-atomic backend, one that creates records on `replace`,
/// one whose `insert` overwrites, and a runtime on which racing calls cannot overlap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_backend_catches_broken_backends() {
    for (flaw, broken) in [
        (
            Flaw::ReadThenWrite,
            "of racing replaces at one version, exactly one must write",
        ),
        (
            Flaw::Upserting,
            "replace wrote a record that does not exist",
        ),
        (Flaw::Overwriting, "insert replaced a record already there"),
    ] {
        assert!(matches!(
            check_backend(&Flawed::new(flaw)).await,
            Err(BackendCheckError::Contract(message)) if message == broken
        ));
    }
    // Neither a current-thread runtime nor a single worker lets racing calls overlap.
    for runtime in [
        tokio::runtime::Builder::new_current_thread().build(),
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build(),
    ] {
        let runtime = runtime.expect("runtime");
        let checked = tokio::task::spawn_blocking(move || {
            runtime.block_on(check_backend(&Flawed::new(Flaw::ReadThenWrite)))
        });
        assert!(matches!(
            checked.await.expect("task"),
            Err(BackendCheckError::Contract(message)) if message.contains("two workers")
        ));
    }
}

/// The memory backend keeps the backend contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_backend_keeps_the_contract() {
    check_backend(&MemoryBackend::default())
        .await
        .expect("a sound backend");
}

/// A dump of the backend holds no token and nothing naming the user: session
/// records are sealed with a key derived from the session key, which the backend
/// never sees. A record opens only under its own name, for its own client and key,
/// and one that does not open is a missing session, not a trusted one.
#[tokio::test]
async fn backend_dumps_hold_no_usable_token() {
    let backend = Spy::default();
    let sid = SessionId::new();
    let (key, _) = session(&backend, &stored_login(USER, sid, 300)).await;
    let (other, _) = session(&backend, &stored_login(USER, SessionId::new(), 300)).await;
    let records = backend.dump().await;
    // The two sessions, and the `sid` and `sub` indexes listing them.
    assert_eq!(records.len(), 5);
    for record in &records {
        for secret in ["access-0", "refresh-0", "id-0", USER, &sid.to_string()] {
            assert!(!record.data.contains(secret), "{secret} in {record:?}");
        }
    }
    assert!(load(&backend, &key).await.is_some());
    let elsewhere = Sessions::new(backend.clone(), "another-app".parse().expect("client"));
    assert!(
        elsewhere
            .load(&key, Utc::now())
            .await
            .expect("load")
            .is_none()
    );

    // Each session record under the other's name, then tampered with.
    let (first, second) = (hashed_name(&key), hashed_name(&other));
    let mut record = backend.load(&second).await.expect("load").expect("record");
    let moved = backend.load(&first).await.expect("load").expect("record");
    record.data = moved.data;
    assert!(backend.replace(&second, 1, &record).await.expect("replace"));
    assert!(load(&backend, &other).await.is_none(), "moved");
    let mut record = backend.load(&first).await.expect("load").expect("record");
    record.data.replace_range(
        ..1,
        if record.data.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    assert!(backend.replace(&first, 1, &record).await.expect("replace"));
    assert!(load(&backend, &key).await.is_none(), "tampered");
}

/// The backend name of the test client's session under `key`.
fn hashed_name(key: &SessionKey) -> String {
    let digest = sha2::Sha256::digest(format!("{CLIENT}\0{}", key.as_cookie()));
    format!(
        "session-v3:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}
