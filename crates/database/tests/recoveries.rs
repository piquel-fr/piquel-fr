//! Persistence guarantees behind account recoveries: their links, their state,
//! and the database backstops that hold for every writer, a release older than
//! recovery included.
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    AuthenticationMethod, Handle, PasskeyId, RecoveryId, SessionId, UserId,
    events::{Browser, Platform, UserAgentFamily},
};
use piquel_repository::{
    Database, DatabaseConfig, InsertPasskey, InsertRecovery, InsertSession, InsertUser,
    RecoveryState, StoredRecovery,
};
use std::net::IpAddr;

/// How long a probation lasts in these tests.
const PROBATION: Duration = Duration::days(15);

/// The migrated test database, connected as its owner, with a plain pool for
/// the statements no repository runs: creating roles, and moving a recovery's
/// clock.
struct Owner {
    /// The repositories.
    db: Database,
    /// Raw statements.
    pool: sqlx::PgPool,
}

impl Owner {
    /// Connects and migrates.
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let db = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("config"),
        )
        .await
        .expect("connect");
        db.run_migrations().await.expect("migrate");
        let pool = sqlx::PgPool::connect(&url).await.expect("pool");
        Self { db, pool }
    }

    /// Runs `sql` in one transaction, serialized with every other test's: grants
    /// on the same tables from concurrent transactions fail.
    async fn raw(&self, sql: &str) {
        let serialized = format!("BEGIN; SELECT pg_advisory_xact_lock(4519); {sql}; COMMIT;");
        sqlx::raw_sql(&serialized)
            .execute(&self.pool)
            .await
            .expect(sql);
    }

    /// Makes recovery `id`'s unused link expire now.
    async fn expire(&self, id: RecoveryId) {
        sqlx::query("UPDATE account_recoveries SET expires_at = clock_timestamp() WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .expect("expire");
    }

    /// Ends recovery `id`'s probation now, as if its link had been used
    /// [`PROBATION`] ago.
    async fn settle(&self, id: RecoveryId) {
        sqlx::query(
            "UPDATE account_recoveries
            SET completed_at = completed_at - interval '15 days',
                settles_at = clock_timestamp()
            WHERE id = $1",
        )
        .bind(id.as_uuid())
        .execute(&self.pool)
        .await
        .expect("settle");
    }
}

/// Creates an account.
async fn account(db: &Database) -> UserId {
    let user = UserId::new();
    db.users()
        .insert(&InsertUser {
            id: user,
            handle: Handle::parse(&format!("recover-{}", &user.to_string()[24..])).expect("handle"),
            display_name: "Recovery test".into(),
        })
        .await
        .expect("user");
    user
}

/// A role like the runtime role between the migration and provisioning: it may
/// use every table but `account_recoveries`, which the migration created after
/// its grants. Connected as that role, the database the triggers run under.
struct Limited {
    /// Connected as the role.
    db: Database,
    /// The role's name, which [`Self::drop`] removes.
    name: String,
}

impl Limited {
    /// Creates the role and connects as it.
    async fn new(owner: &Owner) -> Self {
        let name = format!("recovery_{}", uuid::Uuid::now_v7().simple());
        owner
            .raw(&format!(
                "CREATE ROLE {name} LOGIN PASSWORD 'limited';
                GRANT USAGE ON SCHEMA public TO {name};
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {name};
                REVOKE ALL ON account_recoveries FROM {name};"
            ))
            .await;
        let mut url =
            url::Url::parse(&std::env::var("TEST_DATABASE_URL").expect("URL")).expect("test URL");
        url.set_username(&name).expect("user");
        url.set_password(None).expect("password");
        let config = DatabaseConfig::new(url.as_str(), 1, std::time::Duration::from_secs(5))
            .expect("config")
            .with_password("limited");
        let db = Database::connect(config).await.expect("log in as the role");
        Self { db, name }
    }

    /// Drops the role, once its connection is gone.
    async fn drop(self, owner: &Owner) {
        drop(self.db);
        owner
            .raw(&format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{0}';
                DROP OWNED BY {0}; DROP ROLE {0}",
                self.name
            ))
            .await;
    }
}

/// Enrolls a passkey for `user`.
async fn passkey(db: &Database, user: UserId) -> PasskeyId {
    let id = PasskeyId::new();
    db.passkeys()
        .insert(&InsertPasskey {
            id,
            credential_id: id.as_uuid().as_bytes().to_vec(),
            user_id: user,
            credential: serde_json::json!({}),
            friendly_name: "Key".into(),
        })
        .await
        .expect("passkey");
    id
}

/// Starts a recovery of `user` whose link works for `lifetime`.
async fn start(db: &Database, user: UserId, lifetime: Duration) -> RecoveryId {
    let id = RecoveryId::new();
    let digest = id.as_uuid().as_bytes().repeat(2);
    db.recoveries()
        .insert(&InsertRecovery {
            id,
            user_id: user,
            secret_digest: &digest,
            expires_at: Utc::now() + lifetime,
        })
        .await
        .expect("recovery");
    id
}

/// Starts a recovery of `user` and uses its link, enrolling a passkey: the
/// recovery is in probation. Returns it and its passkey.
async fn probation(db: &Database, user: UserId) -> (RecoveryId, PasskeyId) {
    let id = start(db, user, Duration::hours(1)).await;
    let enrolled = passkey(db, user).await;
    let completed = db
        .recoveries()
        .complete(user, id, enrolled, PROBATION)
        .await
        .expect("complete");
    assert!(completed);
    (id, enrolled)
}

/// Inserts a session of `user`, signed in with `passkey` and confirmed at `now`
/// when `confirmed`, as any release writes one.
async fn session(
    db: &Database,
    user: UserId,
    passkey: Option<PasskeyId>,
    confirmed: bool,
) -> SessionId {
    let (id, now) = (SessionId::new(), Utc::now());
    db.sessions()
        .insert(&InsertSession {
            id,
            user_id: user,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: now,
            expires_at: now + Duration::minutes(5),
            user_agent_family: UserAgentFamily {
                browser: Browser::Firefox,
                platform: Platform::Linux,
            },
            ip: IpAddr::from([192, 0, 2, 1]),
            passkey_confirmed_at: confirmed.then_some(now),
            passkey_id: passkey,
        })
        .await
        .expect("session");
    id
}

/// When session `id` was confirmed with a passkey, if it was.
async fn confirmed_at(db: &Database, id: SessionId) -> Option<DateTime<Utc>> {
    db.sessions()
        .find_by_id(id)
        .await
        .expect("lookup")
        .expect("session")
        .passkey_confirmed_at
}

/// A recovery as stored, `read_at` `now`, for the state's boundaries.
fn stored(now: DateTime<Utc>) -> StoredRecovery {
    StoredRecovery {
        id: RecoveryId::new(),
        user_id: UserId::new(),
        started_at: now - Duration::hours(1),
        expires_at: now + Duration::hours(1),
        completed_at: None,
        passkey_id: None,
        settles_at: None,
        cancelled_at: None,
        undone_at: None,
        read_at: now,
    }
}

/// A recovery is open while its unused link works, in probation until it
/// settles, then settled; expired, cancelled and undone ones have ended. Only
/// open and in probation can be undone.
#[test]
fn a_recovery_state_follows_its_link_and_probation() {
    let now = Utc::now();
    let open = stored(now);
    assert_eq!(open.state(), RecoveryState::Open);
    let expired = StoredRecovery {
        expires_at: now,
        ..stored(now)
    };
    assert_eq!(expired.state(), RecoveryState::Ended);
    let cancelled = StoredRecovery {
        cancelled_at: Some(now),
        ..stored(now)
    };
    assert_eq!(cancelled.state(), RecoveryState::Ended);
    let used = |settles_at| StoredRecovery {
        completed_at: Some(now - Duration::minutes(1)),
        passkey_id: Some(PasskeyId::new()),
        settles_at: Some(settles_at),
        // A used link's expiry no longer matters.
        expires_at: now - Duration::minutes(1),
        ..stored(now)
    };
    let settles_at = now + Duration::seconds(1);
    assert_eq!(
        used(settles_at).state(),
        RecoveryState::Probation { settles_at }
    );
    assert_eq!(used(now).state(), RecoveryState::Settled);
    let undone = StoredRecovery {
        undone_at: Some(now),
        ..used(settles_at)
    };
    assert_eq!(undone.state(), RecoveryState::Ended);
    let undoable: Vec<_> = [
        open,
        expired,
        cancelled,
        used(settles_at),
        used(now),
        undone,
    ]
    .iter()
    .map(|recovery| recovery.state().undoable())
    .collect();
    assert_eq!(undoable, [true, false, false, true, false, false]);
}

/// A link that expires while its finish waits, as it would for the account lock,
/// does not complete, though the transaction started before the deadline.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_link_that_expires_while_finishing_does_not_complete() {
    let owner = Owner::new().await;
    let db = &owner.db;
    let user = account(db).await;
    let id = start(db, user, Duration::milliseconds(500)).await;

    let mut tx = db.begin().await.expect("transaction");
    tx.users()
        .find_active_by_id_for_update(user)
        .await
        .expect("lock")
        .expect("user");
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let completed = tx
        .recoveries()
        .complete(user, id, PasskeyId::new(), PROBATION)
        .await;
    assert!(!completed.expect("complete"), "expired while waiting");
}

/// An account has at most one recovery whose link was not used, cancelled or
/// undone. An expired one counts until the next start cancels it.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn one_open_recovery_per_account() {
    let owner = Owner::new().await;
    let db = &owner.db;
    let user = account(db).await;
    let first = start(db, user, Duration::hours(1)).await;
    owner.expire(first).await;
    let digest = [7; 64];
    let second = InsertRecovery {
        id: RecoveryId::new(),
        user_id: user,
        secret_digest: &digest,
        expires_at: Utc::now() + Duration::hours(1),
    };
    let second_open = db.recoveries().insert(&second).await;
    assert!(second_open.is_err(), "the expired first still counts");
    assert!(db.recoveries().cancel_open(user).await.expect("cancel"));
    db.recoveries()
        .insert(&second)
        .await
        .expect("once the first is cancelled");
}

/// A passkey of a recovery in probation never confirms a session, whichever
/// release writes it, even without access to `account_recoveries`; nor does a
/// confirmation that names no passkey. An older passkey still confirms, and so
/// does any once the recovery settled or was undone.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn a_probation_passkey_never_confirms_a_session() {
    let owner = Owner::new().await;
    let limited = Limited::new(&owner).await;
    let db = &limited.db;
    let user = account(&owner.db).await;
    let older = passkey(&owner.db, user).await;
    let (recovery, recovered) = probation(&owner.db, user).await;

    let by_recovered = session(db, user, Some(recovered), true).await;
    assert_eq!(confirmed_at(db, by_recovered).await, None, "inserted");
    let unnamed = session(db, user, None, true).await;
    assert_eq!(confirmed_at(db, unnamed).await, None, "no passkey named");
    let by_older = session(db, user, Some(older), true).await;
    assert!(
        confirmed_at(db, by_older).await.is_some(),
        "an older passkey"
    );
    db.sessions()
        .confirm_passkey(by_older, recovered, Utc::now())
        .await
        .expect("confirm");
    assert_eq!(confirmed_at(db, by_older).await, None, "confirmed by it");
    db.sessions()
        .confirm_passkey(by_older, older, Utc::now())
        .await
        .expect("confirm");
    assert!(confirmed_at(db, by_older).await.is_some());

    owner.settle(recovery).await;
    let settled = session(db, user, Some(recovered), true).await;
    assert!(confirmed_at(db, settled).await.is_some(), "once settled");

    let other = account(&owner.db).await;
    let (recovery, recovered) = probation(&owner.db, other).await;
    owner.db.recoveries().undo(recovery).await.expect("undo");
    let undone = session(db, other, Some(recovered), true).await;
    assert!(confirmed_at(db, undone).await.is_some(), "once undone");
    limited.drop(&owner).await;
}

/// No account is made an administrator while a recovery of it can be undone,
/// whichever release grants it: neither while its link works, nor during its
/// probation. Once the link expired unused, or the recovery settled, it may be.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn no_grant_while_a_recovery_can_be_undone() {
    let owner = Owner::new().await;
    let limited = Limited::new(&owner).await;
    let db = &limited.db;
    let (open, used) = (account(&owner.db).await, account(&owner.db).await);
    let link = start(&owner.db, open, Duration::hours(1)).await;
    let (recovery, _) = probation(&owner.db, used).await;
    for user in [open, used] {
        let granted = db.administrators().grant(user).await;
        assert!(granted.is_err(), "refused mid-recovery");
    }

    owner.expire(link).await;
    owner.settle(recovery).await;
    for user in [open, used] {
        assert!(db.administrators().grant(user).await.expect("grant"));
    }
    limited.drop(&owner).await;
}

/// While a recovery can be undone, no passkey but its own is revoked, whichever
/// release revokes it, so nothing takes away the passkeys that can undo it.
/// Once the link expired unused, or the recovery settled or was undone, any may
/// be.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn only_the_recoverys_own_passkey_is_revoked_mid_recovery() {
    let owner = Owner::new().await;
    let limited = Limited::new(&owner).await;
    let db = &limited.db;

    let open = account(&owner.db).await;
    let older = passkey(&owner.db, open).await;
    let link = start(&owner.db, open, Duration::hours(1)).await;
    assert!(
        db.passkeys().revoke(older, open).await.is_err(),
        "link works"
    );
    owner.expire(link).await;
    assert!(db.passkeys().revoke(older, open).await.expect("revoke"));

    let used = account(&owner.db).await;
    let older = passkey(&owner.db, used).await;
    let (recovery, recovered) = probation(&owner.db, used).await;
    assert!(
        db.passkeys().revoke(older, used).await.is_err(),
        "probation"
    );
    assert!(
        db.passkeys()
            .revoke(recovered, used)
            .await
            .expect("its own")
    );
    owner.settle(recovery).await;
    assert!(db.passkeys().revoke(older, used).await.expect("settled"));

    let undone = account(&owner.db).await;
    let older = passkey(&owner.db, undone).await;
    let (recovery, _) = probation(&owner.db, undone).await;
    owner.db.recoveries().undo(recovery).await.expect("undo");
    assert!(db.passkeys().revoke(older, undone).await.expect("undone"));
    limited.drop(&owner).await;
}
