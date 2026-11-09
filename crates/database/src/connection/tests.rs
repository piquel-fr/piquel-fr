//! Focused persistence and security contract tests.

use super::{Database, DatabaseConfig, Limit, MIGRATOR, RuntimeRole, Scope};
use crate::{DatabaseConnectionError, DatabaseError, EventContent, LockKey};
use sqlx::{PgConnection, Postgres, postgres::PgArguments, query::Query};
use std::time::Duration;
use uuid::Uuid;

/// TCP needs verified TLS or an explicit `sslmode=disable`, loopback included; a
/// Unix socket needs an absolute path under `localhost`. Repeated transport
/// settings and address overrides are refused before `SQLx` parses them.
#[test]
fn transport_is_verified_tls_a_local_socket_or_explicit_plaintext() {
    use DatabaseConnectionError::{AmbiguousTransport, InsecureTransport, InvalidSocket};
    for (url, expected) in [
        ("postgres://db.example/sourceorigin?sslmode=verify-full", None),
        ("postgres://db.example/sourceorigin?ssl-mode=verify-full", None),
        ("postgres://db.example/sourceorigin?sslmode=disable", None),
        ("postgres://[::1]/sourceorigin?sslmode=disable", None),
        ("postgres://localhost/sourceorigin?host=/run/postgresql", None),
        ("postgres://db.example/sourceorigin", Some(InsecureTransport)),
        ("postgres://localhost/sourceorigin", Some(InsecureTransport)),
        ("postgres://127.0.0.1/sourceorigin", Some(InsecureTransport)),
        (
            "postgres://db.example/sourceorigin?sslmode=prefer",
            Some(InsecureTransport),
        ),
        (
            "postgres://db.example/sourceorigin?sslmode=require",
            Some(InsecureTransport),
        ),
        (
            "postgres://db.example/sourceorigin?sslmode=verify-ca",
            Some(InsecureTransport),
        ),
        (
            "postgres://db.example/sourceorigin?host=/run/postgresql",
            Some(InvalidSocket),
        ),
        (
            "postgres://localhost/sourceorigin?host=relative/path",
            Some(InvalidSocket),
        ),
        (
            "postgres://db.example/sourceorigin?sslmode=verify-full&host=elsewhere.example",
            Some(InvalidSocket),
        ),
        (
            "postgres://db.example/sourceorigin?sslmode=verify-full&sslmode=disable",
            Some(AmbiguousTransport),
        ),
        (
            "postgres://db.example/sourceorigin?sslmode=disable&ssl-mode=verify-full",
            Some(AmbiguousTransport),
        ),
        (
            "postgres://db.example/sourceorigin?sslmode=verify-full&hostaddr=127.0.0.1",
            Some(AmbiguousTransport),
        ),
        (
            "postgres://localhost/sourceorigin?host=/run/postgresql&host=db.example",
            Some(AmbiguousTransport),
        ),
    ] {
        let result = DatabaseConfig::new(url, 1, Duration::from_secs(1));
        assert_eq!(
            result.err().map(|error| error.to_string()),
            expected.map(|error| error.to_string()),
            "{url}"
        );
    }
    // Accepting a URL is not enough: the transport it asked for is the one used.
    let options = |url| {
        DatabaseConfig::new(url, 1, Duration::from_secs(1))
            .expect("accepted")
            .options
    };
    assert!(matches!(
        options("postgres://db.example/sourceorigin?sslmode=disable").get_ssl_mode(),
        sqlx::postgres::PgSslMode::Disable
    ));
    assert_eq!(
        options("postgres://localhost/sourceorigin?host=/run/postgresql")
            .get_socket()
            .map(std::path::PathBuf::as_path),
        Some(std::path::Path::new("/run/postgresql"))
    );
}

/// Startup failures name the scheme or pool bound at fault, keep the parser's
/// error as their source and never print credentials.
#[test]
fn configuration_errors_name_the_setting_without_credentials() {
    let timeout = Duration::from_secs(1);
    let verified = "postgres://db.example/test?sslmode=verify-full";
    assert!(matches!(
        DatabaseConfig::new("https://db.example/test", 1, timeout),
        Err(DatabaseConnectionError::Scheme)
    ));
    for (max_connections, timeout) in [(0, timeout), (1, Duration::ZERO)] {
        assert!(matches!(
            DatabaseConfig::new(verified, max_connections, timeout),
            Err(DatabaseConnectionError::ZeroPoolBound)
        ));
    }
    let error = DatabaseConfig::new("not a URL", 1, timeout).expect_err("absolute URL");
    assert!(std::error::Error::source(&error).is_some());
    let error = DatabaseConfig::new("postgres://user:secret@db.example/test", 1, timeout)
        .expect_err("verified transport");
    assert!(!error.to_string().contains("secret"));
}

/// Cleanup skips rows a live request has locked instead of waiting on them.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn cleanup_skips_rows_locked_by_requests() {
    let pool = Database::test_pool().await;
    let bucket = uuid::Uuid::now_v7().as_bytes().to_vec();
    // Concurrent tests purge too and can delete the expired row before it is
    // locked, so insert it again until the request holds it.
    let request = loop {
        sqlx::query(
            "INSERT INTO request_limits (bucket, requests, expires_at)
            VALUES ($1, 1, now() - interval '1 minute')",
        )
        .bind(&bucket)
        .execute(&pool)
        .await
        .expect("expired limit");
        let mut request = pool.begin().await.expect("request transaction");
        let locked = sqlx::query("SELECT 1 FROM request_limits WHERE bucket=$1 FOR UPDATE")
            .bind(&bucket)
            .fetch_optional(&mut *request)
            .await
            .expect("lock");
        if locked.is_some() {
            break request;
        }
    };
    let database = Database { pool: pool.clone() };
    tokio::time::timeout(
        Duration::from_secs(2),
        database.maintenance().purge_expired_auth_state(1000),
    )
    .await
    .expect("cleanup must not wait on a locked row")
    .expect("purge");
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM request_limits WHERE bucket=$1")
        .bind(&bucket)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(remaining, 1);
    request.rollback().await.expect("rollback request");
}

/// A redeemed code outlives its one-day grace while its refresh family can still
/// refresh, so a late replay can revoke it; cleanup purges it once the session ends.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn cleanup_keeps_redeemed_codes_while_their_session_is_live() {
    let pool = Database::test_pool().await;
    let database = Database { pool: pool.clone() };
    let [user, session, code, family] = [(); 4].map(|()| uuid::Uuid::now_v7());
    let client = format!("purge_{user}");
    // One statement keeps the fixture short; foreign keys are checked at its end.
    sqlx::query(
        "WITH account AS (
            INSERT INTO users (id, display_name) VALUES ($1, 'Purge')
        ), browser AS (
            INSERT INTO sessions (
                id, user_id, authentication_methods, authenticated_at, expires_at, last_seen_at
            ) VALUES ($2, $1, '[]', now(), now() + interval '30 days', now())
        ), registration AS (
            INSERT INTO oidc_clients (id, display_name, allowed_scopes, allowed_audiences)
            VALUES ($5, 'Purge', '[]', '[]')
        ), redeemed AS (
            INSERT INTO authorization_codes (
                id, secret_digest, client_id, user_id, session_id, redirect_uri,
                pkce_challenge, scopes, audience, expires_at, consumed_at, authentication
            ) VALUES ($3, convert_to($3::text, 'UTF8'), $5, $1, $2, 'https://client.example',
                'challenge', '[]', 'test', now() - interval '2 days', now() - interval '2 days', '{}')
        )
        INSERT INTO refresh_token_families (
            id, user_id, client_id, session_id, authorization_code_id, audience, scopes,
            authentication
        ) VALUES ($4, $1, $5, $2, $3, 'test', '[]', '{}')",
    )
    .bind(user)
    .bind(session)
    .bind(code)
    .bind(family)
    .bind(&client)
    .execute(&pool)
    .await
    .expect("redeemed grant");
    let link = || async {
        sqlx::query_scalar::<_, Option<uuid::Uuid>>(
            "SELECT authorization_code_id FROM refresh_token_families WHERE id = $1",
        )
        .bind(family)
        .fetch_one(&pool)
        .await
        .expect("family link")
    };
    database
        .maintenance()
        .purge_expired_auth_state(1000)
        .await
        .expect("purge");
    assert_eq!(link().await, Some(code), "a live grant keeps its code");
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
        .bind(session)
        .execute(&pool)
        .await
        .expect("end session");
    database
        .maintenance()
        .purge_expired_auth_state(1000)
        .await
        .expect("purge");
    assert_eq!(link().await, None, "an ended session releases its code");
}

/// Migration versions count up from 1 with no gaps or repeats. Two branches
/// that each add the next migration under different names fail here once the
/// second is rebased, instead of failing every database test at runtime.
#[test]
fn migration_versions_are_unique_and_contiguous() {
    for (expected, migration) in (1..).zip(MIGRATOR.iter()) {
        assert_eq!(
            migration.version, expected,
            "migration {} ({}) should be numbered {expected:04}; renumber it after the latest migration on main",
            migration.version, migration.description,
        );
    }
}

/// Only plain lowercase identifiers can be provisioned, so SQL never quotes them.
#[test]
fn runtime_roles_need_plain_names() {
    let role = |user: &str| {
        let url = format!("postgres://{user}@localhost/sourceorigin?host=/run/postgresql");
        RuntimeRole::new(
            &DatabaseConfig::new(&url, 1, Duration::from_secs(1)).expect("config"),
            "password",
        )
    };
    assert!(role("sourceorigin_auth").is_ok());
    assert!(role(&"a".repeat(63)).is_ok());
    for user in [
        "SourceOrigin",
        "1auth",
        "auth-service",
        "a%24%24b",
        &"a".repeat(64),
    ] {
        assert!(
            matches!(role(user), Err(crate::DatabaseConnectionError::RoleName)),
            "accepted {user}"
        );
    }
}

/// The runtime role reads and writes app rows, and appends history, but cannot
/// set an event's chain columns, transaction, time or sequence, attach personal
/// data to another transaction's event, forge a checkpoint, rewrite history, reach
/// migrations, change the schema, create temporary tables or run programs. The
/// service's cleanup still works with it, and overlapping provisioning runs are safe.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn runtime_role_has_only_row_privileges() {
    let owner = Database {
        pool: Database::test_pool().await,
    };
    let name = format!("sourceorigin_auth_{}", uuid::Uuid::now_v7().simple());
    let config = config_for(&name);
    let role = RuntimeRole::new(&config, "runtime password").expect("role");
    // Overlapping runs, as two `migrate` jobs: one creates the role, the other
    // waits for it, then resets it.
    let (first, second) = tokio::join!(owner.provision(&role), owner.provision(&role));
    first.expect("create or reset");
    second.expect("create or reset");
    let runtime = Database::connect(config.with_password("runtime password"))
        .await
        .expect("log in as the runtime role");

    // Rolled back, since other tests consume every event.
    let mut append = runtime.pool.begin().await.expect("begin");
    sqlx::query(
        "INSERT INTO domain_events (id, kind, version, payload, actor)
        VALUES (uuidv7(), 'test', 1, '{}', '{}')",
    )
    .execute(&mut *append)
    .await
    .expect("append an event");
    append.rollback().await.expect("rollback");
    assert!(
        owner.audit().may_prune().await.expect("owner"),
        "the owner prunes"
    );
    assert!(
        !runtime.audit().may_prune().await.expect("runtime"),
        "auth never prunes"
    );
    // Sealing locks unsealed events and sets their chain columns, nothing else.
    let mut seal = runtime.begin().await.expect("begin");
    seal.audit()
        .unsealed(1, EventContent::UNTAGGED)
        .await
        .expect("lock unsealed events");
    seal.rollback().await.expect("rollback");
    sqlx::query(
        "UPDATE domain_events
        SET chain_position = chain_position, chain_hash = chain_hash, chain_format = chain_format
        WHERE false",
    )
    .execute(&runtime.pool)
    .await
    .expect("seal");
    runtime
        .maintenance()
        .purge_expired_auth_state(1000)
        .await
        .expect("cleanup");
    for statement in [
        "INSERT INTO domain_events (id, kind, version, payload, actor, chain_position, chain_hash)
        VALUES (uuidv7(), 'test', 1, '{}', '{}', 1, sha256(''))",
        "INSERT INTO domain_events (id, kind, version, payload, actor, txid)
        VALUES (uuidv7(), 'test', 1, '{}', '{}', '1')",
        "INSERT INTO domain_events (id, kind, version, payload, actor, occurred_at)
        VALUES (uuidv7(), 'test', 1, '{}', '{}', now() - INTERVAL '1 year')",
        "INSERT INTO domain_events (id, kind, version, payload, actor, sequence)
        OVERRIDING SYSTEM VALUE VALUES (uuidv7(), 'test', 1, '{}', '{}', 1)",
        "INSERT INTO event_personal_data (event_id, created_at) VALUES (uuidv7(), now())",
        "UPDATE domain_events SET kind = kind",
        "DELETE FROM domain_events",
        "UPDATE event_personal_data SET client_ip = client_ip",
        "UPDATE audit_checkpoints SET note = note",
        "DELETE FROM audit_checkpoints",
        "UPDATE audit_anchor SET position = position",
        "INSERT INTO audit_anchor (position) VALUES (1)",
        "DELETE FROM event_consumers",
        "SELECT FROM _sqlx_migrations",
        "CREATE TABLE shadow (id INT)",
        "CREATE TEMPORARY TABLE shadow (id INT)",
        "ALTER TABLE users DISABLE TRIGGER ALL",
        "SET session_replication_role = replica",
        "COPY (SELECT 1) TO PROGRAM 'true'",
    ] {
        assert_eq!(
            refusal(&runtime, sqlx::query(statement)).await,
            "42501",
            "{statement}"
        );
    }
    assert_personal_data_only_erases(&runtime).await;
    assert_history_is_never_forged(&runtime).await;
    runtime.pool.close().await;

    under_provisioning_lock(&owner, &format!("DROP OWNED BY {name}; DROP ROLE {name}")).await;
}

/// Runs `sql`, which changes roles or privileges, as `owner` in one transaction
/// under provisioning's lock: concurrent tests provision too, and the database's
/// and schema's privileges are each one catalog row.
async fn under_provisioning_lock(owner: &Database, sql: &str) {
    let locked = format!(
        "SELECT pg_advisory_xact_lock({}); {sql}",
        LockKey::Provisioning.id()
    );
    sqlx::raw_sql(&locked)
        .execute(&owner.pool)
        .await
        .expect(sql);
}

/// Connection settings for `user` on `TEST_DATABASE_URL`, without a password.
fn config_for(user: &str) -> DatabaseConfig {
    let mut url = url::Url::parse(&std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL"))
        .expect("test URL");
    url.set_username(user).expect("user");
    url.set_password(None).expect("password");
    DatabaseConfig::new(url.as_str(), 1, Duration::from_secs(5)).expect("config")
}

/// Provisioning resets what an existing role holds beyond its grants: settings,
/// such as replica mode, which skips every trigger, and privileges on the
/// database and schema. A large object or default privileges it owns, which any
/// role may create, do not stop provisioning.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn provisioning_resets_what_it_does_not_grant() {
    let owner = Database {
        pool: Database::test_pool().await,
    };
    let name = format!("sourceorigin_auth_{}", uuid::Uuid::now_v7().simple());
    let role = RuntimeRole::new(&config_for(&name), "password").expect("role");
    owner.provision(&role).await.expect("create");
    let database: String = sqlx::query_scalar("SELECT current_database()::text")
        .fetch_one(&owner.pool)
        .await
        .expect("database");
    let object: i64 = sqlx::query_scalar("SELECT lo_create(0)::text::bigint")
        .fetch_one(&owner.pool)
        .await
        .expect("large object");
    let setup = format!(
        "ALTER ROLE {name} SET session_replication_role = replica;
        ALTER ROLE {name} IN DATABASE {database} SET session_replication_role = replica;
        GRANT CREATE ON DATABASE {database} TO {name};
        GRANT CREATE ON SCHEMA public TO {name};
        ALTER LARGE OBJECT {object} OWNER TO {name};
        ALTER DEFAULT PRIVILEGES FOR ROLE {name} GRANT SELECT ON TABLES TO PUBLIC;"
    );
    under_provisioning_lock(&owner, &setup).await;
    owner.provision(&role).await.expect("reset");
    let (settings, create): (i64, bool) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole
            WHERE r.rolname = $1),
            has_database_privilege($1, current_database(), 'CREATE')
            OR has_schema_privilege($1, 'public', 'CREATE')",
    )
    .bind(&name)
    .fetch_one(&owner.pool)
    .await
    .expect("what remains");
    assert_eq!((settings, create), (0, false));
    under_provisioning_lock(&owner, &format!("DROP OWNED BY {name}; DROP ROLE {name}")).await;
}

/// Provisioning refuses a role that could do more than the grants allow: the
/// schema owner, a member of another role, which keeps that role's privileges,
/// and the owner of anything, which could change it.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn provisioning_refuses_roles_that_could_do_more() {
    let owner = Database {
        pool: Database::test_pool().await,
    };
    let owner_name = sqlx::query_scalar::<_, String>("SELECT current_user::text")
        .fetch_one(&owner.pool)
        .await
        .expect("owner");
    let error = owner
        .provision(&RuntimeRole::new(&config_for(&owner_name), "password").expect("role"))
        .await
        .expect_err("the owner is refused");
    assert!(format!("{error:?}").contains("must not be the schema owner"));

    let name = format!("sourceorigin_auth_{}", uuid::Uuid::now_v7().simple());
    let role = RuntimeRole::new(&config_for(&name), "password").expect("role");
    for (setup, undo, refusal) in [
        (
            format!("CREATE ROLE {name}_group; GRANT {name}_group TO {name}"),
            format!("DROP ROLE {name}_group"),
            "must not be a member of another role",
        ),
        (
            format!("CREATE SCHEMA {name} AUTHORIZATION {name}"),
            format!("DROP SCHEMA {name}"),
            "must not own anything",
        ),
        (
            format!("GRANT SET ON PARAMETER session_replication_role TO {name}"),
            format!("REVOKE SET ON PARAMETER session_replication_role FROM {name}"),
            "must not be granted any server parameter",
        ),
    ] {
        under_provisioning_lock(&owner, &format!("CREATE ROLE {name}; {setup}")).await;
        let error = owner.provision(&role).await.expect_err(refusal);
        assert!(format!("{error:?}").contains(refusal), "{error:?}");
        under_provisioning_lock(&owner, &format!("{undo}; DROP ROLE {name}")).await;
    }
}

/// Every function pins its `search_path` with `pg_temp` last, so temporary tables
/// cannot shadow the tables it reads: left out, `pg_temp` is searched first.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn functions_pin_their_search_path() {
    let pool = Database::test_pool().await;
    let unpinned: Vec<String> = sqlx::query_scalar(
        "SELECT proname::text FROM pg_proc
        WHERE pronamespace = 'public'::regnamespace
        AND NOT EXISTS (
            SELECT FROM unnest(proconfig) setting
            WHERE setting LIKE 'search_path=%' AND setting LIKE '%, pg_temp'
        )",
    )
    .fetch_all(&pool)
    .await
    .expect("functions");
    assert!(unpinned.is_empty(), "unpinned functions: {unpinned:?}");
}

/// Only their owner may execute functions that run as their owner, so the runtime
/// role cannot attach one to a table of its own and have it run its SQL.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn functions_running_as_their_owner_are_not_executable_by_others() {
    let pool = Database::test_pool().await;
    let executable: Vec<String> = sqlx::query_scalar(
        "SELECT proname::text FROM pg_proc
        WHERE pronamespace = 'public'::regnamespace
        AND prosecdef
        AND EXISTS (
            SELECT FROM aclexplode(coalesce(proacl, acldefault('f', proowner))) privilege
            WHERE privilege.grantee <> proowner AND privilege.privilege_type = 'EXECUTE'
        )",
    )
    .fetch_all(&pool)
    .await
    .expect("functions");
    assert!(
        executable.is_empty(),
        "executable by others: {executable:?}"
    );
}

/// Every connection starts with the default limits. A statement past its limit is
/// cancelled, and a lock wait past its limit fails, each with its own error.
/// Each transaction lowers its limit, so the test need not wait out the defaults.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn statements_and_lock_waits_past_their_limits_fail() {
    Database::test_pool().await;
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let config = DatabaseConfig::new(&url, 2, Duration::from_secs(5)).expect("configuration");
    let database = Database::connect(config).await.expect("connect");
    let settings: Vec<String> = sqlx::query_scalar(
        "SELECT current_setting(name) FROM unnest(ARRAY[
            'statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout',
            'transaction_timeout'
        ]) AS name",
    )
    .fetch_all(&database.pool)
    .await
    .expect("settings");
    assert_eq!(settings, ["15s", "5s", "30s", "0"]);

    let limit = Duration::from_millis(100);
    let mut slow = database.begin().await.expect("transaction");
    Limit::STATEMENT
        .at(limit)
        .set(Scope::Transaction)
        .fetch_one(&mut *slow.inner)
        .await
        .expect("statement limit");
    let cancelled = sqlx::query("SELECT pg_sleep(1)")
        .execute(&mut *slow.inner)
        .await
        .map_err(DatabaseError::from);
    assert!(
        matches!(cancelled, Err(DatabaseError::Cancelled(_))),
        "{cancelled:?}"
    );
    drop(slow);

    // A key no other test takes.
    let key = i64::from_be_bytes(*b"timeout!");
    let mut holder = database.begin().await.expect("transaction");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *holder.inner)
        .await
        .expect("lock");
    let mut waiter = database.begin().await.expect("transaction");
    Limit::LOCK
        .at(limit)
        .set(Scope::Transaction)
        .fetch_one(&mut *waiter.inner)
        .await
        .expect("lock limit");
    let unavailable = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *waiter.inner)
        .await
        .map_err(DatabaseError::from);
    assert!(
        matches!(unavailable, Err(DatabaseError::LockUnavailable(_))),
        "{unavailable:?}"
    );
}

/// Runs `query` as `runtime` in a transaction it rolls back, so a regressed
/// grant cannot harm concurrent tests, and returns the code it is refused with.
async fn refusal(runtime: &Database, query: Query<'_, Postgres, PgArguments>) -> String {
    let mut probe = runtime.pool.begin().await.expect("begin");
    let error = query.execute(&mut *probe).await.expect_err("refused");
    probe.rollback().await.expect("rollback");
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map_or_else(|| error.to_string(), Into::into)
}

/// Inserts an event as auth does, in `connection`'s transaction, and returns its ID.
async fn insert_event(connection: &mut PgConnection) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO domain_events (id, kind, version, payload, actor)
        VALUES (uuidv7(), 'test', 1, '{}', '{}') RETURNING id",
    )
    .fetch_one(connection)
    .await
    .expect("event")
}

/// Erasing a purged owner's origins removes values from `details` as `runtime`;
/// no update may add or change one.
async fn assert_personal_data_only_erases(runtime: &Database) {
    for (statement, allowed) in [
        (
            "UPDATE event_personal_data SET details = details - '/origin'",
            true,
        ),
        (
            "UPDATE event_personal_data SET details = details || '{\"/origin\": 1}'",
            false,
        ),
    ] {
        let mut probe = runtime.pool.begin().await.expect("begin");
        let event = insert_event(&mut probe).await;
        sqlx::query(
            "INSERT INTO event_personal_data (event_id, details)
            VALUES ($1, '{\"/origin\": \"https://a.example\", \"/name\": \"A\"}')",
        )
        .bind(event)
        .execute(&mut *probe)
        .await
        .expect("personal data");
        let updated = sqlx::query(statement).execute(&mut *probe).await;
        probe.rollback().await.expect("rollback");
        match updated {
            Ok(_) => assert!(allowed, "{statement} was allowed"),
            Err(error) => {
                assert!(!allowed, "{statement}: {error}");
                let code = error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code);
                assert_eq!(code.as_deref(), Some("23000"), "{statement}: {error}");
            }
        }
    }
}

/// A checkpoint `runtime` inserts must sign a sealed event's hash, and an event it
/// inserts must be JSON auth can read back, or sealing would fail on it.
/// `personal_data_is_recorded_only_with_its_event` covers attaching personal data
/// to an older event, which needs a committed event, so a schema of its own.
async fn assert_history_is_never_forged(runtime: &Database) {
    for payload in [
        r#"{"n": 1e400}"#.to_owned(),
        format!("{}{}", "[".repeat(100), "]".repeat(100)),
        format!(r#"{{"s": "{}"}}"#, "a".repeat(9_000)),
    ] {
        let unreadable = sqlx::query(
            "INSERT INTO domain_events (id, kind, version, payload, actor)
            VALUES (uuidv7(), 'test', 1, $1::jsonb, '{}')",
        )
        .bind(&payload);
        assert_eq!(refusal(runtime, unreadable).await, "23514", "{payload}");
    }
    let forged = sqlx::query(
        "INSERT INTO audit_checkpoints (position, head, created_at, note)
        VALUES (9223372036854775807, sha256(''), now(), 'forged')",
    );
    assert_eq!(
        refusal(runtime, forged).await,
        "23000",
        "a forged checkpoint"
    );
}
