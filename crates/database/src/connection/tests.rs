//! Focused persistence and security contract tests.

use super::{Database, DatabaseConfig, MIGRATOR, RuntimeRole};
use sqlx::postgres::PgSslMode;
use std::time::Duration;
/// TCP requires verified TLS unless plaintext is explicitly selected.
#[test]
fn production_requires_verified_tls() {
    assert!(
        DatabaseConfig::new("postgres://db.example/piquel", 1, Duration::from_secs(1)).is_err()
    );
    assert!(
        DatabaseConfig::new(
            "postgres://db.example/piquel?sslmode=verify-full",
            1,
            Duration::from_secs(1)
        )
        .is_ok()
    );
    assert!(
        DatabaseConfig::new(
            "postgres://db.example/piquel?ssl-mode=verify-full",
            1,
            Duration::from_secs(1)
        )
        .is_ok()
    );
    for mode in ["prefer", "require", "verify-ca"] {
        assert!(
            DatabaseConfig::new(
                &format!("postgres://db.example/piquel?sslmode={mode}"),
                1,
                Duration::from_secs(1)
            )
            .is_err(),
            "accepted unverified TLS mode {mode}"
        );
    }
}
/// Explicit plaintext is accepted without silently enabling opportunistic TLS.
#[test]
fn plaintext_tcp_requires_explicit_opt_in() {
    let config = DatabaseConfig::new(
        "postgres://postgres:5432/piquel?sslmode=disable",
        1,
        Duration::from_secs(1),
    )
    .expect("explicit plaintext is allowed");
    assert!(matches!(config.options.get_ssl_mode(), PgSslMode::Disable));
}
/// Unix sockets require an absolute path and cannot replace remote TCP hosts.
#[test]
fn unix_sockets_are_explicit_and_cannot_override_tcp_hosts() {
    let config = DatabaseConfig::new(
        "postgres://piquel:password@localhost/piquel?host=/run/postgresql&sslmode=disable",
        1,
        Duration::from_secs(1),
    )
    .expect("local socket does not require TLS");
    assert_eq!(
        config.options.get_socket().map(std::path::PathBuf::as_path),
        Some(std::path::Path::new("/run/postgresql"))
    );
    for url in [
        "postgres://db.example/piquel?host=/run/postgresql",
        "postgres://localhost/piquel?host=relative/path",
        "postgres://localhost/piquel?host=/run/postgresql&host=db.example",
        "postgres://localhost/piquel?host=db.example&host=/run/postgresql",
        "postgres://localhost/piquel?host=/run/postgresql&hostaddr=192.0.2.1",
    ] {
        assert!(DatabaseConfig::new(url, 1, Duration::from_secs(1)).is_err());
    }
}
/// Repeated transport settings and host overrides are rejected before `SQLx` parses them.
#[test]
fn production_rejects_ambiguous_tls_modes_and_host_overrides() {
    for url in [
        "postgres://db.example/piquel?sslmode=verify-full&sslmode=disable",
        "postgres://db.example/piquel?sslmode=disable&sslmode=verify-full",
        "postgres://db.example/piquel?sslmode=verify-full&ssl-mode=disable",
        "postgres://db.example/piquel?sslmode=verify-full&ssl-mode=verify-full",
        "postgres://db.example/piquel?sslmode=verify-full&host=elsewhere.example",
        "postgres://db.example/piquel?sslmode=verify-full&hostaddr=127.0.0.1",
    ] {
        assert!(
            DatabaseConfig::new(url, 1, Duration::from_secs(1)).is_err(),
            "accepted ambiguous database URL: {url}"
        );
    }
}

/// Loopback TCP also needs an explicit plaintext opt-in.
#[test]
fn loopback_requires_explicit_transport() {
    for host in ["localhost", "[::1]", "127.0.0.1"] {
        assert!(
            DatabaseConfig::new(
                &format!("postgres://{host}/test"),
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            DatabaseConfig::new(
                &format!("postgres://{host}/test?sslmode=disable"),
                1,
                Duration::from_secs(1)
            )
            .is_ok()
        );
    }
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
            INSERT INTO users (id, username, display_name) VALUES ($1, $5, 'Purge')
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

/// Startup failures identify the invalid transport or pool setting without printing credentials.
#[test]
fn configuration_errors_name_the_constraint_and_preserve_parsers() {
    use crate::DatabaseConnectionError;
    let timeout = Duration::from_secs(1);
    assert!(matches!(
        DatabaseConfig::new("https://db.example/test", 1, timeout),
        Err(DatabaseConnectionError::Scheme)
    ));
    assert!(matches!(
        DatabaseConfig::new("postgres://db.example/test?sslmode=verify-full", 0, timeout),
        Err(DatabaseConnectionError::ZeroPoolBound)
    ));
    assert!(matches!(
        DatabaseConfig::new(
            "postgres://db.example/test?sslmode=verify-full",
            1,
            Duration::ZERO
        ),
        Err(DatabaseConnectionError::ZeroPoolBound)
    ));
    assert!(matches!(
        DatabaseConfig::new(
            "postgres://db.example/test?sslmode=verify-full&ssl-mode=disable",
            1,
            timeout
        ),
        Err(DatabaseConnectionError::AmbiguousTransport)
    ));
    assert!(matches!(
        DatabaseConfig::new("postgres://db.example/test", 1, timeout),
        Err(DatabaseConnectionError::InsecureTransport)
    ));
    let error = DatabaseConfig::new("not a URL", 1, timeout).expect_err("absolute URL");
    assert!(std::error::Error::source(&error).is_some());
    let error = DatabaseConfig::new("postgres://user:secret@db.example/test", 1, timeout)
        .expect_err("verified transport");
    assert!(!error.to_string().contains("secret"));
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
        let url = format!("postgres://{user}@localhost/piquel?host=/run/postgresql");
        RuntimeRole::new(
            &DatabaseConfig::new(&url, 1, Duration::from_secs(1)).expect("config"),
            "password",
        )
    };
    assert!(role("piquel_auth").is_ok());
    assert!(role(&"a".repeat(63)).is_ok());
    for user in [
        "Piquel",
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
/// rewrite history, reach migrations, change the schema or run programs. The
/// service's cleanup still works with it, and overlapping provisioning runs are safe.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn runtime_role_has_only_row_privileges() {
    let owner = Database {
        pool: Database::test_pool().await,
    };
    let name = format!("piquel_auth_{}", uuid::Uuid::now_v7().simple());
    let mut url = url::Url::parse(&std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL"))
        .expect("test URL");
    url.set_username(&name).expect("user");
    url.set_password(None).expect("password");
    let config = DatabaseConfig::new(url.as_str(), 1, Duration::from_secs(5)).expect("config");
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
    runtime
        .maintenance()
        .purge_expired_auth_state(1000)
        .await
        .expect("cleanup");
    for statement in [
        "UPDATE domain_events SET kind = kind",
        "DELETE FROM domain_events",
        "UPDATE event_personal_data SET details = details",
        "DELETE FROM event_consumers",
        "SELECT FROM _sqlx_migrations",
        "CREATE TABLE shadow (id INT)",
        "ALTER TABLE users DISABLE TRIGGER ALL",
        "SET session_replication_role = replica",
        "COPY (SELECT 1) TO PROGRAM 'true'",
    ] {
        // Rolled back, so a regressed grant cannot harm concurrent tests.
        let mut probe = runtime.pool.begin().await.expect("begin");
        let error = sqlx::query(statement)
            .execute(&mut *probe)
            .await
            .expect_err(statement);
        probe.rollback().await.expect("rollback");
        let code = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code);
        assert_eq!(code.as_deref(), Some("42501"), "{statement}: {error}");
    }
    runtime.pool.close().await;

    let owner_name = sqlx::query_scalar::<_, String>("SELECT current_user::text")
        .fetch_one(&owner.pool)
        .await
        .expect("owner");
    url.set_username(&owner_name).expect("user");
    let config = DatabaseConfig::new(url.as_str(), 1, Duration::from_secs(5)).expect("config");
    let error = owner
        .provision(&RuntimeRole::new(&config, "password").expect("role"))
        .await
        .expect_err("the owner is refused");
    assert!(format!("{error:?}").contains("must not be the schema owner"));

    sqlx::raw_sql(&format!("DROP OWNED BY {name}; DROP ROLE {name}"))
        .execute(&owner.pool)
        .await
        .expect("drop the role");
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
