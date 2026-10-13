//! Focused persistence and security contract tests.

use super::{Database, DatabaseConfig};
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
    sqlx::query(
        "INSERT INTO request_limits (bucket, requests, expires_at)
        VALUES ($1, 1, now() - interval '1 minute')",
    )
    .bind(&bucket)
    .execute(&pool)
    .await
    .expect("expired limit");
    let mut request = pool.begin().await.expect("request transaction");
    sqlx::query("SELECT 1 FROM request_limits WHERE bucket=$1 FOR UPDATE")
        .bind(&bucket)
        .execute(&mut *request)
        .await
        .expect("lock");
    let database = Database { pool: pool.clone() };
    tokio::time::timeout(
        Duration::from_secs(2),
        database.purge_expired_auth_state(1000),
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
