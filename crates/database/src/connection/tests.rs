use super::{Database, DatabaseConfig};
use sqlx::postgres::PgSslMode;
use std::time::Duration;

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
        assert!(DatabaseConfig::new_development(url, 1, Duration::from_secs(1)).is_err());
    }
}

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

#[test]
fn development_requires_verified_tls_outside_loopback() {
    assert!(
        DatabaseConfig::new_development("postgres://[::1]/test", 1, Duration::from_secs(1)).is_ok()
    );
    assert!(
        DatabaseConfig::new_development("postgres://localhost/piquel", 1, Duration::from_secs(1))
            .is_ok()
    );
    assert!(
        DatabaseConfig::new_development("postgres://db.example/piquel", 1, Duration::from_secs(1))
            .is_err()
    );
    assert!(
        DatabaseConfig::new_development(
            "postgres://localhost/piquel?host=db.example",
            1,
            Duration::from_secs(1)
        )
        .is_err()
    );
    for mode in ["prefer", "require", "verify-ca"] {
        assert!(
            DatabaseConfig::new_development(
                &format!("postgres://db.example/piquel?sslmode={mode}"),
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
    let config = DatabaseConfig::new_development(
        "postgres://db.example/piquel?sslmode=verify-full",
        1,
        Duration::from_secs(1),
    )
    .expect("verified remote database is safe in development");
    assert!(matches!(
        config.options.get_ssl_mode(),
        PgSslMode::VerifyFull
    ));
}

/// Cleanup skips rows a live request has locked instead of waiting on them.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn cleanup_skips_rows_locked_by_requests() {
    let pool = crate::repositories::test_pool().await;
    let bucket = uuid::Uuid::now_v7().as_bytes().to_vec();
    sqlx::query(
        "INSERT INTO request_limits(bucket,requests,expires_at) VALUES($1,1,now()-interval '1 minute')",
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
