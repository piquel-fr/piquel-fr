//! Focused persistence and security contract tests.

use super::{Database, DatabaseConfig, RUNTIME_ROLE_LOCK, RuntimeRole};
use crate::DatabaseError;
use sqlx::PgPool;
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
                pkce_challenge, scopes, audience, expires_at, consumed_at
            ) VALUES ($3, convert_to($3::text, 'UTF8'), $5, $1, $2, 'https://client.example',
                'challenge', '[]', 'test', now() - interval '2 days', now() - interval '2 days')
        )
        INSERT INTO refresh_token_families (
            id, user_id, client_id, session_id, authorization_code_id, audience, scopes
        ) VALUES ($4, $1, $5, $2, $3, 'test', '[]')",
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
        .purge_expired_auth_state(1000)
        .await
        .expect("purge");
    assert_eq!(link().await, None, "an ended session releases its code");
}

/// A disposable runtime role, provisioned through the migrated test database.
struct RoleFixture {
    /// The schema owner that provisions the role.
    owner: Database,
    /// Unique role name, so concurrent tests never share a role.
    name: String,
    /// Test database connection settings for the role, without a password.
    config: DatabaseConfig,
}

impl RoleFixture {
    /// Migrates the test database and names a fresh role.
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let mut config = DatabaseConfig::new(&url, 1, Duration::from_secs(5)).expect("test URL");
        let name = format!("piquel_runtime_{}", uuid::Uuid::now_v7().simple());
        config.options = config.options.username(&name);
        Self {
            owner: Database {
                pool: Database::test_pool().await,
            },
            name,
            config,
        }
    }

    /// Runs `sql` as the owner, replacing `{role}` and `{database}`.
    /// It holds the provisioning lock: another test provisioning concurrently
    /// would otherwise make these catalog updates fail.
    async fn owner_sql(&self, sql: &str) {
        let mut transaction = self.owner.pool.begin().await.expect("begin");
        let database: String =
            sqlx::query_scalar("SELECT current_database()::text FROM pg_advisory_xact_lock($1)")
                .bind(RUNTIME_ROLE_LOCK)
                .fetch_one(&mut *transaction)
                .await
                .expect("provisioning lock");
        let sql = sql
            .replace("{role}", &self.name)
            .replace("{database}", &database);
        sqlx::raw_sql(&sql)
            .execute(&mut *transaction)
            .await
            .expect("owner SQL");
        transaction.commit().await.expect("commit owner SQL");
    }

    /// Provisions the role with `password`, as `migrate` does.
    async fn grant(&self, password: &str) -> Result<(), DatabaseError> {
        self.owner
            .grant_runtime_role(&RuntimeRole::new(&self.config, password))
            .await
    }

    /// Asserts that provisioning with `password` fails, naming `reason`.
    async fn refused(&self, password: &str, reason: &str) {
        let error = self.grant(password).await.expect_err("refused");
        let chain = piquel_common::ErrorChain(&error).to_string();
        assert!(chain.contains(reason), "{chain}");
    }

    /// Connects as the role with `password`.
    async fn connect(&self, password: &str) -> PgPool {
        Database::connect(self.config.clone().with_password(password))
            .await
            .expect("connect as the runtime role")
            .pool
    }

    /// Revokes everything granted to the role and drops it.
    async fn drop_role(&self) {
        self.owner_sql(r#"DROP OWNED BY "{role}"; DROP ROLE "{role}""#)
            .await;
    }
}

/// The runtime role can sign a user up, including the trigger-maintained email
/// ownership, but cannot change the schema, rewrite audit history, read migration
/// history, create temporary tables or run server programs, even after the owner
/// granted it more outside `migrate`. The next run also rotates its password.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn runtime_role_holds_only_row_privileges() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    role.owner_sql(
        r#"GRANT TRUNCATE ON security_audit_log TO "{role}";
        GRANT SELECT ON _sqlx_migrations TO "{role}";
        GRANT CREATE ON SCHEMA public TO "{role}";
        GRANT CREATE, TEMPORARY ON DATABASE "{database}" TO "{role}""#,
    )
    .await;
    role.grant("second").await.expect("reset runtime role");
    let runtime = role.connect("second").await;

    let user = uuid::Uuid::now_v7();
    let mut signup = runtime.begin().await.expect("begin");
    sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Runtime test')")
        .bind(user)
        .bind(format!("runtime-{user}"))
        .execute(&mut *signup)
        .await
        .expect("insert user");
    sqlx::query(
        "INSERT INTO user_emails(id,user_id,normalized_email,verified_at,is_primary)
        VALUES($1,$2,$3,now(),true)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(user)
    .bind(format!("{user}@example.com"))
    .execute(&mut *signup)
    .await
    .expect("claim email ownership through the trigger");
    sqlx::query(
        "INSERT INTO security_audit_log(id,user_id,action,outcome) VALUES($1,$2,'login','success')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(user)
    .execute(&mut *signup)
    .await
    .expect("append audit event");
    signup.commit().await.expect("commit signup");

    let privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolcreaterole
            OR has_table_privilege(current_user, 'security_audit_log', 'TRUNCATE')
            OR has_database_privilege(current_user, current_database(), 'CREATE')
        FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&runtime)
    .await
    .expect("role attributes and privileges");
    assert!(!privileged);
    // `WHERE false` still checks privileges without touching other tests' rows.
    for forbidden in [
        "CREATE TABLE runtime_role_test (id INT)",
        "CREATE TEMP TABLE runtime_role_test (id INT)",
        "ALTER TABLE user_emails DISABLE TRIGGER ALL",
        "UPDATE security_audit_log SET outcome = outcome WHERE false",
        "DELETE FROM security_audit_log WHERE false",
        "SELECT 1 FROM _sqlx_migrations",
        "SET session_replication_role = replica",
        "COPY (SELECT 1) TO PROGRAM 'true'",
    ] {
        assert!(
            sqlx::query(forbidden).execute(&runtime).await.is_err(),
            "{forbidden}"
        );
    }
    runtime.close().await;
    role.drop_role().await;
}

/// The migration role cannot demote itself, and an existing role that belongs to
/// another role or owns an object is refused without any change, since revoking
/// privileges would leave either in place.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn runtime_role_with_memberships_or_objects_is_refused() {
    let role = RoleFixture::new().await;
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let owner_config = DatabaseConfig::new(&url, 1, Duration::from_secs(5)).expect("test URL");
    assert!(
        role.owner
            .grant_runtime_role(&RuntimeRole::new(&owner_config, "unused"))
            .await
            .is_err()
    );
    role.owner_sql(
        r#"CREATE ROLE "{role}" LOGIN PASSWORD 'kept'; GRANT pg_read_server_files TO "{role}""#,
    )
    .await;
    role.refused("replaced", "must not belong to other roles or own objects")
        .await;
    // The refused run rolled back, so the role keeps its old password.
    role.connect("kept").await.close().await;
    role.owner_sql(
        r#"REVOKE pg_read_server_files FROM "{role}"; CREATE SCHEMA "{role}" AUTHORIZATION "{role}""#,
    )
    .await;
    role.refused("replaced", "must not belong to other roles or own objects")
        .await;
    // Large objects have owners too.
    role.owner_sql(
        r#"DROP SCHEMA "{role}";
        DO $lo$ BEGIN
            EXECUTE format('ALTER LARGE OBJECT %s OWNER TO %I', lo_create(0), '{role}');
        END $lo$"#,
    )
    .await;
    role.refused("replaced", "must not belong to other roles or own objects")
        .await;
    role.drop_role().await;
}

/// Privileges granted to PUBLIC, including its default temporary tables, are
/// revoked, since every role inherits them.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn public_grants_are_revoked() {
    let role = RoleFixture::new().await;
    role.owner_sql(
        r#"GRANT TRUNCATE ON security_audit_log TO PUBLIC;
        GRANT TEMPORARY ON DATABASE "{database}" TO PUBLIC;
        CREATE SEQUENCE "{role}_sequence";
        GRANT SELECT, UPDATE ON SEQUENCE "{role}_sequence" TO PUBLIC"#,
    )
    .await;
    role.grant("password")
        .await
        .expect("provision runtime role");
    let runtime = role.connect("password").await;
    let inherited: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(current_user, 'security_audit_log', 'TRUNCATE')
            OR has_database_privilege(current_user, current_database(), 'TEMPORARY')
            OR has_sequence_privilege(current_user, $1, 'SELECT, UPDATE')",
    )
    .bind(format!("{}_sequence", role.name))
    .fetch_one(&runtime)
    .await
    .expect("effective privileges");
    assert!(!inherited);
    runtime.close().await;
    role.owner_sql(r#"DROP SEQUENCE "{role}_sequence""#).await;
    role.drop_role().await;
}

/// PUBLIC can create large objects by default, which the role would then own,
/// so every later provisioning run would refuse it, and take advisory locks,
/// which could stall `migrate` indefinitely.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn public_cannot_create_large_objects_or_take_advisory_locks() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    let runtime = role.connect("first").await;
    for create in [
        "SELECT lo_create(0)",
        "SELECT lo_creat(-1)",
        "SELECT lo_from_bytea(0, 'x')",
        "SELECT pg_try_advisory_lock(1)",
        "SELECT pg_advisory_xact_lock(1)",
    ] {
        assert!(
            sqlx::query(create).execute(&runtime).await.is_err(),
            "{create}"
        );
    }
    runtime.close().await;
    role.grant("second").await.expect("rotate password");
    role.drop_role().await;
}

/// PUBLIC may still connect to the cluster's other databases, where the role
/// can create a large object and set its own per-database settings. Neither
/// applies here, so they cannot block provisioning.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn other_databases_cannot_block_provisioning() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    // PUBLIC may connect to `postgres` and `template1` by default. The test
    // database may itself be `postgres`, so pick another one, templates last.
    let database: String = sqlx::query_scalar(
        "SELECT datname::text FROM pg_database
        WHERE datname <> current_database() AND datallowconn
        AND has_database_privilege($1, datname, 'CONNECT')
        ORDER BY datistemplate, datname LIMIT 1",
    )
    .bind(&role.name)
    .fetch_one(&role.owner.pool)
    .await
    .expect("another database");
    let mut elsewhere = role.config.clone().with_password("first");
    elsewhere.options = elsewhere.options.database(&database);
    let other = Database::connect(elsewhere)
        .await
        .expect("connect to another database")
        .pool;
    // DROP ROLE in `drop_role` removes this setting.
    sqlx::query(&format!(
        r#"ALTER ROLE CURRENT_USER IN DATABASE "{database}" SET work_mem = '4MB'"#
    ))
    .execute(&other)
    .await
    .expect("setting for another database");
    let object: sqlx::postgres::types::Oid = sqlx::query_scalar("SELECT lo_create(0)")
        .fetch_one(&other)
        .await
        .expect("large object in another database");
    let rotated = role.grant("second").await;
    // DROP OWNED in `drop_role` only reaches this database. The open connection
    // outlives the password change, so the role removes its own object, before
    // any assertion can fail; DROP OWNED there would race other tests' updates
    // to shared catalog rows.
    sqlx::query("SELECT lo_unlink($1)")
        .bind(object)
        .execute(&other)
        .await
        .expect("unlink the large object");
    rotated.expect("rotate password");
    other.close().await;
    role.drop_role().await;
}

/// Default privileges need no privilege to set and are owned by the role, but
/// only apply to objects it creates, so they cannot block provisioning, which
/// removes them.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn default_privileges_cannot_block_provisioning() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    let runtime = role.connect("first").await;
    sqlx::raw_sql(
        "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC",
    )
    .execute(&runtime)
    .await
    .expect("default privileges");
    runtime.close().await;
    role.grant("second").await.expect("rotate password");
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_default_acl WHERE defaclrole = $1::regrole")
            .bind(&role.name)
            .fetch_one(&role.owner.pool)
            .await
            .expect("default privileges");
    assert_eq!(remaining, 0);
    role.drop_role().await;
}

/// A failed password change reports PostgreSQL's reason, here a reserved role
/// name, without echoing the statement and its password.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn failed_provisioning_does_not_echo_the_password() {
    let owner = Database {
        pool: Database::test_pool().await,
    };
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let mut reserved = DatabaseConfig::new(&url, 1, Duration::from_secs(5)).expect("test URL");
    reserved.options = reserved.options.username("pg_read_all_data");
    let password = "never-echoed-password";
    let error = owner
        .grant_runtime_role(&RuntimeRole::new(&reserved, password))
        .await
        .expect_err("reserved role name");
    let debug = format!("{error:?}");
    assert!(debug.contains("is reserved"), "{debug}");
    assert!(!debug.contains(password), "{debug}");
}

/// Settings persisted on the role, globally or for this database, are reset,
/// so a new login does not start with triggers disabled.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn role_settings_are_reset() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    role.owner_sql(
        r#"ALTER ROLE "{role}" SET session_replication_role = replica;
        ALTER ROLE "{role}" IN DATABASE "{database}" SET session_replication_role = replica"#,
    )
    .await;
    role.grant("second").await.expect("reset runtime role");
    let runtime = role.connect("second").await;
    let setting: String = sqlx::query_scalar("SELECT current_setting('session_replication_role')")
        .fetch_one(&runtime)
        .await
        .expect("setting");
    assert_eq!(setting, "origin");
    runtime.close().await;
    role.drop_role().await;
}

/// The owner's grants on built-in functions, such as `lo_export`, which writes
/// server files, are revoked.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn builtin_function_grants_are_revoked() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    role.owner_sql(r#"GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) TO "{role}""#)
        .await;
    role.grant("second").await.expect("reset runtime role");
    let runtime = role.connect("second").await;
    let executable: bool = sqlx::query_scalar(
        "SELECT has_function_privilege(current_user, 'pg_catalog.lo_export(oid, text)', 'EXECUTE')",
    )
    .fetch_one(&runtime)
    .await
    .expect("function privilege");
    assert!(!executable);
    runtime.close().await;
    role.drop_role().await;
}

/// A grant made by another grantor survives `DROP OWNED`, which revokes as the
/// object owner, so it is refused.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn grants_from_other_grantors_are_refused() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    role.owner_sql(
        r#"CREATE ROLE "{role}_grantor";
        GRANT TRUNCATE ON security_audit_log TO "{role}_grantor" WITH GRANT OPTION;
        SET ROLE "{role}_grantor";
        GRANT TRUNCATE ON security_audit_log TO "{role}";
        RESET ROLE"#,
    )
    .await;
    role.refused("second", "beyond row access").await;
    role.owner_sql(
        r#"REVOKE TRUNCATE ON security_audit_log FROM "{role}_grantor" CASCADE;
        DROP ROLE "{role}_grantor""#,
    )
    .await;
    role.drop_role().await;
}

/// A parameter grant, such as one that lets the role disable triggers through
/// `session_replication_role`, is revoked.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn parameter_grants_are_revoked() {
    let role = RoleFixture::new().await;
    role.grant("first").await.expect("create runtime role");
    role.owner_sql(r#"GRANT SET ON PARAMETER session_replication_role TO "{role}""#)
        .await;
    role.grant("second").await.expect("reset runtime role");
    let runtime = role.connect("second").await;
    assert!(
        sqlx::query("SET session_replication_role = replica")
            .execute(&runtime)
            .await
            .is_err()
    );
    runtime.close().await;
    role.drop_role().await;
}

/// A temporary `users` table, searched first by default, does not hide the real
/// account from the email-ownership trigger.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn temporary_tables_cannot_shadow_trigger_tables() {
    let pool = Database::test_pool().await;
    let user = uuid::Uuid::now_v7();
    let mut transaction = pool.begin().await.expect("begin");
    sqlx::query("INSERT INTO public.users(id,username,display_name) VALUES($1,$2,'Shadow test')")
        .bind(user)
        .bind(format!("shadow-{user}"))
        .execute(&mut *transaction)
        .await
        .expect("insert user");
    sqlx::raw_sql("CREATE TEMP TABLE users (id UUID, status TEXT) ON COMMIT DROP")
        .execute(&mut *transaction)
        .await
        .expect("shadowing table");
    sqlx::query(
        "INSERT INTO public.user_emails(id,user_id,normalized_email,verified_at,is_primary)
        VALUES($1,$2,$3,now(),true)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(user)
    .bind(format!("{user}@example.com"))
    .execute(&mut *transaction)
    .await
    .expect("insert verified email");
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM public.active_verified_email_ownership WHERE user_id = $1)",
    )
    .bind(user)
    .fetch_one(&mut *transaction)
    .await
    .expect("ownership");
    assert!(owned);
    transaction.rollback().await.expect("rollback");
}

/// Every function in the schema pins its `search_path`, with `pg_temp` last, so a
/// caller's objects cannot replace the ones it uses.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn functions_pin_their_search_path() {
    let pool = Database::test_pool().await;
    let unpinned: Vec<String> = sqlx::query_scalar(
        "SELECT proname::text FROM pg_proc
        WHERE pronamespace = 'public'::regnamespace
        AND NOT 'search_path=pg_catalog, public, pg_temp' = ANY(coalesce(proconfig, '{}'))",
    )
    .fetch_all(&pool)
    .await
    .expect("functions");
    assert!(unpinned.is_empty(), "{unpinned:?}");
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
