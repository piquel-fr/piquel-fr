//! The guard triggers on sealed history.
use crate::{Database, DatabaseConfig};
use sqlx::{Connection, PgConnection};
use std::time::Duration;
use uuid::Uuid;

/// Runs `sql`, bound to `id`, in a savepoint, so a refusal leaves the surrounding
/// transaction usable. Returns the error code of a refusal.
async fn attempt(connection: &mut PgConnection, sql: &str, id: Uuid) -> Result<(), String> {
    let mut savepoint = connection.begin().await.expect("savepoint");
    let result = sqlx::query(sql).bind(id).execute(&mut *savepoint).await;
    match result {
        Ok(_) => savepoint.commit().await.map_err(|error| error.to_string()),
        Err(error) => Err(error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map_or_else(|| error.to_string(), Into::into)),
    }
}

/// Inserts the unsealed event `$1`.
const INSERT: &str = r#"INSERT INTO domain_events (id, kind, version, payload, actor)
    VALUES ($1, 'imported', 1, '{}', '{"type": "unrecorded"}')"#;

/// Seals the event `$1` at `position`.
fn seal(position: u8) -> String {
    format!(
        "UPDATE domain_events SET chain_position = {position}, chain_hash = sha256('')
        WHERE id = $1"
    )
}

/// Sealing must read committed data: an older snapshot could still show events a
/// concurrent prune deleted. Rolled back, so the shared schema is left as it was.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn sealing_needs_committed_data() {
    let pool = Database::test_pool().await;
    let mut stale = pool
        .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .expect("transaction");
    let id = Uuid::now_v7();
    assert_eq!(attempt(&mut stale, INSERT, id).await, Ok(()), "event");
    assert_eq!(
        attempt(&mut stale, &seal(1), id).await,
        Err("23000".to_owned())
    );
    stale.rollback().await.expect("rollback");
}

/// Sealing an unsealed event works only right after the position before, and a
/// sealed one is never updated; only a transaction that set `piquel.audit_prune`
/// deletes it or sets the anchor, which never moves back. A checkpoint is added
/// only if it is of a sealed event's hash and dated at a finite time not in the
/// future, and is never changed. The chain starts in a schema of its own, and
/// everything runs in one transaction that is rolled back.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn sealed_history_is_guarded() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let database = Database::isolated(
        DatabaseConfig::new(&url, 1, Duration::from_secs(5)).expect("configuration"),
    )
    .await
    .expect("isolated database");
    let refused = Err("23000".to_owned());
    let mut tx = database.pool.begin().await.expect("transaction");
    let [id, later] = [(); 2].map(|()| Uuid::now_v7());
    for event in [id, later] {
        assert_eq!(attempt(&mut tx, INSERT, event).await, Ok(()), "event");
    }
    for (event, position, outcome) in [
        (id, 2, refused.clone()),
        (id, 1, Ok(())),
        (later, 3, refused.clone()),
    ] {
        assert_eq!(
            attempt(&mut tx, &seal(position), event).await,
            outcome,
            "sealing at {position}"
        );
    }
    for change in [
        "UPDATE domain_events SET payload = '{\"edited\": true}' WHERE id = $1",
        "UPDATE domain_events SET chain_position = NULL, chain_hash = NULL WHERE id = $1",
        "DELETE FROM domain_events WHERE id = $1",
    ] {
        assert_eq!(attempt(&mut tx, change, id).await, refused, "{change}");
    }
    for (head, time, note) in [
        ("sha256('x')", "now()", "'note'"),
        ("chain_hash", "now() + INTERVAL '1 hour'", "'note'"),
        ("chain_hash", "'-infinity'", "'note'"),
        ("chain_hash", "now()", "repeat('a', 1025)"),
    ] {
        let forged = format!(
            "INSERT INTO audit_checkpoints (position, head, created_at, note)
            SELECT chain_position, {head}, {time}, {note} FROM domain_events WHERE id = $1"
        );
        assert_eq!(attempt(&mut tx, &forged, id).await, refused, "{forged}");
    }
    let checkpoint = "INSERT INTO audit_checkpoints (position, head, created_at, note)
        SELECT chain_position, chain_hash, now(), 'note' FROM domain_events WHERE id = $1";
    assert_eq!(attempt(&mut tx, checkpoint, id).await, Ok(()), "checkpoint");
    for change in [
        "UPDATE audit_checkpoints SET note = 'forged'
        WHERE position = (SELECT chain_position FROM domain_events WHERE id = $1)",
        "DELETE FROM audit_checkpoints
        WHERE position = (SELECT chain_position FROM domain_events WHERE id = $1)",
    ] {
        assert_eq!(attempt(&mut tx, change, id).await, refused, "{change}");
    }
    let anchor = "INSERT INTO audit_anchor (position)
        SELECT chain_position FROM domain_events WHERE id = $1";
    assert_eq!(
        attempt(&mut tx, anchor, id).await,
        refused,
        "only pruning anchors"
    );
    sqlx::query("SELECT set_config('piquel.audit_prune', 'on', true)")
        .execute(&mut *tx)
        .await
        .expect("prune setting");
    assert_eq!(
        attempt(&mut tx, anchor, id).await,
        Ok(()),
        "pruning anchors"
    );
    for change in [
        "UPDATE audit_anchor SET position = position - 1 WHERE $1 IS NOT NULL",
        "DELETE FROM audit_anchor WHERE $1 IS NOT NULL",
    ] {
        assert_eq!(attempt(&mut tx, change, id).await, refused, "{change}");
    }
    assert_eq!(
        attempt(&mut tx, "DELETE FROM domain_events WHERE id = $1", id).await,
        Ok(()),
        "pruning deletes sealed events"
    );
    tx.rollback().await.expect("rollback");
}

/// Personal data is recorded only with its event, never attached to an event of
/// an earlier transaction. That event is committed, so in a schema of its own.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn personal_data_is_recorded_only_with_its_event() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
    let database = Database::isolated(
        DatabaseConfig::new(&url, 1, Duration::from_secs(5)).expect("configuration"),
    )
    .await
    .expect("isolated database");
    let mut connection = database.pool.acquire().await.expect("connection");
    let id = Uuid::now_v7();
    assert_eq!(attempt(&mut connection, INSERT, id).await, Ok(()), "event");
    assert_eq!(
        attempt(
            &mut connection,
            "INSERT INTO event_personal_data (event_id) VALUES ($1)",
            id
        )
        .await,
        Err("23000".to_owned()),
        "attached to an earlier transaction's event"
    );
}
