//! The guard trigger on sealed history.
use crate::Database;
use sqlx::{Connection, PgConnection};
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

/// Sealing an unsealed event works, but a sealed one is never updated, and only
/// a transaction that set `piquel.audit_prune` deletes it or sets the anchor,
/// which never moves back. Checkpoints are never changed. Everything runs in one transaction that is rolled back, so the shared
/// schema is left as it was.
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn sealed_history_is_guarded() {
    let pool = Database::test_pool().await;
    let mut tx = pool.begin().await.expect("transaction");
    let id = Uuid::now_v7();
    // A position no other test uses: nothing seals the shared schema.
    let position = i64::try_from(id.as_u128() >> 80).expect("position") + 1;
    sqlx::query(
        r#"INSERT INTO domain_events (id, kind, version, payload, actor)
        VALUES ($1, 'imported', 1, '{}', '{"type": "unrecorded"}')"#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("event");
    sqlx::query("UPDATE domain_events SET chain_position = $2, chain_hash = $3 WHERE id = $1")
        .bind(id)
        .bind(position)
        .bind(vec![0_u8; 32])
        .execute(&mut *tx)
        .await
        .expect("sealing an unsealed event");
    let refused = Err("23000".to_owned());
    for change in [
        "UPDATE domain_events SET payload = '{\"edited\": true}' WHERE id = $1",
        "UPDATE domain_events SET chain_position = NULL, chain_hash = NULL WHERE id = $1",
        "DELETE FROM domain_events WHERE id = $1",
    ] {
        assert_eq!(attempt(&mut tx, change, id).await, refused, "{change}");
    }
    sqlx::query(
        "INSERT INTO audit_checkpoints (position, head, created_at, note)
        VALUES ($1, $2, now(), 'note')",
    )
    .bind(position)
    .bind(vec![0_u8; 32])
    .execute(&mut *tx)
    .await
    .expect("checkpoint");
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
