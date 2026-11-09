//! The inventory against the migrated schema.
use super::*;
use crate::Database;
use std::collections::BTreeSet;

/// The inventory names every table of the schema, and none that is gone. A table
/// with a foreign key to an account holds personal data, so it is never
/// [`Holds::Nothing`].
#[tokio::test]
#[ignore = "requires a disposable TEST_DATABASE_URL"]
async fn names_every_table_and_what_it_holds() {
    let pool = Database::test_pool().await;
    // Only this schema's: audit tests migrate schemas of their own beside it.
    let tables: BTreeSet<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
        AND table_name <> '_sqlx_migrations'",
    )
    .fetch_all(&pool)
    .await
    .expect("tables")
    .into_iter()
    .collect();
    let named: BTreeSet<String> = Table::ALL.map(|table| table.as_str().to_owned()).into();
    assert_eq!(tables, named, "the schema's tables, then the inventory's");

    let referencing: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT source.relname::text
        FROM pg_constraint c
        JOIN pg_class source ON source.oid = c.conrelid
        JOIN pg_class target ON target.oid = c.confrelid
        WHERE c.contype = 'f' AND target.relname = 'users'
        AND target.relnamespace = to_regnamespace(current_schema())",
    )
    .fetch_all(&pool)
    .await
    .expect("references");
    for table in referencing {
        let table: Table = table.parse().expect("named");
        assert_ne!(table.holds(), Holds::Nothing, "{table}");
    }
}
