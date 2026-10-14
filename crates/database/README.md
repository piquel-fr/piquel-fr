# piquel-repository

Typed PostgreSQL persistence for the authentication service. SQLx pools and SQL
remain private; callers use repositories or a `DatabaseTransaction`.

The schema is a single migration, `migrations/0001_initial.sql`. Each repository
module in `src/repositories/` owns its methods and record types; `mod.rs` holds
only shared plumbing. See [database architecture](../../docs/architecture/database-crate.md)
for the layout and invariants. Run migrations through the single service binary:
`just db migrate`.

Every query is an SQLx `query!`, `query_as!` or `query_scalar!` macro, checked at
compile time against the committed cache in `.sqlx/`. After changing a query or a
migration, run `just db prepare` and commit the cache with the change.

Integration tests apply the schema and insert uniquely named fixtures into one
database. They do not create per-test schemas. `just db test` runs them in a
scratch cluster, or against a disposable `TEST_DATABASE_URL` (local TCP needs
`sslmode=disable`); ordinary tests skip them. Fixtures may use unchecked
`sqlx::query`.
