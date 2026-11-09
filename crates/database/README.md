# sourceorigin-repository

Typed PostgreSQL persistence for the authentication service. SQLx pools and SQL
remain private; callers use repositories or a `DatabaseTransaction`.

The schema lives in numbered, immutable files under `migrations/`. Each repository
module in `src/repositories/` owns its methods and record types; `mod.rs` holds
only shared plumbing. See [database architecture](../../docs/dev/architecture/database.md)
for the layout and invariants. Run migrations through the single service binary:
`just db migrate`.

Every query is an SQLx `query!`, `query_as!` or `query_scalar!` macro, checked at
compile time against the committed cache in `.sqlx/`. The one exception is the
role provisioning script, whose DDL takes no bind parameters; a checked query
renders it. After changing a query or a
migration, run `just db prepare` and commit the cache with the change.

Integration tests apply the schema and insert uniquely named fixtures into one
database. The audit chain's verification tests need history no other test
shares, so they get a migrated schema of their own from `Database::isolated`. `just db test`
runs them in a scratch cluster, or against a disposable `TEST_DATABASE_URL`
(local TCP needs `sslmode=disable`); ordinary tests skip them. Fixtures may use
unchecked `sqlx::query`.

`just db test` ends with `just db prepare-check`, which runs
`cargo sqlx prepare --check` against the migrated schema, so a migration that
breaks a cached query fails even when no test runs that query, as does a cached
query the code no longer uses. CI runs the same check after its database tests.
