# piquel-repository

Typed PostgreSQL persistence for the authentication service. SQLx pools and SQL
remain private; callers use repositories or a `DatabaseTransaction`.

See [database architecture](../../docs/architecture/database-crate.md) for invariants.
Run migrations through the single service binary: `auth-service migrate`.

Integration tests use a disposable `TEST_DATABASE_URL`, apply the schema, and insert
uniquely named fixtures into that database. They do not create per-test schemas.
Run them explicitly with the command in the root README; ordinary tests skip them.
