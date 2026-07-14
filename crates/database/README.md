# Piquel repository

`piquel-repository` is the only SQLx consumer. Applications use `Database` and
typed repositories only; pool, transaction, row, and SQLx error types are not
public API.

Set `DATABASE_URL` in the process environment and run migrations explicitly with
`just migrate`. Applications do
not migrate on startup. Database integration tests use a disposable PostgreSQL
database named by `TEST_DATABASE_URL`; each test must create an isolated schema
and drop it afterwards, so ordering is never significant.

The ignored PostgreSQL suite is explicit: set `TEST_DATABASE_URL` to an
isolated database and run `just test-database`. The checked-in test Dockerfile
can run the same suite on a container network when the host cannot reach the
database container.
