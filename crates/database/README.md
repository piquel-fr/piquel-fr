# Piquel repository

`piquel-repository` is the only SQLx consumer. Applications use `Database` and
typed repositories only; pool, transaction, row, and SQLx error types are not
public API.

Set `DATABASE_URL` in the process environment and run migrations explicitly with
`just migrate`. Applications do
not migrate on startup. Database integration tests use a disposable PostgreSQL
database named by `TEST_DATABASE_URL`; each test must create an isolated schema
and drop it afterwards, so ordering is never significant.

Database tests are not currently configured. `just test-database` prints a
message and skips the database suite.
