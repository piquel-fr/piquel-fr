# PostgreSQL boundary

`crates/database` is the only crate that runs SQL. It exposes `Database`, validated
`DatabaseConfig`, typed repository handles, and `DatabaseTransaction`. Pools,
connections, rows and raw SQL remain private. Application modules choose policy;
repository methods enforce atomic persistence and return contextual errors.

`piquel-common` supplies closed string enums and `piquel-auth-protocol` supplies
IDs, account status, authentication methods and providers. Their `sqlx` feature,
enabled only here, lets IDs decode from `UUID` columns (rejecting anything but
`UUIDv7`) and vocabularies from `TEXT` columns. Cryptographic material
is generated and hashed in `piquel-crypto`; the repository persists its digests.
Ceremony kinds, audit actions/outcomes and OIDC redirect kinds are typed storage
vocabulary. Successful account operations use `audit_events().record`.

`DatabaseConfig` rejects zero pool bounds, ambiguous TLS/socket options and host
overrides with actionable `DatabaseConnectionError` variants. TCP requires
`sslmode=verify-full` or explicit `sslmode=disable`; local Unix sockets use an
absolute `host` path with `localhost` in the URL. Parser failures retain their
sources. Client provisioning validates fields and allowlists through
`ClientConfigurationError` before writing any SQL.

Each repository has its own module under `src/repositories/` (`users`, `emails`,
`sessions`, `audit`, `passkeys`, `oidc`, `tokens`, `federation`, `security`),
holding its methods and the records they take and return. `repositories/mod.rs`
holds only shared plumbing: the executor, the `repositories!` macro that declares
every handle and its accessors on both `Database` and `DatabaseTransaction`, the
`run!` query macro and the column types that queries decode into.
`run!(self, fetch_one, query)` (or `execute`, `fetch_optional`, `fetch_all`)
dispatches to the pool or transaction and converts SQLx errors once. Dropping an
unfinished `DatabaseTransaction` rolls it back.

Every query is a checked SQLx macro: `query!`, `query_as!` or `query_scalar!`.
The compiler checks its SQL, column names, nullability and bind types against the
schema recorded in `.sqlx/`. `query_as!` decodes straight into the public records,
with type overrides for typed columns, e.g. `id AS "id: SessionId"`,
`status AS "status: AccountStatus"`, `scopes AS "scopes: JsonArray<String>"`
(a JSONB array into a `Vec`) or `profile_version AS "profile_version: Unsigned"`.
Binds pass the column's own type, e.g. `id.as_uuid()` or `kind.as_str()`, so the
macro checks them too; JSONB binds use `Json(&value) as _`. A value its Rust type
rejects, like a non-v7 ID or JSON outside the record's type, becomes
`DatabaseError::InvalidStoredData` with the column index SQLx reports and the
decoding error as its source. Uniqueness conflicts and deadline failures retain
their sources too.

The cache in `.sqlx/` is committed, and `.cargo/config.toml` sets
`SQLX_OFFLINE=true`, so builds, including image builds, never connect to a
database. After changing a query or migration, run `just db prepare` and commit
the cache. Stale query text fails the build; `just db test` runs
`cargo sqlx prepare --check` to catch a migration that breaks a cached query.

Repository tests live in `<module>/tests.rs` or an inline module for small pure
validation tests.

User, session and credential locks serialize security-sensitive changes. Acquire
account locks before session and credential locks. Credentials are rechecked under lock before authentication
updates; a ceremony snapshot cannot override newer counters or revocation.

Important invariants:

- Opaque browser tokens and invitation/OAuth lookup secrets are stored as digests.
- Ceremonies are browser-bound, expire and are consumed once, even for invalid
  authentication responses. Their serialized WebAuthn state contains challenges
  and stays server-side; do not log it.
- Account, initial credential, optional social identity, invitation redemption and
  initial session commit in one transaction.
- A session-bound management expiry is checked inside the mutation transaction.
  It permits repeated changes for two minutes and does not outlive the session.
- Account locking protects the last-passkey guard from concurrent removals.
- Active provider subjects and active provider-per-account links are unique.
  Unlink marks the identity revoked and releases both constraints.
- Verified email ownership is unique across active accounts. Email is optional;
  explicit provider linking never transfers ownership of another account's email.
- Authorization codes are single-use and bound to client, redirect and PKCE.
  Refresh tokens rotate transactionally, remain bound to their client/session,
  and reuse revokes the family.

The schema is a single initial migration, `migrations/0001_initial.sql`. The
prototype schema is disposable and the release requires a fresh database. Released
migrations are immutable; later schema changes go in new numbered files. Run
migrations with `just db migrate` (`auth-service migrate` in deployed images); startup does not silently mutate the schema.

Every five minutes the service drains expired ephemeral state in bounded batches,
for up to one minute per pass.
Security audit history is retained. Tests that use `TEST_DATABASE_URL` are explicitly
marked ignored by the ordinary unit test runner. `just db test` runs them in a
throwaway PostgreSQL cluster, or against an explicit, disposable `TEST_DATABASE_URL`.
