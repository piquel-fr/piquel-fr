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
The one exception is the runtime-role provisioning block (below), which builds
role and grant statements at run time and runs through `raw_sql`.
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
- Each refresh family records the code it was redeemed from. Redeeming that code
  again with its secret, as the same client, revokes the family and audits the
  replay; a wrong secret or client revokes nothing. The browser session stays
  signed in. Cleanup keeps a redeemed code for at least a day, and for as long as
  a family it produced is unrevoked and its session live, so a replay is detected
  while it could still revoke tokens.

The schema starts with the initial migration, `migrations/0001_initial.sql`. The
prototype schema is disposable and the release requires a fresh database. Released
migrations are immutable; later schema changes go in new numbered files. Run
migrations with `just db migrate` (`auth-service migrate` in deployed images); startup does not silently mutate the schema.

Deployments separate the schema owner from the role the service runs as.
`Database::grant_runtime_role`, run by `migrate` after the migrations as the
owner, creates or updates a `RuntimeRole` (the service connection's user) as a
plain login role with row access to every table. It skips `_sqlx_migrations` and
leaves `security_audit_log` append-only. It needs PostgreSQL 17 or later and a
superuser owner, and checks both first. It resets every role attribute,
including `VALID UNTIL` and `CONNECTION LIMIT`. Lock waits time out after 10
seconds, so a session holding a lock on the role, e.g. its own open
`ALTER ROLE`, fails `migrate` with instructions instead of stalling it. The
password never reaches the server: `RuntimeRole` hashes it into a SCRAM-SHA-256
verifier (`piquel_crypto::ScramVerifier`), which `ALTER ROLE … PASSWORD` stores
as is. Statements in errors, lock-wait logs or parameter logs, including ones
from a terminated backend, which no handler can intercept, show only the verifier.
Errors put their guidance in the message, since `migrate` prints only that.

A role that belongs to another role, or owns an object in this database (large
objects included) or a shared object, is refused before any change, since revoking
privileges cannot undo either. Objects it owns in other databases are ignored:
PUBLIC may connect to those by default, so counting them would let the role block
every later run, and they cannot reach the app database. Default privileges are
ignored for the same reason: setting them needs no privilege, and they apply only
to objects the role creates. The role then owns nothing, so `DROP OWNED BY` only
revokes its privileges in the database and on shared objects such as parameters,
and removes its default privileges. `ALTER ROLE … RESET ALL`, globally and in the
database, clears settings such as `session_replication_role = replica`, which
would skip triggers on every login. Then it grants exactly the set above, so new
migrations need no grant statements and changes made by hand do not survive.
PUBLIC, which every role inherits from, loses its default temporary tables, schema
creation, table and sequence privileges, and `EXECUTE` on the large-object,
server-file and advisory-lock functions in one list in the provisioning SQL. The
service takes no advisory locks; the role could otherwise hold `migrate`'s locks
and stall every deployment. SQLx's migrator takes one, so afterwards only a
superuser can run migrations, which provisioning requires anyway.

`DROP OWNED` revokes as the object owner, so grants made by another grantor survive
it. Rather than chase them, provisioning finally checks the role's effective
privileges on tables, sequences, the schema, the database and those functions,
plus parameter grants and settings that apply to its logins in this database
(its own global or app-database ones, or a database or cluster-wide
`session_replication_role`), and rolls back with an error naming each check
that found more than row access.
Trigger functions run as the invoker, so the runtime role needs, and has, row
access to the tables they maintain, such as `active_verified_email_ownership`;
foreign-key checks run as the table owner.

Every function must pin `SET search_path = pg_catalog, public, pg_temp`, which
`0003_pin_function_search_path.sql` adds to the initial ones. Otherwise the
caller's `search_path` applies, and it searches `pg_temp` first unless that is
listed, so a temporary table could shadow a table the function reads. A database
test fails for any function in the schema without it.

Every five minutes the service drains expired ephemeral state in bounded batches,
for up to one minute per pass.
Security audit history is retained. Tests that use `TEST_DATABASE_URL` are explicitly
marked ignored by the ordinary unit test runner. `just db test` runs them in a
throwaway PostgreSQL cluster, or against an explicit, disposable `TEST_DATABASE_URL`.
