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
Ceremony kinds, OIDC redirect kinds and user agent families are typed storage
vocabulary. Account and security changes are recorded as typed domain events; see
[Domain events](#domain-events).

`DatabaseConfig` rejects zero pool bounds, ambiguous TLS/socket options and host
overrides with actionable `DatabaseConnectionError` variants. TCP requires
`sslmode=verify-full` or explicit `sslmode=disable`; local Unix sockets use an
absolute `host` path with `localhost` in the URL. Parser failures retain their
sources. Client provisioning validates fields and allowlists through
`ClientConfigurationError` before writing any SQL.

Each repository has its own module under `src/repositories/` (`users`, `emails`,
`sessions`, `events`, `deliveries`, `passkeys`, `oidc`, `tokens`, `federation`,
`security`, `maintenance`), holding its methods and the records they take and return.
`repositories/mod.rs` holds only shared plumbing: the executor, the
`repositories!` macro that declares every handle and its accessors on `Database`,
`DatabaseTransaction` and `ExclusiveConnection`, the `run!` query macro and the
column types that queries decode into. `run!(self, fetch_one, query)` (or
`execute`, `fetch_optional`, `fetch_all`) dispatches to the pool or the bound
connection and converts SQLx errors once. Dropping an
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
- A session's passkey confirmation time is rechecked inside the mutation
  transaction, under the session row lock, against the action's maximum age. It
  belongs to one session and ends with it.
- Account locking protects the last-passkey guard from concurrent removals.
- Active provider subjects and active provider-per-account links are unique.
  Unlink marks the identity revoked and releases both constraints.
- Verified email ownership is unique across active accounts. Email is optional;
  explicit provider linking never transfers ownership of another account's email.
- A session's `acr`, `amr` and `auth_time` are derived from its methods,
  `authenticated_at` and `passkey_confirmed_at` (`SessionAuthentication`). Codes
  copy them when issued, and refresh families copy them from the code, so a grant
  keeps reporting its original authentication.
- Authorization codes are single-use and bound to client, redirect and PKCE.
  Refresh tokens rotate transactionally, remain bound to their client/session,
  and reuse revokes the family.
- Each refresh family records the code it was redeemed from. Redeeming that code
  again with its secret, as the same client, revokes the family and records the
  replay; a wrong secret or client revokes nothing. The browser session stays
  signed in. Cleanup keeps a redeemed code for at least a day, and for as long as
  a family it produced is unrevoked and its session live, so a replay is detected
  while it could still revoke tokens.

The schema starts with the initial migration, `migrations/0001_initial.sql`. The
prototype schema is disposable and the release requires a fresh database. Released
migrations are immutable; later schema changes go in new numbered files. Run
migrations with `just db migrate` (`auth-service migrate` in deployed images); startup does not silently mutate the schema.

Migrations expand, then contract. A deploy runs `migrate` first, and the previous
release keeps serving against the new schema until its replacement is healthy, so
every migration must keep the previous release working. Add tables, and columns
that are nullable or have a default. Drop or rename a column or table, or add a
constraint the previous release could violate, only in a later release, once no
deployed code uses the old shape. Migration `0003` dropped
`sessions.management_expires_at` in the release that stopped reading it: a one-time
exception while there were few users, not a precedent. SQLx's migrator takes an
advisory lock, so concurrent `migrate` runs are safe.

Every five minutes, one replica drains expired ephemeral state in bounded batches
through `maintenance()`, for up to one minute per pass. The same pass deletes event
personal data older than 90 days; the events themselves are kept indefinitely. It
also deletes finished deliveries: succeeded ones after 7 days, failed or cancelled
ones after 30. Jobs like it that must run
on one replica at a time call `Database::try_exclusive(LockKey)`, which takes a
session-level advisory lock on a dedicated connection outside the pool. The lock
ends with that connection, even when the job is cancelled or the process dies, so
it needs no lease or expiry, and a lock holder never returns to the pool. Give each
job its own `LockKey` value and never reuse one.
Tests that use `TEST_DATABASE_URL` are explicitly
marked ignored by the ordinary unit test runner; other crates' tests read stored state
through helpers behind the `test-support` feature. `just db test` runs them in a
throwaway PostgreSQL cluster, or against an explicit, disposable `TEST_DATABASE_URL`.

## Domain events

`repositories/events/` defines `DomainEvent`, one variant per account or security
change, and `Actor`, the one type every feature uses to say who caused it: a user,
an administrator, an operator at the CLI (`$USER` and host name), a client, a
background job, or an anonymous browser. Handlers record an event with
`tx.record(&context, subject, event)` in the transaction that makes the change, so a
rolled-back change leaves no event. `record` also creates the outbound deliveries
the event causes, in the same transaction; see [the delivery queue](delivery-queue.md). Failed sign-ins change nothing, so they record
theirs in a short transaction of their own. A revocation that ends several sessions
records one `SessionRevoked` per session. Refresh rotations are too frequent to be
events. `Imported` holds the rows of `security_audit_log`, the log events replace,
verbatim; only migrations write it, and its fields are private to this crate.
Migration `0005` imports the log but keeps the table, which the previous release
writes to during a deploy; a later release imports the rows written since and
drops it.

Variants hold only typed IDs, enums, scopes, timestamps and counts, so a secret,
token, `WebAuthn` state or raw header cannot end up in one. Anything that identifies
a person outside auth is wrapped in `Personal<T>`. Adding a variant is a
compile-time change that every `match` must handle.

### Personal data

- `domain_events` holds only non-identifying content: kind, versioned payload,
  actor, subject, client and session IDs, and timestamps. Operator attribution
  (`os_user`, `host`) is accountability data and stays there too. This is the
  content a hash chain (#31) covers.
- `event_personal_data`, one row per event, holds the client IP, the user agent
  family and every `Personal` payload value, keyed by its JSON pointer. On write
  the repository moves each `Personal` value there and leaves `"$erased"` in the
  payload; on read it merges them back. Once the row is gone, they and the request
  origin read as `Personal::Erased`. Deleting it never breaks the event.
- The cleanup pass deletes personal data after 90 days. Account purge (#84) deletes
  it earlier for every event whose subject or actor is the purged account.
- `subject_user_id` has no foreign key: history outlives the account. Subject and
  actor UUIDs are pseudonymous, not anonymous: applications hold the same `sub`.

### Consumers

`events().read_after(consumer, limit)` returns the events after a consumer's cursor,
and `acknowledge(consumer, cursor)` moves it, in the transaction that applies the
consumer's effects. A sequence number alone is not a safe cursor: a transaction can
take sequence 10 and commit after another one took 11, and a reader that saw 11
would skip 10. Consumers therefore read in `(txid, sequence)` order, and only events
of transactions older than every running one (`txid < pg_snapshot_xmin(...)`), which
have all finished. A long-running transaction holds back every consumer until it
ends, so keep transactions short. `history_for_user` lists an account's events,
newest first.
