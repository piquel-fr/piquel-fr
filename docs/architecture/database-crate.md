# PostgreSQL boundary

`crates/database` is the only crate that runs SQL. It exposes `Database`, validated
`DatabaseConfig`, typed repository handles, and `DatabaseTransaction`. Pools,
connections, rows and raw SQL remain private. Application modules choose policy;
repository methods enforce atomic persistence and return contextual errors.

`piquel-common` supplies closed string enums, IDs, account status, authentication
methods, providers and domain events. Its `sqlx` feature,
enabled only here, lets IDs decode from `UUID` columns (rejecting anything but
`UUIDv7`) and vocabularies from `TEXT` columns. Cryptographic material
is generated and hashed in `piquel-crypto`; the repository persists its digests.
Ceremony kinds and OIDC redirect kinds are typed storage vocabulary. Account and security changes are recorded as typed domain events; see
[Domain events](#domain-events).

`DatabaseConfig` rejects zero pool bounds, ambiguous TLS/socket options and host
overrides with actionable `DatabaseConnectionError` variants. TCP requires
`sslmode=verify-full` or explicit `sslmode=disable`; local Unix sockets use an
absolute `host` path with `localhost` in the URL. Parser failures retain their
sources. Client registrations are written only from a `ClientRegistration`, whose
field types (`ClientId`, `RedirectUri`, `ScopeName`, bounded lists) reject invalid
values before any SQL runs.

Each repository has its own module under `src/repositories/` (`users`, `emails`,
`sessions`, `events`, `deliveries`, `passkeys`, `oidc`, `tokens`, `federation`,
`security`, `maintenance`, `administrators`), holding its methods and the records they
take and return.
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

Queries only the admin API reads decode straight into its bodies from
`piquel-admin-api`. Records that auth also uses elsewhere convert into those bodies
with `From`, leaving out what the API never shows, so no record repeats an API body.

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
- Grants and revocations of administrator rights take `administrators().lock()`
  first, so the last-administrator check stays true until they commit. An
  administrator's mutation that changes an account locks it first, as a grant
  does. Every admin mutation checks its caller after its last write, just before
  committing: it share-locks the caller's rights, so a revocation waits for it,
  and reads their session and confirmation without locking either, so it joins
  no lock cycle.
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
ones after 30. Deleting a failed ordered delivery cancels the ones behind it. Jobs like it that must run
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

`piquel_common::events` defines `DomainEvent`, one variant per account or security
change, and `Actor`, the one type every feature uses to say who caused it: a user,
an administrator, an operator at the CLI (`$USER` and host name), a client, a
background job, or an anonymous browser. Handlers record an event with
`tx.record(&context, subject, event)` in the transaction that makes the change, so a
rolled-back change leaves no event. `record` also creates the outbound deliveries
the event causes, in the same transaction; see [the delivery queue](delivery-queue.md). Failed sign-ins change nothing, so they record
theirs in a short transaction of their own. A revocation that ends several sessions
records one `SessionRevoked` per session. Refresh rotations are too frequent to be
events. `Imported` holds the rows of `security_audit_log`, the log events replace,
verbatim; only migrations write it, and its fields are private, so it can only be
read back. `repositories/events/` stores events: the personal data split below,
`read_after` and `acknowledge`.
Migration `0005` imports the log but keeps the table, which the previous release
writes to during a deploy; a later release imports the rows written since and
drops it. Migration `0008` likewise keeps `oidc_clients.client_secret_hash`, which
auth keeps equal to a confidential client's newest secret for the previous
release, and a trigger mirrors the previous release's writes to it into
`oidc_client_secrets`. Redirect URI origins need URL parsing, so `run_migrations`
fills in the ones the previous release leaves empty. A later release drops the
trigger and the column, and makes `oidc_redirect_uris.origin` NOT NULL.

Variants hold only typed IDs, enums, scopes, timestamps and counts, so a secret,
token, `WebAuthn` state or raw header cannot end up in one. Anything that identifies
a person outside auth is wrapped in `Personal<T>`, which any `piquel-common` type
can use; storage decides how to keep it apart. Adding a variant is a
compile-time change that every `match` must handle.

Event readers tolerate events they do not know, so adding a variant is safe during a
rolling deploy or a rollback, when the previous release reads what the next one
wrote. Reads return `StoredEvent.event` as a `RecordedEvent`: `Known(DomainEvent)`,
or `Unknown { kind, version, data }` for a kind this release does not know or a
known kind in a payload version newer than `EVENT_VERSION`. Each reader decides
what to do with it: the security history hides it and refuses to report it, and
the admin events API lists it with its kind, version and data. `record` takes a
`DomainEvent`, so a release never writes an unknown event, and delivery fan-out,
which runs in `record`, only ever sees known ones. A payload of a known kind and
version that does not decode is still `DatabaseError::InvalidStoredData`, so a
change an older release could not decode, such as a new variant of an enum inside a
payload or a renamed field, must be written with a new version of that kind only:
bumping `EVENT_VERSION` for every kind would hide every new event from an older
release. Adding a field is not one, since older releases ignore fields they do not
know, but the field must be an `Option` or `#[serde(default)]`, so that the new
release still reads the rows already stored. The tolerance only protects a release
that has it: ship a new variant in a later deploy than #149, so that a rollback
never lands on a release without it.

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

### Security history

The account API serves each user their own history (`GET /account/history`): the
events whose subject is the caller, read with `list` filtered on that subject, so
the query itself excludes other accounts. `DomainEvent::history_entry` decides
what a user sees. It names every variant, under
`#[deny(clippy::wildcard_enum_match_arm)]`, so a new event cannot be added without
that decision. Ceremonies, rejected attempts, token bookkeeping and invitations
are hidden; admin and CLI actions show with the kind of actor, never the operator.

`POST /account/history/{event_id}/report` reports an entry the user caused as not
theirs. One transaction records `CompromiseReported`, ends the account's other
sessions with `RevocationReason::CompromiseReported` and revokes every refresh
family. The answer names the action that undoes the entry, such as removing the
passkey it added, which still needs a passkey confirmation.
