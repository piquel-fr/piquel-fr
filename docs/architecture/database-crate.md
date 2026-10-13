# PostgreSQL boundary

`crates/database` is the only SQLx consumer. It exposes `Database`, validated
`DatabaseConfig`, typed repository handles, and `DatabaseTransaction`. Pools,
connections, rows and raw SQL remain private. Application modules choose policy;
repository methods enforce atomic persistence and return contextual errors.

`piquel-common` supplies closed string enums and `piquel-auth-protocol` supplies
IDs, account status, authentication methods and providers. Cryptographic material
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
`run!` query macro and typed row decoding. `run!(self, fetch_one, query)` (or
`execute`, `fetch_optional`, `fetch_all`) dispatches to the pool or transaction
and converts SQLx errors once. Decoding names the invalid column and keeps its source;
uniqueness conflicts and deadline failures retain theirs too. Dropping an
unfinished `DatabaseTransaction` rolls it back.

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
migrations with `just migrate` (`auth-service migrate` in deployed images); startup does not silently mutate the schema.

Every five minutes the service drains expired ephemeral state in bounded batches,
for up to one minute per pass.
Security audit history is retained. Tests that use `TEST_DATABASE_URL` are explicitly
marked ignored by the ordinary unit test runner; the documented database test
command includes them and must use a disposable database.
