# 00 — Workspace, protocol, and persistence foundation

## Goal

Create the smallest real Rust workspace on which the auth service can be built:
typed protocol primitives, the sole PostgreSQL access crate, configuration and
telemetry support, and an executable `auth-service` shell. This plan establishes
boundaries; it does not implement login, OIDC, or a frontend.

## Scope

1. Expand root `Cargo.toml` to list only the concrete members introduced here:
   `apps/auth-service`, `crates/auth-protocol`, `crates/database`,
   `crates/configuration`, and `crates/telemetry`. Declare all shared dependency
   versions in `[workspace.dependencies]`; member manifests opt in explicitly.
   Use Tokio, typed errors, UUIDv7 support, time/URL/serialization, tracing, and
   SQLx only where each is actually needed. Add a root `justfile` only for
   commands that now work: format, check, test, migrate, and SQLx preparation.
2. Add `crates/auth-protocol` as a framework- and SQLx-free crate. Define
   validated newtypes and serde representations for `UserId` (UUIDv7),
   `SessionId`, `ClientId`, `Audience`, `ServiceId`, `TokenId`, and common
   authentication-method and account-status enums. Include shared, stable token
   claim structs only where a downstream verifier will need them. Reject invalid
   wire values at parsing boundaries; do not expose database rows or policy.
3. Add `crates/configuration` for reusable parsing/validation of environment
   values, durations, URLs, and secret references. Application-specific auth
   settings belong in `apps/auth-service`, composed from these primitives.
4. Add `crates/telemetry` with sanitized tracing/metrics initialization and
   reusable redaction helpers. Its public API must make it hard to attach
   authorization headers or secrets accidentally; it must not become a generic
   utility crate.
5. Create `crates/database` (`piquel-repository`) according to the database
   architecture: private pool/executor/row types; public `Database`, typed
   configuration and errors, health check, explicit transaction wrapper, and
   domain repository handles. Do not export a `PgPool`, a SQLx transaction, raw
   SQL, or `sqlx::Error`. Start with public module/model/repository scaffolding
   only for users, emails, sessions, audit events, internal events, passkeys,
   OIDC/token records, federation, and service identities; implementations land
   with the owning feature plans.
6. Add the migration runner binary and the initial migration layout. The first
   migration may create PostgreSQL extensions/types needed by later auth tables,
   but must not create speculative feature tables. Establish a documented local
   test database configuration and integration-test harness that uses isolated
   databases/schemas and never depends on test ordering.
7. Add `apps/auth-service` as one deployable binary plus internal `lib.rs`.
   It loads typed configuration, initializes telemetry, connects through
   `Database`, exposes `/health/live` and `/health/ready`, and shuts down
   gracefully. Readiness checks database and required key-provider configuration
   availability without minting tokens. Keep future modules private under
   `src/`; do not extract auth policy into a crate.

## Required interfaces and decisions

- Decide and document the UUIDv7 generation/parsing crate and canonical string
  representation. All IDs must be immutable and downstream-safe.
- Define `DatabaseError`/connection/health error categories that preserve the
  distinction between conflict, unavailable, invalid stored data, and internal
  failure without leaking SQL details.
- Establish an explicit configuration shape for public base URL, database,
  public/internal listener addresses, TLS/key-provider references, and log
  settings. Secrets are references or redacted wrappers, never debug output.
- The internal RPC listener is configured now but not exposed until plan 06;
  public and private traffic must not be unintentionally multiplexed later.

## Tests and acceptance criteria

- `cargo fmt --check`, `cargo clippy --workspace --all-targets`, and
  `cargo test --workspace` pass.
- Protocol ID parsing/serialization and invalid-value tests exist.
- Database integration tests verify connection/health behavior and prove that
  no public API exposes raw SQLx types.
- Auth-service liveness works without dependencies; readiness fails closed when
  the database or configured key dependency is unavailable, and succeeds with
  test substitutes.
- The repository documents how to run migrations and the database tests. Do not
  add deployment-specific infrastructure.

## Handoff

Plan 01 owns the first real auth migration and repository behavior. Preserve
the public `Database`/transaction shape so it can carry a user creation, audit
entry, and internal event in one short transaction.
