# Authentication stack security review

Date: 2026-07-14

Scope: the complete authentication stack from `main` through
`auth/08-hardening-operations` (`e3fde34...f024438`), with emphasis on
architecture, trust boundaries, concurrency, and operational security.

## Decision

**Do not merge or deploy the stack as a completed authentication service.**

The stack establishes useful types, schemas, and policy helpers, but it remains
foundation scaffolding. The executable serves only health endpoints, the
repository handles cannot execute persistence operations, the downstream SDK
does not validate tokens, and the private RPC surface is not implemented. The
current tests do not exercise a real authentication flow or PostgreSQL
invariant.

## Release-blocking findings

### P0 — The authentication authority is a health-only shell

`apps/auth-service/src/lib.rs:9-24` suppresses dead-code warnings for every
policy module and `apps/auth-service/src/lib.rs:75-84` registers only liveness
and readiness. `apps/auth-service/src/main.rs:11-20` binds only the public
listener. There are no discovery, JWKS, authorization, token, revocation,
passkey, federation, session, logout, or account-management endpoints, and the
configured private listener is never bound.

The frontend nevertheless links to login flows that return 404, while the
protobuf contract has no generated server/client, TLS listener, service-token
verification, or method authorization.

**Required action:** relabel the stack as scaffolding or implement each planned
HTTP/RPC flow with its cryptographic and persistence dependencies. Require an
end-to-end test for every advertised flow before describing the service or
runbooks as operational.

### P0 — Persistence and transactional invariants are not implemented

Every type in `crates/database/src/repositories.rs:3-23` is an empty
`PhantomData` handle with no operations or executor. `Database` and
`DatabaseTransaction` create those handles without lending the pool or SQLx
transaction (`crates/database/src/connection.rs:84-113` and
`crates/database/src/transaction.rs:12-40`).

Account creation, session revocation, event/audit co-commit, WebAuthn ceremony
consumption, authorization-code exchange, refresh rotation/replay response, and
federated linking therefore cannot be performed, let alone atomically. The
ceremony helper only inspects a copied `consumed` flag
(`apps/auth-service/src/passkey.rs:21-32`), so two replicas would both accept the
same unclaimed record if it were wired directly.

**Required action:** make repository handles borrow a private pool/transaction
executor and implement typed persistence operations. Consume one-time records
with conditional `UPDATE ... RETURNING` statements and keep their security side
effects in deliberate transactions. Prove rollback and exactly-one-winner
behavior with multi-connection PostgreSQL tests.

### P0 — The downstream SDK performs no JWT validation

`AuthMiddleware` ends after configuration getters and bearer-string parsing at
`crates/auth-middleware/src/lib.rs:33-95`. It never validates `typ`, `alg`,
`kid`, signature, issuer, audience, `exp`, `nbf`, or `iat`, and it implements no
JWKS retrieval/cache/rotation behavior. Its advertised verified principal also
has publicly constructible fields (`crates/auth-middleware/src/lib.rs:7-14`) and
is re-exported to consumers.

This makes the intended local-validation boundary unavailable and makes it easy
for a consumer to treat an unchecked, caller-constructed value as an
authenticated identity.

**Required action:** implement a fixed-algorithm, fail-closed verifier with
bounded JWKS caching and exact claim validation. Make the principal opaque and
constructible only after successful verification; expose read-only accessors
and framework adapters that preserve authentication-versus-authorization error
semantics.

### P1 — Active verified-email uniqueness is raceable and bypassable

The trigger in
`crates/database/migrations/0002_identity_sessions.sql:24-41` claims to lock
matching rows but performs only an `EXISTS` query. Concurrent transactions can
both observe no committed owner and insert the same verified email for two
active accounts. Locking existing rows alone would still not serialize the
initial no-row case.

The trigger also runs only for changes to `user_emails`. Two disabled accounts
may hold the same verified address and both may later transition to `active`
without rechecking the invariant. This makes verified-email federation linking
ambiguous and risks binding authentication to the wrong account.

**Required action:** represent active email ownership with a transactionally
maintained row uniquely keyed by normalized email, or serialize claims and
reactivations with a per-email lock and checks covering both tables. Add
concurrent insert and disabled-to-active tests using separate connections.

### P1 — WebAuthn RP validation accepts attacker origins

`apps/auth-service/src/passkey.rs:45-54` accepts any string starting with
`https://` that contains the RP ID. For RP ID `example.com`, origins such as
`https://example.com.evil`, `https://evil.test/example.com`, and
`https://example.com@evil.test` pass.

**Required action:** parse origins as URLs; reject userinfo, paths, query,
fragment, and non-HTTPS schemes; compare against an exact normalized origin
allowlist; and validate the RP ID against the hostname using DNS-label
boundaries and the WebAuthn rules. Add the examples above as negative tests.

### P1 — OIDC client authorization policy has no authoritative model

`crates/database/migrations/0004_oidc_tokens.sql:1-6` records only a client ID,
enabled state, and redirect URIs. It has no registered audiences, scopes, grant
types, client-authentication methods, or post-logout URIs. Authorization codes
store arbitrary scopes and audience, do not record the PKCE method, and do not
relationally bind their redirect to the client's registration. The
`exact_audience` helper accepts a slice from an unspecified caller
(`apps/auth-service/src/oidc.rs:61-69`).

**Required action:** model static client authorization explicitly and load it
through typed repository operations. Derive allowed audience/scope solely from
that registration, persist `S256`, and atomically bind/consume codes and refresh
families. Test cross-client audience, scope, redirect, and replay failures.

### P1 — Readiness does not test signing-key usability

`SecretReference::parse` accepts any non-whitespace string and
`SecretReference::is_configured()` always returns true
(`crates/configuration/src/lib.rs:57-69`). `main` reduces the key dependency to
that boolean, and readiness combines it only with a database query
(`apps/auth-service/src/main.rs:15-18`, `apps/auth-service/src/lib.rs:86-96`).

A missing, revoked, unauthorized, or unreachable key therefore reports ready
and continues receiving token traffic.

**Required action:** resolve an allowlisted key-provider reference at startup,
validate an active asymmetric key and stable `kid`, and probe bounded provider
usability/rotation metadata from readiness without exposing key material.

### P1 — The documented migration command leaks database credentials

`justfile:23-24`, `crates/database/README.md:7`, and
`docs/operations/auth-release.md:3-5` pass `$DATABASE_URL` as a positional
argument to `just`. Credentials embedded in the URL can appear in process
listings, shell history, and command telemetry.

**Required action:** make `just migrate` inherit `DATABASE_URL` from its
environment or accept a secret-provider reference; never put the URL in argv.

## Additional security and operational findings

- **P2 — insecure production transport is accepted.**
  `crates/configuration/src/lib.rs:30-40` accepts HTTP for arbitrary public
  hosts, and `crates/database/src/connection.rs:24-42` does not enforce verified
  PostgreSQL TLS. Default to HTTPS and verified database TLS; allow loopback
  exceptions only behind explicit development configuration.

- **P2 — shutdown does not meet the runbook.**
  `apps/auth-service/src/main.rs:19-26` listens only for Ctrl-C/SIGINT and puts no
  deadline on draining. Handle SIGTERM, stop readiness/intake first, and bound
  shutdown so orchestrator termination cannot drop transactions or hang.

- **P2 — health and hardening signals are absent.**
  The readiness database query has no explicit query deadline, failures are
  silently collapsed to 503, and telemetry provides formatting but no bounded
  auth/replay/rate-limit/key/RPC metrics. No endpoint rate limits or shared
  replay controls exist.

- **P3 — refresh parsing permits unbounded allocation.**
  `apps/auth-service/src/oidc.rs:37-54` base64-decodes an arbitrary-size secret
  before imposing only a minimum length. Require an exact encoded/decoded size
  before allocation and enforce request-body limits.

- **P3 — one low-severity JavaScript advisory is present.**
  `pnpm audit` reports `GHSA-pxg6-pf52-xh8x` for transitive `cookie@0.6.0` via
  SvelteKit. The current shell does not set application cookies, but the
  dependency should be upgraded/overridden before cookie-backed auth is added.

## Verification performed

- `cargo fmt --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `cargo test --workspace`: passed; only 12 small unit tests ran, with no
  database, HTTP, browser, cryptographic, multi-replica, or RPC integration
  coverage.
- `pnpm install --frozen-lockfile`: passed.
- `pnpm -r check`: passed.
- `pnpm -r build`: passed; adapter-auto could not identify a production target.
- `cargo deny check advisories`: passed.
- `pnpm audit`: one low-severity advisory, described above.

The exact redirect matcher, PKCE S256 computation, keyed refresh-token digest,
canonical UUID/text parsing, secret debug redaction, SQLx dependency boundary,
dependency-free liveness endpoint, and auth-web baseline CSP/referrer/cache
headers were also reviewed and did not produce additional findings.
