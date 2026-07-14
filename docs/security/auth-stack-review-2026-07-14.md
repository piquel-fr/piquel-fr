# Authentication stack security review

Date: 2026-07-14

Original scope: the complete authentication stack from `main` through the
then-current `auth/08-hardening-operations`, with emphasis on architecture,
trust boundaries, concurrency, and operational security.

Second-review scope: the rebuilt cumulative stack from `main` at `e3fde34`
through `auth/08-hardening-operations` at `47d9f4d`, as presented by this final
audit PR. The second review was performed independently across architecture,
security, and remediation-evidence validation.

## Second review verdict

**Do not merge or deploy the stack as a completed authentication service.**

The rebuild replaces the original scaffolding with substantial executable
code, but the prior remediation follow-up overstates completion. The second
review found three release blockers and several P1 trust, concurrency, and
operability gaps. In particular, account disablement is not an authentication
invariant, signing-key rotation is both unsupported and destructive to refresh
tokens, and there is still no deployable end-to-end browser/OIDC flow.

The findings below are based on the rebuilt implementation and supersede the
claims in **First remediation follow-up (superseded)**.

### P0 — Disabled accounts can authenticate with passkeys

Passkey authentication consumes and verifies a ceremony, updates a credential,
and creates a new session without loading the user or requiring an active
account (`apps/auth-service/src/passkey.rs:316-363`). Browser-session resolution
joins only `browser_session_secrets` and `sessions`, so an existing session for
a subsequently disabled account remains accepted by account endpoints
(`crates/database/src/repositories.rs:768-773`). Private RPC likewise reports a
session active from revocation and expiry alone
(`apps/auth-service/src/service_rpc.rs:207-229`). Federation checks account
status before session creation in a separate transaction, leaving a disable
race (`apps/auth-service/src/federation.rs:475-495,582-617`).

OIDC code and refresh queries do require an active user, so the same account has
different status semantics at different trust boundaries. Administrative
disablement therefore does not reliably disable authentication or central
session use.

**Required action:** enforce active account status transactionally whenever a
session is resolved or created. Make account disablement revoke sessions and
refresh families and append its audit/event records in the same transaction.
Make RPC session status include account status and add disable-versus-login race
tests.

### P0 — Signing-key rotation is unsupported and invalidates refresh tokens

The authority loads exactly one ES256 private key and publishes exactly one JWK
(`apps/auth-service/src/oidc.rs:58-110`). It also passes the signing PEM bytes
into OIDC construction and derives the authorization-code/refresh-token digest
key from those bytes (`apps/auth-service/src/main.rs:25-56` and
`apps/auth-service/src/oidc.rs:223-235`). Replacing the signing key therefore
removes the old public key immediately and invalidates every outstanding
authorization code and refresh token, despite refresh tokens being issued for
up to 30 days.

This makes the overlap procedure in
`docs/operations/auth-key-rotation.md:3-7` impossible to perform and turns a
routine signing-key rotation into a global session outage.

**Required action:** use an independently managed, stable digest key for opaque
tokens. Implement an active-plus-retired signing key ring that can publish old
and new JWKs concurrently, then prove new issuance, overlap, removal after the
last token expiry, and refresh continuity in an authority integration test.

### P0 — No complete browser/OIDC authorization flow is deployable

An unauthenticated `/oauth/authorize` request is redirected back to the client
with `login_required`; there is no server-side authorization transaction,
login continuation, or authorization/consent UX
(`apps/auth-service/src/oidc.rs:284-369`). The independently deployed SvelteKit
application calls relative API paths, but has no proxy or server routes and no
documented edge-routing contract that composes page and API routes on
`auth.piquel.fr` (`apps/auth-web/src/lib/webauthn.ts:21-22` and
`apps/auth-web/svelte.config.js:1-3`).

The account-security page's “Add a passkey” link opens the new-account
registration flow; the backend has no authenticated enrollment ceremony
(`apps/auth-web/src/routes/security/+page.svelte:8` and
`apps/auth-service/src/passkey.rs:137-247`). Social-identity listing, OIDC
authorization presentation/cancellation, and continuation after authentication
are also absent.

**Required action:** define the production edge/BFF routing contract, persist a
bounded server-side authorization continuation, implement the authenticated
enrollment and authorization UX, and prove passkey, federation, SSO
continuation, cancellation, and logout with browser tests through that topology.

### P1 — Public transport and rate limiting depend on an undefined proxy

Production configuration validates an advertised HTTPS issuer, but the public
server binds a plaintext `TcpListener` with `axum::serve`
(`apps/auth-service/src/main.rs:88-105`). Secure deployment therefore requires
an external TLS terminator and private backend network, neither of which is an
enforced or documented invariant. The limiter keys on the TCP peer address
(`apps/auth-service/src/hardening.rs:51-74`), so a reverse proxy collapses all
users into one 30-per-minute login/WebAuthn bucket. Health endpoints share the
public bucket, and more than 10,000 recent source keys cause a full map scan
under a mutex on each request.

**Required action:** terminate TLS in process or specify and enforce a trusted
proxy/private-listener topology. Define authenticated client-IP propagation,
separate health traffic, and use bounded incremental limiter eviction.

### P1 — Refresh rotation ignores current client policy

Refresh consumption checks that the client remains enabled, but does not
require `allow_refresh` or verify that the family's stored audience and scopes
remain allowed (`crates/database/src/repositories.rs:401-455`). Rotation then
reissues those stored grants unchanged (`apps/auth-service/src/oidc.rs:479-533`).
Removing a client scope/audience or disabling refresh therefore has no effect on
existing families.

**Required action:** reapply current client policy inside the locked rotation
transaction, or explicitly model immutable grants and atomically revoke affected
families whenever client policy is reduced. Add policy-reduction tests.

### P1 — Passkey state changes have revocation and last-factor races

Authentication reads credential state and later updates it without a row lock
or optimistic state condition. The handler ignores the boolean result of the
conditional `revoked_at IS NULL` update, so a credential revoked between lookup
and update can still produce a session
(`apps/auth-service/src/passkey.rs:335-362` and
`crates/database/src/repositories.rs:665-677`). Concurrent authentications can
also overwrite newer authenticator state.

The “keep at least one passkey” rule is a list-then-delete sequence over separate
pool operations (`apps/auth-service/src/passkey.rs:488-510`). Two concurrent
deletions can each observe two credentials and leave the account with none.

**Required action:** lock or compare-and-swap credential state through
authentication completion, require a successful update before creating a
session, and enforce last-factor removal in one transaction with the relevant
credential set locked.

### P1 — The SDK returns an unvalidated ID token

The OIDC SDK creates and stores a nonce, but callback exchange validates only
state and sends the token request. The nonce is never consumed, and the returned
ID token is exposed after only response-shape checks
(`crates/auth-sdk/src/lib.rs:118-192,236-315`). There is no ID-token verifier in
the SDK that checks signature, issuer, client audience, time claims, and nonce.

**Required action:** validate the ID token against the trusted issuer/JWKS and
the single-use callback nonce before returning an authenticated result. Keep raw
token access separate from a verified identity type and add negative nonce,
audience, issuer, algorithm, and signature tests.

### P1 — Required replay evidence and RPC hardening are absent

Refresh replay revokes the family but writes no security-audit record and emits
no replay-specific bounded signal (`apps/auth-service/src/oidc.rs:487-495`).
This contradicts `docs/operations/auth-incidents.md:3-4` and the Plan 08 release
gate. Public HTTP limits do not cover Tonic; private RPC has no server-enforced
request deadline or concurrency bound and no mTLS/authentication/permission
integration test (`apps/auth-service/src/main.rs:107-125`).

**Required action:** co-commit a sanitized replay audit record with family
revocation, emit a bounded replay metric, and test both. Add RPC deadlines,
concurrency limits, certificate/service-identity binding policy, and black-box
mTLS and permission tests.

### P1 — Passing gates do not verify the implemented system

The default Rust suite passes but the sole PostgreSQL integration test is
ignored unless `TEST_DATABASE_URL` is supplied, and `just ci` does not run it
(`crates/database/tests/identity.rs:40` and `justfile:19-24`). Auth-service HTTP
tests mount only health routes with all applications set to `None`
(`apps/auth-service/src/lib.rs:199-234`). There are no handler-level OIDC,
federation, startup, mTLS/RPC, or browser-flow tests. The web package's `test`
script is a production build (`apps/auth-web/package.json:8-10`), not a test.

The second review reran formatting, Clippy, the default Rust suite, SvelteKit
checking, the production web build, and inspected the PostgreSQL concurrency
suite. Those gates pass or are structurally present, but they cannot support the
claim that a real authentication flow or production topology was exercised.
`cargo deny check advisories` now fails on unmaintained `rustls-pemfile 2.2.0`
through Tonic (`RUSTSEC-2025-0134`), and `pnpm audit` still reports the already
documented low-severity `cookie` advisory (`GHSA-pxg6-pf52-xh8x`). The follow-up
claim that the advisory gate passed is no longer current.

**Required action:** make the isolated PostgreSQL suite mandatory in CI and add
black-box HTTP, RPC, and browser tests that start the production composition.
Tie every release-control claim to an enforced test rather than a helper or
build-only check.

### Additional P2 findings

- `/oidc/logout` mutates session state on GET without origin or CSRF validation,
  so a cross-site top-level navigation can force logout
  (`apps/auth-service/src/oidc.rs:654-689`). Use POST with an exact origin and
  CSRF control; keep GET non-mutating if a confirmation page is required.
- The mTLS listener requires a CA-issued certificate but token issuance never
  binds the verified peer certificate identity to the assertion's service ID
  (`apps/auth-service/src/main.rs:106-125` and
  `apps/auth-service/src/service_rpc.rs:62-109`). Define a SAN/SPIFFE-style
  identity contract and require it to match the assertion subject.
- Expired sessions, browser secrets, WebAuthn ceremonies, authorization codes,
  refresh records, and federation transactions have no bounded cleanup owner.
  Public start endpoints can grow several of these stores indefinitely. Define
  retention periods and a bounded purge mechanism.
- Federation initial linking queries all historical verified-email owners rather
  than the active ownership row (`apps/auth-service/src/federation.rs:497-530`
  and `crates/database/src/repositories.rs:188-224`). A disabled historical
  owner can make an otherwise unambiguous active-account login fail.
- Client bootstrap accepts raw URI/scope/audience strings and performs its
  replace operation as multiple statements without requiring a transaction
  (`crates/database/src/repositories.rs:265-295`). Validate the registration at
  a typed administrative boundary and make replacement atomic.
- HTTP handlers have a ten-second timeout, but the Tonic listener and overall
  graceful drain have no server deadline. Secret readiness wraps synchronous
  file reads in an async timeout that cannot preempt them. Bound both listener
  drains and use a genuinely deadline-aware secret-provider boundary.

## First remediation follow-up (superseded)

The decision and findings below describe the originally reviewed commits. They
were accurate: the PRs had been presented as implementations even though most
contained only schemas, policy-shaped helpers, and UI/protocol scaffolding. The
stack was subsequently rebuilt on the same ordered branches and re-reviewed on
2026-07-14. The cause was an implementation/review failure, not a regression:
acceptance criteria were treated as file-shape requirements, tests exercised
helpers rather than flows, and completion was reported without tracing a real
request through HTTP, cryptography, persistence, and concurrency boundaries.

The first follow-up claimed the release-blocking findings had been remediated as
follows. The second review above found these claims incomplete:

- The authority now exposes and wires WebAuthn, OIDC discovery/JWKS/code/token/
  refresh/revoke/userinfo/logout, GitHub and Google login, account-security
  operations, and a separate mTLS Tonic listener.
- Repositories now borrow a real pool or transaction executor. Conditional
  `UPDATE ... RETURNING` consumption is used for ceremonies and codes; refresh
  rotation locks records and revokes a family on replay.
- Static OIDC clients own exact redirect/post-logout URIs, scopes, audiences,
  enabled state, refresh permission, and authentication method. Access and ID
  tokens are ES256 and cryptographically separated by `typ` and audience.
- The SDK now validates a single Bearer value, fixed `at+jwt`/ES256/`kid`, a
  trusted cached JWKS key, signature, exact issuer/audience, time claims, and
  typed UUIDv7 claims. `AuthenticatedUser` is opaque outside the validator.
- Active verified-email ownership is represented by a unique lockable row and
  is synchronized on account status changes. Federation uses verified provider
  email only for the initial link and stores issuer/subject as the durable key.
- WebAuthn uses `webauthn-rs` with parsed exact origins and server-side,
  single-use state. The three attacker-controlled origin examples in this
  report are regression tests.
- Production public/database transport fails closed unless HTTPS and verified
  PostgreSQL TLS are configured. Secret locators are allowlisted and redacted;
  readiness resolves the signing, provider, and RPC TLS dependencies.
- Migration credentials are environment-only. Refresh/cookie secrets have
  exact bounds, public bodies and handler time are bounded, sensitive endpoint
  classes are rate limited, and SIGINT/SIGTERM coordinate graceful public and
  private listener shutdown.

Verification after remediation includes the full Rust format/test/clippy gates,
SvelteKit type checking and an adapter-node production build, real ES256 and
software-WebAuthn interoperability tests, JWKS failure/rotation tests, and an
empty PostgreSQL 17 database test using separate concurrent connections. The
database test proves rollback, verified-email claim/reactivation exclusion,
exactly-one WebAuthn/federation transaction consumption, duplicate credential
and provider-subject rejection, optimistic profile conflict, idempotent session
revocation, event ordering, and refresh one-winner/replay-family revocation.

Remaining deployment work is environmental rather than a claim of an
implemented control: production must provision reviewed OIDC/service clients,
ES256 and mTLS key material, GitHub/Google applications, and exercise live
provider/browser and backup/restore drills before release. The in-process rate
limiter is per replica; a shared disposable limiter requires a separately
reviewed failure-mode design if aggregate limits are required.

## Original review decision

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
