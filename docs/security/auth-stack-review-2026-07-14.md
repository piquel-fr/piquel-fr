# Authentication stack architecture and security review

Date: 2026-07-14

Review target: the cumulative implementation from `origin/main` at `e3fde34`
through `origin/auth/08-hardening-operations` at `365d160`.

## Decision

**Changes requested. Do not deploy this stack as the completed authentication
service yet.**

The implementation has several sound foundations: exact OIDC redirect matching,
mandatory S256 PKCE, keyed opaque-token digests, transactional refresh replay
handling, server-side single-use WebAuthn state, exact JWT type/issuer/audience
checks at resource boundaries, account-status checks, mTLS plus SPIFFE-style RPC
identity binding, and bounded public request bodies and deadlines.

Those controls do not offset the release blockers below. The most important are
a bypass in the production database TLS guard, durable account takeover through
email-only federation linking, a nonexistent signing-key rotation boundary, an
over-broad proxy trust boundary, a broken passkey-enrollment schema, and missing
production observability/deployment evidence.

## Release blockers

### High — PostgreSQL TLS validation can be downgraded

`DatabaseConfig::validate` accepts a production URL when *any* query pair equals
`sslmode=verify-full` (`crates/database/src/connection.rs:60-83`), then stores and
later gives the unchanged string to SQLx (`crates/database/src/connection.rs:95-100`).
SQLx 0.8.6 processes connection query pairs sequentially, accepts both
`sslmode` and `ssl-mode`, and lets the last value win.

Consequently, a URL such as
`postgres://db/app?sslmode=verify-full&sslmode=disable` passes this repository's
production guard while SQLx connects with TLS disabled. SQLx also accepts
query-level `host`/`hostaddr` overrides, so a development URL whose authority is
loopback can be redirected to a remote database.

**Required action:** parse once into `PgConnectOptions`, reject duplicate/alias
security parameters and host overrides, validate the effective host and
`PgSslMode::VerifyFull`, and connect with those already-validated options. Add
regression tests for both parameter orders and host overrides.

### High — email-only federation linking permits durable account takeover

For a previously unseen provider subject, federation looks up an existing
active account solely by the provider-asserted verified email and inserts the
new external identity on that account (`apps/auth-service/src/federation.rs:536-605`).
The callback immediately creates a full browser session
(`apps/auth-service/src/federation.rs:247-272`).

Verified email ownership is not immutable. If an address on an active Piquel
account is later reassigned—for example, a former employee's corporate address
is issued to a new employee—the new owner can authenticate through GitHub or
Google with a different provider subject and become linked to the former
owner's Piquel account. A fresh federation session is sufficient for passkey
management (`apps/auth-service/src/passkey.rs:386-478`), so the new owner can
add a credential and then remove the victim's credentials while retaining one
factor (`apps/auth-service/src/passkey.rs:535-564`).

The design documents email auto-linking as an accepted first-version policy,
but the implementation makes the reassignment case a persistent full takeover,
not merely a profile-linking ambiguity.

**Required action:** do not attach a new issuer/subject to an existing account
based only on email. Require a fresh session authenticated with an existing
factor, or route collisions through explicit recovery/administrative review.
Notify the existing account through an independent channel.

### High — key rotation is not an implemented security boundary

Production loads one exportable PKCS#8 key, uses it as the only JWT signing key,
publishes only its JWK, and also passes the same PEM bytes into OIDC as the root
for authorization-request, code, and refresh-token digests
(`apps/auth-service/src/main.rs:25-58`, `apps/auth-service/src/oidc.rs:88-111`,
`apps/auth-service/src/oidc.rs:224-238`).

Replacing a compromised signing key therefore removes verification for
existing JWTs and invalidates every outstanding opaque credential. The runbook
acknowledges that routine overlap is unsupported and emergency replacement
requires global reauthentication (`docs/operations/auth-key-rotation.md:1-19`).
That is honest documentation, but it does not satisfy the hardening plan's key
lifecycle release gate.

`SecretReference` also accepts `kms://` values while `resolve` deterministically
rejects them (`crates/configuration/src/lib.rs:81-125`), so the advertised
provider boundary cannot use a non-exportable production signing key.

**Required action:** separate a stable opaque-token digest key from signing,
implement an active-plus-retired signing key ring and JWKS overlap, and define a
real signing-provider interface for KMS-backed signing. Prove routine rotation,
emergency retirement, refresh continuity, and downstream key-removal timing.

### High — the trusted proxy identity is an entire shared network

The release guide attaches Traefik, auth-service, and auth-web to the same edge
network and configures `AUTH_TRUSTED_PROXY_CIDRS` with that network CIDR
(`docs/operations/auth-release.md:9-18`). The application accepts the first
`X-Forwarded-For` value from any peer in that CIDR
(`apps/auth-service/src/hardening.rs:148-165`).

A compromised sibling container, or any accidentally attached workload, can
connect directly to auth-service, choose arbitrary client IPs, and evade the
per-IP controls without passing through Traefik. The unit test proves only that
one CIDR is accepted and another is rejected; it does not prove that the peer is
Traefik (`apps/auth-service/src/hardening.rs:211-230`).

**Required action:** use separate Traefik-to-web and
Traefik-to-auth-service networks with no sibling route, or authenticate the
proxy hop and identify Traefik specifically. Add a negative integration test
for direct requests from auth-web/the sibling network.

### High — authenticated backup-passkey enrollment cannot work

`/account/passkeys/enroll/start` inserts a ceremony with kind `enrollment`, and
the finish handler consumes the same kind
(`apps/auth-service/src/passkey.rs:412-424`,
`apps/auth-service/src/passkey.rs:443-446`). The database constraint allows only
`registration` and `authentication`
(`crates/database/migrations/0003_passkey_credentials.sql:19-29`). Every start
request therefore fails before the authenticator is invoked.

The browser test masks this by stubbing the enrollment endpoint
(`apps/auth-web/tests/auth-flow.spec.ts:111-134`); no real Postgres-backed HTTP
test exercises passkey enrollment.

**Required action:** add an immutable migration that represents enrollment
consistently, preferably with a typed ceremony kind, and add a real
start/finish enrollment flow through HTTP and PostgreSQL.

### High — production TLS and security telemetry are not release-verifiable

The Traefik routers enable `tls: {}`, but the checked-in static/dynamic config
contains no certificate resolver or certificate store
(`infra/traefik/auth-dynamic.yml:14,21`,
`infra/traefik/auth-static.yml:24-33`). The topology test always uses
`curl --insecure` and replaces both applications with `traefik/whoami`
(`.github/workflows/ci.yml:58-93`). It cannot detect a missing, expired, or
wrong-host certificate and does not compose the software being released.

The hardening plan also requires bounded signals for authentication, replay,
signing, database, RPC, provider, and rate-limit outcomes. Telemetry currently
formats stderr logs only (`crates/telemetry/src/lib.rs:26-35`), and Traefik has
no access log, metrics, or tracing configuration. Most authentication outcomes
are absent, and the cleanup documentation asks operators to alert on failures
without exposing a signal that can drive such an alert
(`docs/security/auth-data-retention.md:25-27`).

**Required action:** provision an explicit certificate source, test the HTTPS
edge with a trusted test CA and hostname verification, compose the real
auth-service/auth-web/PostgreSQL stack, and run Playwright/protocol checks
through that edge. Add bounded metrics/traces and alert simulations for the
outcomes named in Plan 08 before calling the service operable.

## Additional security and architecture findings

### Medium — issued claims bypass scope policy

The authorization endpoint enforces each requested scope against the client's
allowlist (`apps/auth-service/src/oidc.rs:318-327`), but token issuance always
puts `preferred_username`, `name`, and `profile_version` in access and ID tokens
regardless of whether `profile` was granted
(`apps/auth-service/src/oidc.rs:733-757`). The advertised `email` scope never
produces an email claim, including from UserInfo.

**Required action:** construct claim sets from granted scopes, add negative
tests proving omitted scopes omit their claims, and either implement verified
email claims or stop advertising `email`.

### Medium — revocation races protected browser mutations

Passkey enrollment, rename, removal, and authorization approval resolve the
browser session before opening the mutation transaction
(`apps/auth-service/src/passkey.rs:440-478`,
`apps/auth-service/src/passkey.rs:523-563`,
`apps/auth-service/src/oidc.rs:409-471`). They do not lock and re-check that
session in the transaction that performs the protected write.

Logout or administrative revocation can therefore commit after the handler's
initial lookup while the passkey mutation or authorization-code issuance still
succeeds. This is material when revocation races completion of a previously
started enrollment from a stolen browser session.

**Required action:** revalidate and lock the active session, user state, and
fresh-authentication requirement inside the protected transaction. Serialize
revocation on the same session row and add race tests.

### Medium — abuse limits are neither replica-safe nor capacity-safe

The public limiter is in process memory (`apps/auth-service/src/hardening.rs:23-50`).
N replicas permit N times the configured rate and restart/autoscaling resets
all windows. After 10,000 distinct `(IP, endpoint-class)` keys, every unseen
legitimate client receives 503 (`apps/auth-service/src/hardening.rs:85-93`).
Rotating IPv6 addresses or a botnet can reach that global new-client denial
state within one window.

Private service-token issuance is outside this limiter. A CA-trusted but
compromised/looping service can multiply the per-connection concurrency limit
with new connections, cause database work for assertions, and append a durable
audit row for every rejected assertion (`apps/auth-service/src/main.rs:125-136`,
`apps/auth-service/src/service_rpc.rs:195-213`).

**Required action:** place the authoritative aggregate limit at ingress or in
explicitly disposable shared coordination, retain a local circuit breaker, use
bounded eviction rather than global 503 for unseen clients, aggregate IPv6
prefixes, and add global/per-service RPC concurrency and rate limits.

### Medium — outstanding OIDC state survives policy removal

Authorization-request and code consumption check that the client is enabled,
but do not revalidate the stored redirect URI, scopes, or audience against the
current client registration (`crates/database/src/repositories.rs:362-384`).
After an operator removes a compromised redirect or grant, an already-created
request can still approve and exchange the old policy snapshot until it
expires. Disabling the entire client is the only immediate stop.

**Required action:** re-read and enforce current redirect/scope/audience policy
at approval and code exchange, or atomically revoke affected outstanding state
when policy changes. Add policy-reduction tests.

### Medium — service assertion cleanup is unbounded on the issuance path

Every accepted assertion first deletes *all* expired replay rows
(`crates/database/src/repositories.rs:739-758`). The bounded maintenance job
does not own this table (`crates/database/src/connection.rs:130-156`). A large
expired set turns token issuance into an unbounded delete/lock operation and can
exhaust the small shared database pool.

**Required action:** make assertion recording a single insert and move indexed,
limited cleanup into the maintenance owner using bounded batches.

### Medium — `prompt=none` and `max_age` do not implement their contract

A negative `max_age` is stored and routed through login even though no session
can ever satisfy it (`apps/auth-service/src/oidc.rs:331-376`,
`apps/auth-service/src/oidc.rs:489-505`). With an active session,
`prompt=none` still redirects to the authorization UI, contrary to its
no-interaction meaning.

**Required action:** reject negative/out-of-range values immediately and make
`prompt=none` either complete without UI under an explicit prior-consent policy
or return the appropriate OAuth error.

### Medium — policy ownership is mostly nominal

The account, session, audit, and event modules define validators and
transactional helpers, but the deployed handlers bypass them. Initial passkey
and federation flows insert users/sessions/audits/events directly; the policy
modules are kept behind `allow(dead_code)` in `apps/auth-service/src/lib.rs`.
That duplication already creates inconsistent audit coverage: account creation
through passkeys or federation does not use `account::create`, passkey rename is
not audited, and OIDC authorization/revocation/logout mutations do not produce
the security history implied by the architecture.

**Required action:** make one application-service boundary own each account,
session, credential, and audit transition. Remove dead policy facades or route
all handlers through them, and test the expected audit/event record with every
security-sensitive mutation.

### Low — backslash-relative return targets are open redirects

Both return-target validators reject `//evil.example` but accept
`/\evil.example/path` (`apps/auth-service/src/federation.rs:275-284`,
`apps/auth-web/src/lib/navigation.ts:1-3`). WHATWG URL resolution treats the
backslash as a slash for an HTTPS URL, so the callback/navigation resolves to
`https://evil.example/path` (`apps/auth-service/src/federation.rs:257-261`).

This does not leak the host-only session cookie, but it lets a crafted real
login terminate at an attacker-controlled phishing origin.

**Required action:** resolve first against the configured base and require the
resulting origin to be exactly the auth origin. Reject backslashes and encoded
separator ambiguity, and add server and browser regression tests.

### Low — a transient provider failure burns the login transaction

Federation marks the state consumed before token exchange, provider API/JWKS
requests, identity linking, and session creation
(`apps/auth-service/src/federation.rs:237-256`,
`crates/database/src/repositories.rs:625-642`). A transient provider or database
failure makes the browser callback permanently unretryable.

**Required action:** use claim/finalize state with bounded retry semantics, or
retain a short-lived claimed state and finalize it only after provider
verification and local commit. Do not hold a database transaction across the
provider network call.

## Verification and review coverage

Three independent passes covered architecture/concurrency, adversarial
authentication security, and web/edge/operations. The review traced public
inputs and authorization decisions across WebAuthn, OIDC, refresh rotation,
federation, JWT SDK/middleware, private mTLS RPC, PostgreSQL repositories,
SvelteKit, Traefik, configuration, CI, and runbooks.

Locally executed checks:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- `pnpm check:web`
- `pnpm test:web`
- `pnpm test:browser`
- `cargo deny check advisories`
- `pnpm audit --audit-level=high`

Formatting, Clippy, workspace unit tests, Svelte checks, Vitest, and Chromium
flows pass. The dependency gates pass at their configured thresholds;
`pnpm audit` reports one low-severity advisory. The ignored PostgreSQL/HTTP/RPC
suites are enabled in GitHub CI and the current PR check is green, but the gaps
above show that those suites do not exercise backup-passkey enrollment, the
effective SQLx connection options, real services behind the HTTPS edge, key
rotation, distributed rate limiting, or operational alerting.

## Merge criteria

At minimum, resolve the six release blockers, add regression coverage for the
database TLS parser and passkey enrollment, remove email-only account linking,
and demonstrate signing-key overlap plus the real composed HTTPS deployment.
The medium findings should be fixed or explicitly accepted with owner, threat
model, compensating controls, and a tracked expiry; documentation alone is not
a compensating security control.
