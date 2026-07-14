# 08 — Security hardening, observability, and operational readiness

## Goal

Turn the implemented first iteration into an operable, security-reviewed auth
service: abuse controls, data-protection checks, monitoring, key lifecycle,
backup/restore evidence, and cross-boundary failure tests.

## Prerequisite

Plans 00–07 are complete. This plan must not silently expand scope into an event
broker, Redis-as-authority, or a deployment platform that has not been chosen.

## Scope

1. Add rate limiting and replay/abuse controls for login, WebAuthn ceremonies,
   authorization/token endpoints, provider callbacks, service assertions, and
   unknown-`kid` JWKS refreshes. Redis may be selected as disposable shared
   coordination only after failure-mode design; PostgreSQL remains authoritative
   for identities, sessions, refresh revocation, audit, events, and key metadata.
   Define fail-open/fail-closed behavior per endpoint and test Redis loss.
2. Finalize production key-provider integration and a documented signing-key
   rotation procedure: stable `kid`, active key selection, JWKS overlap until all
   affected token classes expire, distinct development/production keys, access
   restriction to auth-service, and readiness failure if required keys cannot be
   used. Add the parallel administrative service-public-key rotation procedure.
3. Instrument sanitized metrics/traces for the design’s login, credential,
   authorization-code, token/refresh replay, JWKS, RPC, DB, Redis, and rate-limit
   outcomes. Keep labels bounded; never use emails, raw IDs, tokens, headers, or
   unbounded user data. Add dashboards/alerts only under `infra/monitoring/` and
   only in the format supported by the chosen monitoring stack.
4. Complete health and graceful-shutdown behavior. Liveness stays process-only;
   readiness verifies PostgreSQL plus required key dependencies and fails closed.
   On termination, stop intake, honor bounded request/RPC deadlines, and roll
   back unfinished transactions. Verify replica safety for concurrent social
   callbacks, refreshes, and ceremony/session coordination.
5. Add operational docs under `docs/operations/` for migrations/release order,
   signing/service-key rotation, auth outage behavior, token replay incident,
   backup restoration, and audit-log investigation. Add/update security docs for
   accepted risks (social trust/linking/recovery and five-minute JWT tail) and
   the redaction/data-retention policy. Use ADRs only if these choices change a
   documented architecture boundary.
6. Perform security-focused test work: fuzz/property tests for token/refresh
   parsing and redirect validation, negative OIDC/WebAuthn/provider/RPC tests,
   database permission tests when roles are provisioned, dependency/security
   audit, migration-from-empty and upgrade-path tests, and backup/restore drills
   that validate authentication invariants without copying sensitive test data.

## Release gates

- A key rotation in a test environment proves new issuance, old-key verification
  during overlap, and old-key removal only after expiry.
- Loss of Redis (if used) does not corrupt authoritative state; the documented
  endpoint degradation behavior is observed.
- An intentional refresh replay produces one family revocation, audit/metric
  signal, a generic client error, and no leaked token material.
- Multi-replica integration tests prove no double code exchange, refresh
  rotation, event sequence, or identity link can succeed.
- Dashboards/alerts contain no secret/high-cardinality labels; alert simulations
  cover elevated login failure, replay, signing, DB, and RPC-auth failures.
- Full workspace formatting, linting, unit/integration/browser tests, migration
  tests, and SQLx metadata checks pass. Record any remaining accepted risk rather
  than masking it with an untested control.

## Explicitly deferred

Do not implement a broker/consumer delivery system, deletion orchestration,
TOTP, risk-based authentication, third-party registration, token exchange,
central storage of product external-provider credentials, or provider framework
generalization. The transactional event log remains a foundation for later work,
not a claim of delivered event publishing.
