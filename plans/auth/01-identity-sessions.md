# 01 — Core identity, email, sessions, audit, and internal events

## Goal

Implement the authoritative account state that all authentication methods use:
global users, conservative verified emails, central login sessions, security
audit records, and an append-only transactional domain-event log.

## Prerequisite

Plan 00 is complete, including an integration-testable database crate.

## Scope

1. Add immutable auth-owned migrations for `users`, `user_emails`, `sessions`,
   `security_audit_log`, and `internal_events`. Use UUIDv7 primary identities
   (or documented compatible representation), UTC timestamps, foreign keys, and
   deliberate indexes. Add a partial/conditional uniqueness constraint so a
   normalized email cannot be verified for two active accounts; do not use a
   blanket unique constraint that prevents unverified onboarding states. Ensure
   exactly one primary verified email per account when an account has one.
2. Implement typed public database models, private SQLx row conversion, and
   focused repositories for persistence actions such as user insert/find/status
   update/profile update, verified-email lookup/insert/primary selection,
   session create/find/touch/revoke, audit append, and event append. Use
   explicit input structures and typed conflicts. All list APIs are bounded.
3. Extend `DatabaseTransaction` with those repository families. Document row
   locks and write integration tests for duplicate verified email rejection,
   primary-email integrity, idempotent session revocation, and per-aggregate
   event sequence uniqueness. Allocate event sequence numbers transactionally;
   event append and the state mutation it describes must commit together.
4. Add private `account`, `email`, `session`, `audit`, and `event_log` modules to
   `apps/auth-service`. They own validation and policy, while repositories only
   persist. Implement account creation with an optional already-verified email
   as one short transaction and append both security audit/event entries as
   appropriate. Accounts must be able to start passkey-first with no email;
   social linking will create an initial verified email from its verified claim.
5. Define and document conservative email normalization: Unicode handling where
   chosen, domain case normalization, and a clear local-part rule. It must not
   strip plus suffixes, remove dots, or apply provider-specific equivalence.
   Make normalization a tested domain function, not a SQL expression.
6. Implement central session state with authentication time/methods, expiry,
   last-seen tracking, client metadata minimization, and revocation. This plan
   exposes service-layer methods, not public login endpoints; plan 02 will
   establish the browser cookie after a successful authentication ceremony.
7. Provide narrow account/profile read and mutation interfaces needed by later
   plans. A display-name/username change increments `profile_version` using
   optimistic concurrency and emits an event. Downstream identity is always
   `UserId`; username/display name are presentation snapshots only.

## Data and security rules

- `users` contains immutable ID, username, display name, monotonically
  increasing profile version, account status, and timestamps. Enforce username
  uniqueness according to a separately documented validation policy.
- The design does not authorize an email-delivery/verification protocol or mail
  provider. This plan owns verified-email persistence and normalization only;
  do not fabricate verification emails/endpoints. A later approved plan must
  add the delivery, proof, expiry, and recovery policy before arbitrary email
  entry can become verified.
- Audit rows record action/outcome and sanitized request metadata; they never
  include token values, emails as metric labels, or raw client secrets.
- `internal_events` is append-only with unique event ID and
  `(aggregate_type, aggregate_id, aggregate_sequence)`. Payloads are versioned
  JSON events, never credentials; `published_at` is future-publication metadata
  only, not a broker implementation.
- Account disabling and session revocation must be idempotent and provide the
  state needed for later refresh-family revocation. Do not pretend existing
  access JWTs can be immediately revoked.

## Tests and acceptance criteria

- PostgreSQL integration tests cover constraints, transactions, optimistic
  profile updates, concurrent email conflict, session revocation, and event
  sequencing.
- Unit tests cover normalization edge cases and profile-version behavior.
- Auth-service tests prove an account creation transaction leaves no partial
  user/email/event/audit state if any insert fails.
- Checked-query metadata and migration tests are updated where applicable.

## Handoff

Plan 02 consumes account/session services and adds passkey state. Plan 03 adds
OIDC sessions/codes and refresh-token families. Do not add passkey, token, or
federated identity tables in this plan.
