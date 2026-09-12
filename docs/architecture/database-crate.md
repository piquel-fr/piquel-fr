# PostgreSQL boundary

`crates/database` is the only SQLx consumer. It exposes `Database`, validated
`DatabaseConfig`, typed repository handles, and `DatabaseTransaction`. Pools,
connections, rows and raw SQL remain private. Application modules choose policy;
repository methods enforce atomic persistence and return contextual errors.

Repository modules separate identity/passkeys, OIDC and federation. Transactions
expose the same repository families as `Database`. User, session and credential
locks serialize security-sensitive changes. Acquire account locks before session
and credential locks. Credentials are rechecked under lock before authentication
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

The prototype schema is disposable. The release requires a fresh database;
subsequent released migrations must be immutable. Run migrations with
`auth-service migrate`; startup does not silently mutate the schema.

Every five minutes the service purges bounded batches of expired ephemeral state.
Security audit history is retained. Tests that use `TEST_DATABASE_URL` are explicitly
marked ignored by the ordinary unit test runner; the documented database test
command includes them and must use a disposable database.
