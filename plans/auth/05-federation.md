# 05 — Approved social login and automatic account linking

## Goal

Add one approved external identity provider as a complete authentication method
while enforcing stable issuer/subject identity, verified-email-only automatic
linking, and the first-iteration social-recovery policy.

## Prerequisite

Plans 01–02 are complete. Select the first provider and record its issuer,
OIDC/OAuth metadata source, required verified-email claim semantics, key
validation, and whether it is explicitly allowed to auto-link before coding.

## Scope

1. Add a migration and repository/model for `external_login_identities` with
   unique `(issuer, subject)`, user foreign key, provider name, linked email,
   timestamps, and revocation. Store provider client secrets through the
   configuration/secret-reference boundary, never in the database or logs.
2. Add a private `federation` module and provider adapter interface inside
   auth-service. It owns provider allowlisting, initiation, callback validation,
   issuer/subject extraction, verified-email verification, metadata/JWKS use,
   provider error normalization, and state/nonce/PKCE transaction handling.
   Do not create a generalized connector platform; implement only the selected
   provider behind a small testable interface.
3. Serve `GET /login/{provider}` and `/login/{provider}/callback`. Bind the
   initiation transaction to the browser/session and return URL, expiry, state,
   nonce, and PKCE data. Validate it exactly once on callback before provider
   token processing. Use server-to-server token exchange with deadlines and
   safe retries; provider credentials are transient and redacted.
4. Implement the linking transaction exactly: find by issuer/subject; otherwise
   require an asserted verified, usable provider email; normalize it using plan
   01 policy; find exactly one active Piquel user by verified email; link if one
   exists; create a new account and verified email if none exists; reject
   ambiguous/disabled/unverified/not-approved cases. Rely on unique constraints
   and map concurrent races to safe re-read/retry behavior. Email never becomes
   the durable provider key after this step.
5. Successful social login establishes/updates the central session with the
   social authentication method and can satisfy fresh authentication for
   passkey-management purpose tokens, as explicitly accepted in the design.
   Record auditing/event entries for link, login, rejection, and recovery
   actions; arrange user notification through a future-safe interface without
   implementing an unselected mail system.
6. Expose narrow authenticated operations to list/link/unlink social identities
   for later UI. Linking/unlinking requires a purpose token and must not permit
   removing the account's last viable login method. The exact recovery policy is
   enforced in auth-service, not repositories.

## Tests and acceptance criteria

- Adapter contract tests use signed provider fixtures and mock discovery/JWKS
  endpoints; cover invalid issuer/signature/nonce/state/PKCE/callback and
  missing or unverified email.
- Transaction tests cover existing mapping, one matching account, no account,
  duplicate mapping race, ambiguous legacy data, disabled user, and no
  provider-specific email rewriting.
- End-to-end tests show social SSO, a new account, automatic linking, and fresh
  social reauthentication enabling a passkey operation under the accepted policy.
- Logs/traces/errors contain no social access/refresh tokens, callback codes, or
  state secrets.

## Handoff

Plan 07 presents the provider choice and post-social passkey recommendation.
Future providers require their own reviewed plan; do not add them by copying
provider-specific assumptions.
