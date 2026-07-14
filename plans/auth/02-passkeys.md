# 02 — Passkey authentication and central browser sessions

## Goal

Add WebAuthn as the first authentication method, including durable credential
storage, short-lived ceremony state, central login-session cookies, and
account-security operations protected by fresh authentication.

## Prerequisite

Plans 00–01 are complete. Confirm the selected WebAuthn library supports the
required relying-party/origin validation and exposes no private-key handling.

## Scope

1. Add `passkey_credentials` migration and repository/model support. Persist
   credential ID (unique), user ID, public key, signature counter, transports,
   backup eligibility/state, friendly name, created/last-used/revoked fields.
   Use typed binary/structured representations and validate database values at
   row conversion. Private keys must never enter the service or database.
2. Add private `passkey` domain module. Configure the RP ID and expected origin
   from validated auth-service configuration (`auth.piquel.fr` in production).
   Explicitly select user-verification policy. Produce opaque, single-use,
   cryptographically random registration/authentication challenges with short
   expiry; validate origin, RP ID, challenge, authenticator result, and
   signature-counter behavior before persistence.
3. Store ceremony state in a replaceable short-lived state abstraction. The
   first implementation may use protected server-side/session storage, but it
   must be safe across stateless replicas and survive no longer than its TTL.
   Redis is optional and must not become authoritative; document the chosen
   backend and failure behavior. Never put challenge secrets in URLs or logs.
4. Implement supported public HTTP endpoints in `apps/auth-service`:
   `POST /webauthn/register/start`, `/finish`, `/authenticate/start`, and
   `/finish`. Registration supports two explicit server-selected intents:
   passkey-first account bootstrap (collect and validate required profile fields,
   then create user and credential atomically) and adding a credential to an
   existing account (requires central session plus fresh, purpose-bound
   authorization). The bootstrap path creates no unverified email and must not
   claim email ownership. Authentication start/finish creates or refreshes a
   central session. Map malformed/expired/replayed ceremony state to generic
   client-safe errors.
5. Implement secure central-session cookie issuance, parsing, renewal, logout
   clearing, and revocation lookup. Cookies are Secure and HttpOnly, have an
   explicitly selected SameSite policy compatible with OIDC/social redirects,
   use a host-safe name/path/domain, and contain only an opaque reference (or
   authenticated equivalent), never a bearer access/refresh token.
6. Provide passkey list/rename/remove service endpoints for the future auth-web.
   Addition/removal must require a purpose token created after fresh passkey
   authentication. Build a narrowly scoped reauthentication/purpose-token
   mechanism now: ES256-signed, `aud=piquel-account-management`, user/session
   bound, operation purpose bound, roughly two-minute expiry, and optional
   single-use persistence when an operation needs it. A refresh token cannot
   authorize these changes.
7. Append security audit and internal event records for credential enrollment,
   use, rename, removal, and ceremony failures where safe. Update last-used and
   signature counter atomically with successful authentication.

## Tests and acceptance criteria

- Unit tests cover ceremony expiry, single use, purpose/audience/user/session
  mismatch, cookie construction, and no-secret error formatting.
- Integration tests use a standards-conformant WebAuthn test authenticator (or
  vetted test fixture) to prove successful register/login, duplicate credential
  rejection, invalid origin/RP/challenge rejection, revoked credential
  rejection, and concurrent credential uniqueness.
- A multi-replica-style test proves ceremony/session state is not process-local.
- HTTP tests assert security headers/cookie attributes and generic public error
  responses; tracing tests assert challenges and credential material are absent.

## Handoff

Plan 03 reuses central sessions for SSO and fresh-login requirements. Plan 05
may treat a successful approved social login as a fresh authentication under the
first-iteration policy; keep the purpose-token assurance model extensible.
