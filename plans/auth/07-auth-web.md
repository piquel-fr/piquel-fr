# 07 — Auth web experience and public-flow integration

## Goal

Deliver the user-facing `auth.piquel.fr` experience over the supported HTTP
API: login, passkey enrollment/security management, social sign-in, OIDC
authorization, session/logout behavior, and safe error handling.

## Prerequisite

Plans 02, 03, and 05 are complete. Select SvelteKit or a React-based framework
using repository policy before scaffolding `apps/auth-web`; do not introduce a
second frontend framework without a concrete need.

## Scope

1. Create `apps/auth-web` as an independently deployable frontend that calls
   public auth HTTP APIs only. Add it to the JS workspace only when a real
   `package.json`/pnpm workspace is introduced. It has no PostgreSQL access,
   service credentials, private keys, or internal gRPC client.
2. Build the login/continuation screens for passkey authentication and approved
   social provider initiation. Handle WebAuthn browser capability/errors,
   double-submit prevention, generic authentication failure messages, return to
   a validated OIDC transaction, and an authenticated existing central session.
   Preserve server-provided transaction correlation without exposing secrets.
3. Implement OIDC authorization UX: interpret only server-validated request
   details, show the requested product/client/audience/scopes, continue or deny,
   and redirect only through the server's validated path. Do not implement a
   product-specific consent system beyond the first-iteration behavior defined
   by the service; do not trust query display fields as authorization inputs.
4. Provide account-security screens backed by the API: list/rename/remove
   passkeys, add passkey after fresh authentication, list social identities,
   sign out, and session status where the server exposes it. All sensitive
   mutations use the short-lived purpose-token flow, never a refresh token in
   browser JavaScript.
5. After a successful social sign-in for an account without passkeys, show the
   non-blocking recommendation to add one. Use distinct language for “Sign in
   with GitHub” (identity authentication) and “Connect GitHub” (a product-owned
   external integration, deliberately not implemented here).
6. Build accessible loading, error, expired-session, unsupported-browser, and
   security-sensitive confirmation states. Apply CSP, secure asset handling,
   CSRF defenses for cookie-authenticated mutations, and no-store/cache-control
   for token/authorization pages. Never place authorization codes, state,
   challenge data, user tokens, or private configuration in analytics/client
   logs.

## Tests and acceptance criteria

- Browser-level tests cover passkey start/finish, social redirect/callback,
  SSO authorization continuation, cancellation, logout, reauthentication for a
  sensitive passkey action, and generic error behavior.
- Accessibility tests cover keyboard-only navigation, labeled controls, focus
  behavior after failures, and provider/passkey alternatives.
- Build/static inspection proves no internal endpoint, secret, service key, or
  refresh-token localStorage use is present. HTTP tests assert CSP/CSRF/cache
  headers and endpoint-origin protections.
- Product-flow tests verify all post-auth redirects are accepted only after
  server-side exact redirect-URI validation.

## Handoff

Plan 08 adds the security/operational validation around this UI. Account
deletion, TOTP, product OAuth credential management, and full user-device
management remain intentionally deferred.
