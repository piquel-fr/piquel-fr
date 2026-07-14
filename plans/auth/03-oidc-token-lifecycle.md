# 03 — OIDC, JWT issuance, refresh rotation, and revocation

## Goal

Implement the public standards-oriented authorization surface: static client
registration, Authorization Code with PKCE, SSO-aware authorization, signed ID
and access tokens, opaque rotating refresh tokens, discovery/JWKS, and logout
or revocation.

## Prerequisite

Plans 00–02 are complete. A production key-management integration must be
selected before deployment; test keys are allowed only in explicit test/dev
configuration.

## Scope

1. Add migrations/repositories for static OIDC clients and their allowed exact
   redirect/post-logout URIs, scopes, audiences, and authentication methods;
   authorization codes; refresh-token families/tokens; and token-purpose use
   records if needed. Authorization codes bind client, exact redirect URI, user,
   session, PKCE challenge/method, nonce, requested grant, expiry, and one-time
   consumption. Refresh token records store an indexed token ID and keyed digest
   only—never the raw value—and families bind user/client/session/device scope.
2. Implement auth-service `oidc` and `token` modules. Static client management
   is an administrative/bootstrap concern; dynamic registration is out of scope.
   Validate client enabled state, exact URI, `response_type=code`, allowed
   scopes/audience, required PKCE challenge (S256), state, nonce where ID token
   applies, `prompt`, `max_age`, and current session/authentication state.
3. Serve `/.well-known/openid-configuration`, `/.well-known/jwks.json`,
   `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke`,
   `GET /oidc/userinfo`, and `GET /oidc/logout`. Discovery is authoritative for
   actual endpoint paths. Authorization response failures must redirect only to
   a validated registered URI; token errors reveal no secrets.
4. On code exchange, atomically consume the code and issue: an ID token for the
   client, a five-minute maximum `at+jwt` ES256 access token for the registered
   API audience, and a product/device-specific opaque refresh token when the
   grant permits it. Claims must implement the design: exact issuer, UUIDv7
   `sub`, client ID, `sid`, `jti`, profile snapshot/version, `amr`, auth time,
   and correct time claims. ID tokens use client audience/nonce and must not be
   accepted as API tokens. Never allow a client to request another product's
   audience.
5. Implement signing behind a key-provider interface in auth-service. It selects
   the active asymmetric key and stable `kid`; JWKS publishes public keys,
   retains old keys through the issued-token overlap, and rejects unapproved
   algorithms. Private keys are not configuration literals or plaintext
   PostgreSQL data. Use a narrowly controlled dev/test signer only outside
   production.
6. Parse `prt_v1_<token-id>.<secret>` strictly and verify the secret with a
   constant-time appropriate primitive. Refresh in one short transaction: lock
   or atomic-consume active token, confirm family/session/client/audience status,
   mark consumed, insert replacement, then commit before returning it. A replay
   of a consumed token revokes its whole family atomically, audits the incident,
   and returns an invalid-grant result. Concurrent refresh attempts must allow
   exactly one success.
7. Implement revocation/logout semantics for one refresh family, central session,
   and all user sessions, with idempotent operations and audit/event entries.
   Clearly document the accepted maximum five-minute access-JWT tail. UserInfo
   accepts only an appropriate valid access token and returns only granted,
   allowed claims.

## Tests and acceptance criteria

- Protocol tests cover every required request validation and prohibit wildcard or
  prefix redirect matching, missing PKCE, code reuse, wrong verifier/client/URI,
  audience escalation, expired code, and invalid nonce handling.
- JWT fixtures verify headers (`typ=at+jwt`, ES256, known `kid`) and every claim
  contract. JWKS rotation tests prove both overlap verification and retired-key
  rejection.
- PostgreSQL concurrency tests prove one refresh succeeds and replay revokes the
  family. Tests confirm raw refresh tokens/digests never appear in logs/errors.
- End-to-end browser-flow tests cover SSO through an existing central session,
  code exchange, token refresh, revoke/logout, and the inability to use an ID
  token at an API resource boundary.

## Handoff

Plan 04 consumes discovery/JWKS and claims as the downstream SDK contract. Plan
06 may reuse the signer but issues distinct service tokens and does not reuse
user access-token audiences.
