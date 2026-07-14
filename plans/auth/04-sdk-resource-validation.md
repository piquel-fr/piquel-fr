# 04 — Rust SDK and local resource-server validation

## Goal

Provide the stable integration surface that lets independent downstream products
perform secure OIDC flows and validate audience-restricted access tokens locally
without a per-request auth-service call.

## Prerequisite

Plans 00 and 03 are complete and expose stable discovery/JWKS/token fixtures.

## Scope

1. Create only the justified shared crates: `crates/auth-middleware` for
   framework-neutral validation (plus optional Axum adapter), `crates/auth-sdk`
   as the ergonomic facade, and an auth application-client module/crate only if
   it has a second consumer or is the public downstream boundary. Keep shared
   types in `auth-protocol`; do not move auth-service policy into the SDK.
2. Implement OIDC discovery fetch/cache, authorization URL construction, random
   state/nonce/PKCE generation, callback state validation, code exchange,
   refresh, and logout helpers. Browser-safe parts can later back
   `packages/auth-client-js`, but this plan must not put refresh tokens in
   JavaScript or prescribe product storage beyond the documented BFF/secure
   cookie/native secure-store rules.
3. Implement the `AuthMiddleware` builder. Production construction requires
   exact issuer, expected audience, trusted JWKS source, and an explicit allowed
   asymmetric algorithm. It may not disable signature, expiry, or audience
   verification. Test-only bypasses, if any, must be unmistakably feature-gated.
4. Enforce the specified validation sequence: one well-formed Bearer header;
   parse header; require `typ=at+jwt`, allowed alg, and `kid`; resolve a trusted
   JWKS key; verify signature; then validate exact issuer/audience, exp/nbf/iat,
   required claim types, and `UserId` format. Return an immutable
   `AuthenticatedUser`, not a raw JWT by default. Framework adapters map auth
   failures to 401 only; product authorization stays 403/business code.
5. Implement bounded in-memory JWKS caching: startup/first-use fetch, TTL,
   controlled single refresh on unknown `kid`, rate limiting of unknown-key
   refreshes, old-key overlap support, and fail-closed behavior. Never trust
   JWT-embedded keys or token-selected algorithms.
6. Define typed, redacted errors and tracing. Provide optional required-scope
   checking without implying that product resource authorization belongs here.
   Re-export the intended downstream API from `auth-sdk`; downstream consumers
   should not need workspace-internal crate knowledge.

## Tests and acceptance criteria

- Compatibility fixtures from plan 03 validate a real access token and reject
  ID/service/purpose tokens, incorrect audience/issuer/typ/alg, expiry, nbf,
  malformed IDs, multiple headers, and bad signatures.
- Mock HTTP tests prove JWKS TTL behavior, one bounded unknown-`kid` refresh,
  key-rotation overlap, rate limiting, and fail-closed network failures.
- Compile tests/examples demonstrate an Axum integration and direct
  framework-neutral use. Public APIs use typed errors and contain no SQLx,
  service private keys, or raw credential logging.
- Add a downstream-consumer compatibility test or minimal external-style sample
  that depends only on the intended SDK facade.

## Handoff

The SDK contract becomes a compatibility boundary. Plans 06 and 07 can add
separate RPC/UI integrations, but may not weaken resource-server validation.
