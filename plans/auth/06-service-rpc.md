# 06 — Service identities and private gRPC API

## Goal

Implement authenticated, authorized internal RPC for exceptional authoritative
operations while preserving local JWT validation as the normal product request
path.

## Prerequisite

Plans 00, 01, and 03 are complete. Decide the protobuf generation/check-in
policy and TLS certificate source before adding generated code.

## Scope

1. Add versioned definitions under `proto/piquel/auth/v1/` for exactly the
   initial `AuthService` methods: `GetUser`, `BatchGetUsers`,
   `GetSessionStatus`, `RevokeSession`, `RevokeAllUserSessions`, and
   `GetServiceConfiguration`. Define request/response fields and stable error
   mapping without exposing database rows. Reserve deleted field numbers/names;
   generate clients through repository tooling, never hand-edit output.
2. Add migrations/repositories for service identities, public keys, permitted
   RPC methods/data fields, and supporting audit state. A registration has
   service ID, display name, enabled status, asymmetric public keys with `kid`,
   algorithm/lifetime/revocation, and explicit permissions. Runtime services
   never write their registration or rotate their own keys.
3. Implement `service_identity` inside auth-service and a small
   `crates/service-auth` boundary. A backend signs a short-lived client
   assertion with its private key; auth-service verifies issuer/audience/time,
   assertion identity and key status, replay controls where required, and then
   issues a distinct five-minute service JWT for `piquel-internal-api`. User and
   service claims/audiences must remain non-interchangeable.
4. Expose the service-token endpoint only on the private surface (or another
   deliberately protected internal endpoint) with TLS, strict body limits and
   deadlines. Use the signing/key-provider contract from plan 03 but a distinct
   token type and validation rules. Audit issuance failures and administrative
   changes without storing assertions/tokens.
5. Implement the separate internal Tonic listener in auth-service. Require TLS
   and service-token metadata, validate it before dispatch, enforce method/data
   permissions per service identity, default deadlines/message-size limits, and
   disable public reflection. RPC methods use typed repository/domain APIs and
   are bounded (especially batch reads); there is no `ValidateAccessToken` RPC.
6. Add `crates/auth-client` plus SDK re-exports. It wraps generated clients with
   concurrency-safe service-token caching/early renewal, request metadata,
   deadlines, sanitized tracing, and at most one safe retry after authentication
   failure. It must not retry non-idempotent revocations blindly or create a
   Tokio runtime. Keep a clear public API that downstream backends can use.

## Tests and acceptance criteria

- Protobuf compatibility lint/tests verify package versioning and reserved
  fields. Generated code is reproducible from documented commands.
- Tests reject disabled/unknown services, invalid/expired/assertion replayed
  credentials, wrong audience/token type, revoked keys, missing TLS identity,
  oversized/deadline-exceeded requests, and unauthorized method/data access.
- gRPC integration tests validate service-token injection/renewal under
  concurrent callers, bounded retry behavior, permission filtering, and
  idempotent revocation semantics.
- Demonstrate that ordinary access-token validation remains entirely local via
  the SDK; no product request needs this RPC service.

## Handoff

Plan 08 operationalizes service-key rotation and RPC monitoring. Administrative
registration/key rotation needs a reviewed administrative workflow; do not put
those privileges in the SDK or browser UI.
