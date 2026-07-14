# Authentication implementation plan index

Implement these plans in numeric order. Each plan is intentionally a reviewable
vertical slice with explicit prerequisites; do not start a later plan by
recreating boundaries established by an earlier one.

| Plan | Outcome | Depends on |
| --- | --- | --- |
| [00-foundation.md](00-foundation.md) | Workspace, typed auth protocol, database crate, and configuration/telemetry foundations | — |
| [01-identity-sessions.md](01-identity-sessions.md) | Accounts, verified emails, central sessions, audit trail, and transactional event log | 00 |
| [02-passkeys.md](02-passkeys.md) | WebAuthn registration/authentication and a central browser session | 01 |
| [03-oidc-token-lifecycle.md](03-oidc-token-lifecycle.md) | OIDC Authorization Code + PKCE, signed tokens, refresh rotation, JWKS, and revocation | 01, 02 |
| [04-sdk-resource-validation.md](04-sdk-resource-validation.md) | Published Rust SDK surface and mandatory local access-token validation | 00, 03 |
| [05-federation.md](05-federation.md) | First approved social provider and safe automatic account linking | 01, 02 |
| [06-service-rpc.md](06-service-rpc.md) | Service identities, short-lived service tokens, private gRPC, and typed client | 00, 01, 03 |
| [07-auth-web.md](07-auth-web.md) | User-facing login, authorization, account-security, and error UI | 02, 03, 05 |
| [08-hardening-operations.md](08-hardening-operations.md) | Security hardening, observability, key rotation, operational runbooks, and end-to-end tests | 00–07 |

## Shared constraints

- Read `docs/architecture/monorepo.md` before changing workspace structure and
  `docs/architecture/database-crate.md` before changing persistence.
- `crates/database` (package name `piquel-repository`) is the only SQLx
  consumer. Applications receive `Database` and typed repository APIs only.
- Keep policy in `apps/auth-service`; keep stable shared protocol types in
  `crates/auth-protocol`; do not create speculative crates or applications.
- Public endpoints are HTTP/OIDC. Private RPC is gRPC on a separate,
  authenticated listener. Browser code never receives service credentials.
- Preserve exact audience validation and five-minute maximum access-token
  lifetime. Never log credentials, token material, codes, PKCE verifiers,
  WebAuthn challenges, or provider credentials.
- Each schema change is an immutable migration in `crates/database/migrations/`;
  update SQLx metadata when checked queries are used. Application replicas do
  not automatically run migrations.

The design intentionally defers a broker, Redis implementation, deletion
orchestration, TOTP, third-party/dynamic client registration, and product-owned
external OAuth credential storage. Do not add them in these plans.
