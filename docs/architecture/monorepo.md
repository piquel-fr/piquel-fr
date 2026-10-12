# Monorepo boundaries

This repository contains piquel.fr and its services. The current implemented scope
is authentication and the piquel.fr account settings frontend.

| Location | Responsibility |
| --- | --- |
| `apps/auth-service` | Rust auth authority, browser ceremonies, social adapters, OIDC, settings API, CLI |
| `apps/auth-web` | Static SvelteKit auth pages embedded by the Rust build |
| `apps/piquel-web` | Static SvelteKit account settings calling the auth API |
| `packages/auth-sdk` | Browser auth SDK: API client, WebAuthn passkey ceremonies, redirect helpers, shared styles |
| `crates/database` | PostgreSQL connections, migrations and typed persistence operations |
| `crates/auth-protocol` | Shared identity/session/token IDs and authentication enums |
| `crates/configuration` | URL and redacted secret-reference validation |
| `crates/telemetry` | Tracing initialization |

Prettier and type-aware ESLint cover all web code from the root configuration, as
rustfmt and Clippy cover Rust; `just fmt`, `just lint` and `just check` run both.

Only the database crate accesses SQLx. Auth-service owns authentication policy;
frontends never receive database credentials or provider secrets. Add new crates
only when another actual consumer needs them.

The auth runtime is one executable and one HTTP listener. Login assets are built
before Rust and embedded in the executable. Account settings remain on piquel.fr;
its exact origin can call the public auth API with the auth host's cookie. Passkey
operations redirect to auth.piquel.fr. The permanent WebAuthn RP ID is the auth
hostname, never a wildcard over piquel.fr subdomains.

The auth binary also runs explicit migrations and generates invitations. PostgreSQL
stores sessions, WebAuthn challenges, OAuth state, pending social identities,
invitations, consent, refresh tokens, rate limits and security audit records.
No separate cache, RPC service, Node server, event bus or key-management service is
required. External applications consume standard OIDC with static client registration.

Build/configuration and testing instructions are in the root README; every task
runs through `just`. Deployment uses piqueld (`infra/README.md`). Public application
registration, SDKs and account recovery are outside this release.
