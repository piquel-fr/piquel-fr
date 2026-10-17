# Monorepo boundaries

This repository contains piquel.fr and its services. The current implemented scope
is authentication and the piquel.fr account settings frontend.

| Location | Responsibility |
| --- | --- |
| `apps/auth-service` | Rust auth authority, browser ceremonies, social adapters, OIDC, settings API, CLI |
| `apps/auth-web` | Static SvelteKit auth pages embedded by the Rust build |
| `apps/piquel-web` | piquel.fr's SvelteKit server on Node: account settings calling the auth API |
| `packages/auth-sdk` | Browser auth SDK: API client, WebAuthn passkey ceremonies, redirect helpers, shared styles; `/server`: auth origin validation and security headers for SvelteKit servers |
| `crates/database` | `piquel-repository`: PostgreSQL connections, migrations and typed persistence operations |
| `crates/auth-protocol` | Wire types shared by auth and the SDKs: IDs, token claims, discovery metadata, JWK sets, OAuth/OIDC vocabulary and errors, bearer challenges, SDK error codes |
| `crates/common` | Named environment variables, validated URLs, secret references and string enums |
| `crates/crypto` | Random secrets, SHA-256, HMAC, PKCE and RS256 signing |
| `crates/telemetry` | Structured tracing initialization |
| `tests/sdk-vectors` | Generated cases both SDKs must pass; see [sdk.md](sdk.md) |

Prettier and type-aware ESLint cover all web code from the root configuration, as
rustfmt and Clippy cover Rust; `just fmt`, `just lint` and `just check` run both.

Only `crates/database` runs SQL. `piquel-common` and `piquel-auth-protocol` have
an optional `sqlx` feature, enabled only by the database crate, that lets their
IDs and vocabularies decode from columns. Auth-service owns authentication policy;
frontends never receive database credentials or provider secrets. Add new crates
for shared domain values or independently auditable primitives.

The auth runtime is one executable and one HTTP listener. Login assets are built
before Rust and embedded in the executable. Account settings remain on piquel.fr;
its exact origin can call the public auth API with the auth host's cookie. Passkey
operations redirect to auth.piquel.fr. The permanent WebAuthn RP ID is the auth
hostname, never a wildcard over piquel.fr subdomains.

The auth binary also runs explicit migrations and generates invitations. PostgreSQL
stores sessions, WebAuthn challenges, OAuth state, pending social identities,
invitations, consent, refresh tokens, rate limits and security audit records.
Auth needs no separate cache, RPC service, event bus or key-management service.
piquel.fr's Node server holds no state and reads everything it renders from auth's
HTTP API. External applications consume standard OIDC with static client registration.

[surfaces.md](surfaces.md) sets out what auth.piquel.fr, piquel.fr and
admin.piquel.fr each serve. Build/configuration and testing instructions are in
the root README; every task runs through `just`. Deployment uses piqueld (`infra/README.md`). The SDKs for
applications follow [sdk.md](sdk.md). Public application registration and account
recovery are outside this release.
