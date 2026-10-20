# Monorepo boundaries

This repository contains piquel.fr and its services. The current implemented scope
is authentication and the piquel.fr account settings frontend.

| Location | Responsibility |
| --- | --- |
| `apps/auth-service` | Rust auth authority, browser ceremonies, social adapters, OIDC, settings and admin APIs, CLI |
| `apps/auth-web` | Static SvelteKit auth pages embedded by the Rust build |
| `apps/piquel-web` | piquel.fr's SvelteKit server on Node: account settings calling the auth API |
| `apps/admin-web` | The admin dashboard at admin.piquel.fr: server-rendered Topcoat pages calling auth's private admin API |
| `packages/auth-sdk` | Browser auth SDK: API client, WebAuthn passkey ceremonies, redirect helpers, shared styles; `/server`: auth origin validation and security headers for SvelteKit servers |
| `crates/database` | `piquel-repository`: PostgreSQL connections, migrations and typed persistence operations |
| `crates/auth-sdk` | `piquel-auth`, the public Rust SDK: token validation, typed scopes, login and the JWKS cache auth also uses for Google; `axum` feature: extractors, bearer layer, login routes over an application's own session backend |
| `crates/admin-api` | `piquel-admin-api`: the paths and JSON bodies of auth's private admin API, shared with the admin dashboard; `client` feature: the dashboard's typed client |
| `crates/common` | `piquel-common`, the one home for shared types: IDs, string enums, `Personal<T>`, and the wire types shared by auth and the SDKs (token claims, discovery metadata, JWK sets, OAuth/OIDC vocabulary and errors, bearer challenges, SDK error codes, and the bodies auth's settings and admin APIs share); `config` feature: environment variables, validated URLs, secret references; `events` feature: domain events |
| `crates/crypto` | Random secrets, SHA-256, HMAC, PKCE and RS256 signing |
| `crates/telemetry` | Structured tracing initialization |
| `tests/sdk-vectors` | Generated cases both SDKs must pass; see [sdk.md](sdk.md) |

Prettier and type-aware ESLint cover all web code from the root configuration, as
rustfmt and Clippy cover Rust; `just fmt`, `just lint` and `just check` run both.

Only `crates/database` runs SQL. `piquel-common` has an optional `sqlx` feature,
enabled only by the database crate, that lets its IDs and vocabularies decode from
columns. Its other server-only parts sit behind the `config` and `events` features,
so the SDKs compile only IDs and wire types. Auth-service owns authentication policy;
frontends never receive database credentials or provider secrets. Shared types
go in `piquel-common`; add new crates only for independently auditable primitives.

The auth runtime is one executable with one public HTTP listener, plus a private
listener for the admin API when it is configured. Login assets are built
before Rust and embedded in the executable. Account settings remain on piquel.fr;
its exact origin can call the public auth API with the auth host's cookie. Passkey
operations redirect to auth.piquel.fr. The permanent WebAuthn RP ID is the auth
hostname, never a wildcard over piquel.fr subdomains.

The auth binary also runs explicit migrations, generates invitations and grants
administrators. PostgreSQL
stores sessions, WebAuthn challenges, OAuth state, pending social identities,
invitations, consent, refresh tokens, rate limits and security events.
Auth needs no separate cache, RPC service, event bus or key-management service.
piquel.fr's Node server holds no state and reads everything it renders from auth's
HTTP API. The admin dashboard has no database either: it keeps administrators'
sign-ins in memory and reads everything from the admin API. External applications
consume standard OIDC; operators register their clients in the database with
`auth-service client`.

[surfaces.md](surfaces.md) sets out what auth.piquel.fr, piquel.fr and
admin.piquel.fr each serve. Build/configuration and testing instructions are in
the root README; every task runs through `just`. Deployment uses piqueld (`infra/README.md`). The SDKs for
applications follow [sdk.md](sdk.md). Public application registration and account
recovery are outside this release.
