# Monorepo boundaries

This repository contains piquel.fr and its services. The current implemented scope
is authentication, with its account settings, and the admin dashboard.

| Location | Responsibility |
| --- | --- |
| `apps/auth-service` | Rust auth authority, browser ceremonies, social adapters, OIDC, server-rendered pages, settings and admin APIs, CLI; `assets/passkey.js`, the one script its pages load: the WebAuthn passkey ceremonies and the form hooks that run them |
| `apps/admin-web` | The admin dashboard at admin.piquel.fr: server-rendered Topcoat pages calling auth's private admin API |
| `crates/database` | `piquel-repository`: PostgreSQL connections, migrations and typed persistence operations |
| `crates/auth-sdk` | `piquel-auth`, the public Rust SDK: token validation, typed scopes, login and the JWKS cache auth also uses for Google; `axum` feature: extractors, bearer layer, login routes over an application's own session backend |
| `crates/admin-api` | `piquel-admin-api`: the paths and JSON bodies of auth's private admin API, shared with the admin dashboard; `client` feature: the dashboard's typed client |
| `crates/common` | `piquel-common`, the one home for shared types: IDs, string enums, `Personal<T>`, and the wire types shared by auth and the SDKs (token claims, discovery metadata, JWK sets, OAuth/OIDC vocabulary and errors, bearer challenges, SDK error codes, and the bodies auth's settings and admin APIs share); `config` feature: environment variables, validated origins, secret references; `events` feature: domain events |
| `crates/crypto` | Random secrets, SHA-256, HMAC, PKCE and RS256 signing |
| `crates/ui` | `piquel-ui`: the Topcoat components and layouts of auth's server-rendered pages, rendering plain data and taking URLs as props, and the shared stylesheet, `assets/style.css`, which admin-web also serves |
| `crates/telemetry` | `piquel-telemetry`: stderr logs, and OpenTelemetry traces, metrics and logs over OTLP; request spans and access logs for axum routers, client spans, and typed metric instruments; see [telemetry.md](telemetry.md) |
| `tests/sdk-vectors` | Generated cases every SDK must pass; see [sdk.md](sdk.md) |

Prettier and type-aware ESLint cover all web code from the root configuration, as
rustfmt and Clippy cover Rust; `just fmt`, `just lint` and `just check` run both.
`tsc` checks the passkey script's JSDoc types as strictly as TypeScript's; nothing
builds JavaScript.

Only `crates/database` runs SQL. `piquel-common` has an optional `sqlx` feature,
enabled only by the database crate, that lets its IDs and vocabularies decode from
columns. Its other server-only parts sit behind the `config` and `events` features,
so the Rust SDK compiles only IDs and wire types. Auth-service owns authentication policy;
frontends never receive database credentials or provider secrets. Shared types
go in `piquel-common`; add new crates only for independently auditable primitives,
or, as `piquel-ui`, to compile slow view code beside the database crate instead of
after it.

The auth runtime is one executable with one public HTTP listener, plus a private
listener for the admin API when it is configured. The executable embeds the shared
stylesheet and the passkey script. Auth renders every
page itself, sign-in included, and the account settings at `/settings`; piquel.fr
only redirects there. The permanent WebAuthn RP ID is the auth hostname, never a wildcard over
piquel.fr subdomains.

Auth's pages live in `apps/auth-service/src/web`, grouped by area: `auth`, the
sign-in flows (signing in and up, consent, logout and the recovery pages),
`settings` and `developers`.

The auth binary also runs explicit migrations, generates invitations and grants
administrators. PostgreSQL
stores sessions, WebAuthn challenges, OAuth state, pending social identities,
invitations, consent, refresh tokens, rate limits and security events.
Auth needs no separate cache, RPC service, event bus or key-management service.
The admin dashboard has no database: it keeps administrators' sign-ins in memory
and reads everything from the admin API. External applications
consume standard OIDC; operators register their clients in the database with
`auth-service client`.

[surfaces.md](surfaces.md) sets out what auth.piquel.fr, piquel.fr and
admin.piquel.fr each serve. Build/configuration and testing instructions are in
the root README; every task runs through `just`. Deployment uses piqueld (`infra/README.md`). The Rust SDK for
applications follows [sdk.md](sdk.md). Public application registration is outside
this release.
