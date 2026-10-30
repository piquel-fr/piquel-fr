# Monorepo boundaries

This repository contains piquel.fr and its services. The current implemented scope
is authentication, with its account settings, and the admin dashboard.

| Location | Responsibility |
| --- | --- |
| `apps/auth-service` | Rust auth authority, browser ceremonies, social adapters, OIDC, server-rendered pages, the settings API, the admin dashboard at admin.piquel.fr, CLI; `assets/passkey.js`, the one script its pages load: the WebAuthn passkey ceremonies and the form hooks that run them |
| `crates/database` | `piquel-repository`: PostgreSQL connections, migrations and typed persistence operations |
| `crates/auth-sdk` | `piquel-auth`, the public Rust SDK: token validation, typed scopes, login and the JWKS cache auth also uses for Google; `axum` feature: extractors, bearer layer, login routes over an application's own session backend |
| `crates/common` | `piquel-common`, the one home for shared types: IDs, string enums, `Personal<T>`, and the wire types shared by auth and the SDKs (token claims, discovery metadata, JWK sets, OAuth/OIDC vocabulary and errors, bearer challenges, SDK error codes, and the bodies auth's settings API and the admin views share); `admin` feature: the views of administration, which the admin dashboard shows, the CLI prints as JSON and the database crate decodes into; `config` feature: environment variables, validated origins, secret references; `events` feature: domain events |
| `crates/crypto` | Random secrets, SHA-256, HMAC, PKCE and RS256 signing |
| `crates/ui` | `piquel-ui`: the Topcoat components and layouts of auth's server-rendered pages, rendering plain data and taking URLs as props, the admin dashboard's included, and the shared stylesheet, `assets/style.css` |
| `crates/telemetry` | `piquel-telemetry`: stderr logs, and OpenTelemetry traces, metrics and logs over OTLP; request spans and access logs for axum routers, client spans, and typed metric instruments; see [telemetry.md](telemetry.md) |
| `packages/auth` | `@piquel/auth`, the TypeScript SDK, not yet published: its `.` entry point (discovery, token validation, typed scopes, challenges, the JWKS cache and the login client), `./server` (server-side login over `Request` and `Response`) and `./browser` (a public client, with passkey sign-in on the app's page), with no runtime dependencies; `src/protocol.ts` is generated from `piquel_common::protocol` |
| `tests/sdk-vectors` | Generated cases every SDK must pass; see [sdk.md](sdk.md) |

Prettier and type-aware ESLint cover all web code from the root configuration, as
rustfmt and Clippy cover Rust; `just fmt`, `just lint` and `just check` run both.
`tsc` checks the passkey script's JSDoc types as strictly as TypeScript's. The
TypeScript SDK is the one package that builds JavaScript, with `tsc`, and is the
pnpm workspace's only member besides the root; auth's executable builds none.

Only `crates/database` runs SQL. `piquel-common` has an optional `sqlx` feature,
enabled only by the database crate, that lets its IDs and vocabularies decode from
columns. Its other server-only parts sit behind the `admin`, `config`, `email` and
`events` features, so the Rust SDK compiles only IDs and wire types. Auth-service
owns authentication policy; frontends never receive database credentials or
provider secrets. Shared types
go in `piquel-common`; add new crates only for independently auditable primitives,
or, as `piquel-ui`, to compile slow view code beside the database crate instead of
after it.

The auth runtime is one executable with one public HTTP listener, plus the admin
dashboard's listener when it is configured, which only a private route reaches.
The executable embeds the shared stylesheet and the passkey script. Auth renders every
page itself, sign-in included, and the account settings at `/settings`; piquel.fr
only redirects there. The permanent WebAuthn RP ID is the auth hostname, never a wildcard over
piquel.fr subdomains.

Auth's pages live in `apps/auth-service/src/web`, grouped by area: `auth`, the
sign-in flows on auth.piquel.fr (signing in and up, consent, logout, the
recovery pages and the admin dashboard's handoff), `settings`, `developers`, and
`admin`, the admin dashboard on admin.piquel.fr, whose views are in
`crates/ui/src/admin`. `src/admin` is not a page module: it holds
`AdminService` and the operator rules that the dashboard and the CLI share.

The auth binary also runs explicit migrations, generates invitations and grants
administrators. PostgreSQL
stores sessions, WebAuthn challenges, OAuth state, pending social identities,
invitations, consent, refresh tokens, rate limits and security events.
Auth needs no separate cache, RPC service, event bus or key-management service.
The admin dashboard calls `AdminService` in-process, as the CLI does, and signs
administrators in by a handoff from auth's own session. External applications
consume standard OIDC; operators register their clients in the database with
`auth-service client`.

[surfaces.md](surfaces.md) sets out what auth.piquel.fr, piquel.fr and
admin.piquel.fr each serve. Build/configuration and testing instructions are in
the root README; every task runs through `just`. Deployment uses piqueld (`infra/README.md`). The Rust SDK for
applications follows [sdk.md](sdk.md). Public application registration is outside
this release.
