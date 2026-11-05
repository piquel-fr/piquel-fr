# Monorepo boundaries

This repository contains piquel.fr and its services. The current implemented scope
is authentication, with its account settings, and the admin dashboard.

| Location | Responsibility |
| --- | --- |
| `apps/auth-service` | Rust auth authority, browser ceremonies, social adapters, OIDC, server-rendered pages, the settings API, the admin dashboard at admin.piquel.fr, CLI |
| `apps/web` | `piquel-web`, piquel.fr's own web server: the homepage and Piquel's policies (`assets/policies/`), and a redirect of every other path to auth. It relies on auth only to sign people in |
| `packages/auth` | `@piquel/auth`, the TypeScript SDK, not yet published: its `.` entry point (discovery, token validation, typed scopes, challenges, the JWKS cache and the login client), `./server` (server-side login over `Request` and `Response`) and `./browser` (a public client, with passkey sign-in on the app's page), with no runtime dependencies; `src/protocol.ts` is generated from `piquel_common::protocol` |
| `tests/sdk-vectors` | Generated cases every SDK must pass; see [sdk.md](sdk.md) |

The crates under `crates/` (`piquel-common`, `piquel-crypto`, `piquel-auth`, the
Rust SDK, `piquel-repository`, `piquel-telemetry` and `piquel-ui`) are described
in [rust-conventions.md](rust-conventions.md#crates).

Prettier and type-aware ESLint cover all web code from the root configuration, as
rustfmt and Clippy cover Rust; `just fmt`, `just lint` and `just check` run both.
The pages load no JavaScript of their own. The TypeScript SDK is the one package that builds JavaScript, with `tsc`, and is the
pnpm workspace's only member besides the root; auth's executable builds none.

Only `crates/database` runs SQL. `piquel-common` has an optional `sqlx` feature,
enabled only by the database crate, that lets its IDs and vocabularies decode from
columns. Its server-only parts sit behind the `admin`, `config`, `email` and
`events` features, so the Rust SDK compiles none of them. Auth-service
owns authentication policy; frontends never receive database credentials or
provider secrets. Shared types
go in `piquel-common`; add new crates only for independently auditable primitives,
or, as `piquel-ui`, to compile slow view code beside the database crate instead of
after it.

The auth runtime is one executable with one public HTTP listener, plus the admin
dashboard's listener when it is configured, which only a private route reaches.
The executable embeds the shared stylesheet, Topcoat's runtime and the expressions
module it builds from the pages' components. Auth renders every
page itself, sign-in included, and the account settings at `/settings`; piquel.fr's
server redirects there every path it doesn't serve. The permanent WebAuthn RP ID is the auth hostname, never a wildcard over
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
consume standard OIDC. Any account registers its own clients in the developer
console, at `/developers`, and operators manage clients with
`auth-service client`.

[surfaces.md](surfaces.md) sets out what auth.piquel.fr, piquel.fr and
admin.piquel.fr each serve. Build/configuration and testing instructions are in
the root README; every task runs through `just`. Deployment uses piqueld (`infra/README.md`). The Rust SDK for
applications follows [sdk.md](sdk.md).
