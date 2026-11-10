# Overview

This page is the map of SourceOrigin: the processes that run it, what each crate
owns, and which page to read next. Start here before changing anything that
crosses a crate or a process.

## Processes

```text
 browsers ──HTTPS──┐               apps ──OIDC over HTTPS──┐
                   ▼                                       ▼
 ┌──────────────────────── piqueld gateway ─────────────────────────┐
 │ sourceorigin.dev    auth.sourceorigin.dev    admin.sourceorigin.dev*    docs.sourceorigin.dev│
 └─────┬───────────────┬─────────────────┬───────────────────┬──────┘
       ▼               ▼                 ▼                   ▼
   sourceorigin-web     auth-service:     auth-service:          docs
                  public listener   admin listener
                          └────────┬───────┘
                                   ├──▶ PostgreSQL
                                   ├──▶ apps' back-channel logout URIs
                                   └──▶ SMTP relay

 auth-service, sourceorigin-web ──OTLP──▶ collector ──▶ Prometheus, Tempo, Loki ──▶ Grafana

 * a private route: reachable on the tailnet only
```

- **`auth-service`** (`apps/auth-service`) is one executable. `serve` runs a public
  listener (`AUTH_PUBLIC_LISTENER`) for auth.sourceorigin.dev and, when the dashboard is
  configured, an admin listener (`AUTH_ADMIN_LISTENER`) for admin.sourceorigin.dev, which
  only a private route reaches. Each listener has its own router and security
  layer (`AuthConfig::router` and `AuthConfig::admin_router` in `src/lib.rs`).
  Both stop together: when one ends, `Command::listen` in `src/cli/serve.rs` stops
  the other, then background jobs get a grace period to finish. The same
  executable is the operator CLI: migrations, invitations, administrators, keys
  and every admin operation.
- **`sourceorigin-web`** (`apps/web`) is sourceorigin.dev's own server: the homepage and
  SourceOrigin's policies, and a redirect of every other path to auth. It relies on
  auth only to sign people in, and never shares its database, keys or process.
- **PostgreSQL** holds all of auth's state. Auth needs no separate cache, RPC
  service, event bus or key-management service, so it runs as several replicas
  ([running several replicas](../operations/replicas.md)).
- **piqueld** deploys everything from `infra/piqueld.toml`. Its gateway
  terminates HTTPS, answers the `www` redirect itself, and overwrites
  `X-Forwarded-For`, which auth trusts only from the gateway's ranges
  ([deploying](../operations/deploying.md)).
- **The telemetry stack** (`infra/telemetry.toml`) receives OTLP from auth and
  sourceorigin-web and stores traces, metrics and logs
  ([telemetry](telemetry.md), [telemetry stack](../operations/telemetry.md)).
- **Apps** sign in through standard OIDC, with any OIDC library or the SDKs
  ([SDK design](sdk.md)). Auth calls them back only through the
  [delivery queue](delivery-queue.md): back-channel logout tokens, and email to
  account holders through an SMTP relay.

Auth renders every page itself, sign-in included, and the account settings at
`/settings`; sourceorigin.dev redirects there every path it doesn't serve.
[Surfaces](surfaces.md) sets out what each host serves.

## Repository

| Location | Responsibility |
| --- | --- |
| `apps/auth-service` | The auth authority: browser ceremonies, social sign-in, OIDC, the server-rendered pages, the settings API, the admin dashboard and the CLI. `assets/passkey.js` runs the WebAuthn ceremonies and the form hooks that start them, and `assets/picture.js` lets the picture form choose its crop |
| `apps/web` | `sourceorigin-web`, sourceorigin.dev's own web server, with SourceOrigin's policies in `assets/policies/` |
| `packages/auth` | `@sourceorigin/auth`, the TypeScript SDK, not yet published: its `.` entry point (discovery, token validation, typed scopes, challenges, the JWKS cache and the login client), `./server` (server-side login over `Request` and `Response`) and `./browser` (a public client, with passkey sign-in on the app's page). It has no runtime dependencies, and `src/protocol.ts` is generated from `sourceorigin_common::protocol` |
| `tests/sdk-vectors` | Generated cases every SDK must pass; see [SDK design](sdk.md#test-vectors) |
| `tests/browser` | Playwright tests, and the documentation's screenshots |
| `infra/` | Dockerfiles and the piqueld manifests |

Inside auth-service, each HTTP feature is a module whose `XApplication` serves
its routes, and `src/routes.rs` declares every path. Pages live in `src/web`, grouped by area:
`auth`, the sign-in flows on auth.sourceorigin.dev (signing in and up, consent, logout,
the recovery pages and the admin dashboard's handoff), `settings`, `developers`,
and `admin`, the admin dashboard, whose views are in `crates/ui/src/admin`.
`src/admin` is not a page module: it holds `AdminService` and the operator rules
that the dashboard and the CLI share. [Rust conventions](../rust-conventions.md)
explains how applications, routes and services fit together.

## Crates

| Crate | Owns |
| --- | --- |
| `sourceorigin-common` (`crates/common`) | Shared types: IDs, handles, vocabularies, domain events, notifications, and under `protocol` the wire types auth and the SDKs share. Its server-only parts sit behind the `admin`, `config`, `email`, `events` and `similarity` features, so the Rust SDK compiles none of them |
| `sourceorigin-crypto` (`crates/crypto`) | Every cryptographic primitive: secrets, digests, HMAC, PKCE, RS256 signing and key sets, AES-256-GCM sealing, Ed25519 signed notes and SCRAM verifiers |
| `sourceorigin-repository` (`crates/database`) | The only crate that runs SQL: connections, migrations, repositories, transactions, events and the delivery queue's storage |
| `sourceorigin-telemetry` (`crates/telemetry`) | Logs, traces and metrics, and the HTTP layer every router uses |
| `sourceorigin-ui` (`crates/ui`) | The Topcoat components of auth's pages and the admin dashboard, and the bodies of its emails, which know nothing of the database or HTTP |
| `sourceorigin-auth` (`crates/auth-sdk`) | The Rust SDK, which depends only on `sourceorigin-common` |

[Rust conventions](../rust-conventions.md#crates) describes each crate in full.
Shared types go in `sourceorigin-common`. Add a crate only for an independently
auditable primitive, or, as `sourceorigin-ui`, to compile slow view code beside the
database crate instead of after it.

`sourceorigin-common`'s optional `sqlx` feature, enabled only by the database crate,
lets its IDs and vocabularies decode from columns. Auth-service owns
authentication policy: frontends never receive database credentials or provider
secrets. The permanent WebAuthn RP ID is the auth hostname, never a wildcard over
sourceorigin.dev subdomains.

## Tooling

Every task runs through `just`: see [getting started](../getting-started.md) and
[testing](../testing.md). Prettier and type-aware ESLint cover all web code from
the root configuration, as rustfmt and Clippy cover Rust; `just fmt`, `just lint`
and `just check` run both. `tsc` checks the pages' scripts' JSDoc types as
strictly as TypeScript's. The TypeScript SDK is the one package that builds
JavaScript, and the pnpm workspace's only member besides the root; auth's
executable embeds its stylesheet and scripts and builds none.

## Read next

1. [Request lifecycle](request-lifecycle.md): what happens to a request in auth,
   from the listener to the response.
2. [Sessions](sessions.md): browser sessions, their confirmation and their end.
3. [Authorization flow](oidc.md): OIDC inside auth.
4. [Keys](keys.md): signing keys, token digest keys and the audit key.
5. [Surfaces](surfaces.md), [PostgreSQL boundary](database.md) and the
   [delivery queue](delivery-queue.md), then the feature pages:
   [notifications](notifications.md), [email addresses](email.md) and
   [account deletion](account-deletion.md).
6. [Telemetry](telemetry.md) and [SDK design](sdk.md).
