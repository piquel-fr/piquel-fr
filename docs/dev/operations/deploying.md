# Deploying with piqueld

`infra/piqueld.toml` deploys piquel.fr as one repository-backed piqueld
application, `piquel-fr`: auth, which also serves the account settings and the
admin dashboard, piquel.fr's web server, the documentation, and PostgreSQL. Its environments and previews share the
manifest; variables give each its own hostnames. A second application,
`telemetry` (`infra/telemetry.toml`), stores and shows their traces, metrics and
logs; see [the telemetry stack](telemetry.md).

| Deployment | Source | Web, redirects to auth | Auth | Admin | Docs | www, redirects to web | Reachable from |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `production` | promoted from staging | `piquel.fr` | `auth.piquel.fr` | `admin.piquel.fr` | `docs.piquel.fr` | `www.piquel.fr` | internet; admin from the tailnet |
| `staging` | `main`, on every push | `staging.piquel.fr` | `auth.staging.piquel.fr` | `admin.staging.piquel.fr` | `docs.staging.piquel.fr` | `www.staging.piquel.fr` | tailnet |
| previews | a branch or a local worktree | `<slug>.dev.piquel.fr` | `auth-<slug>.dev.piquel.fr` | `admin-<slug>.dev.piquel.fr` | `docs-<slug>.dev.piquel.fr` | `www-<slug>.dev.piquel.fr` | tailnet |

The gateway answers both redirects itself, keeping the path and query. `web` is
temporary (307), so browsers cache nothing once piquel.fr serves pages of its own
again: `piquel.fr/settings/emails?x=1` goes to
`auth.piquel.fr/settings/emails?x=1` (see [piquel.fr](#piquelfr)). `www` is permanent (308)
and goes to the web host: `www.piquel.fr/settings?x=1` goes to
`piquel.fr/settings?x=1`. piqueld renders every route in every environment, so
staging and previews get both too; their names fall under the existing wildcard
records and certificates.

Production never builds. It only receives releases that staging built and ran:
the same images, never rebuilt. Promotion is refused unless staging's current
deployment succeeded and every service runs healthy. Build inputs therefore
contain nothing environment-specific: per-environment values are runtime
`environment` entries.

## Daemon requirements

- piqueld with in-container HTTP probes, local previews and manifest-declared
  environments.
- Managed ingress with the private apps node, and a DNS provider for
  `piquel.fr`: private routes get DNS-01 certificates (`*.dev.piquel.fr` covers
  every preview).
- DNS records for every hostname: `manage_records = true` on that provider, or by
  hand: public hosts (`piquel.fr`, `auth.piquel.fr`, `docs.piquel.fr`, `www.piquel.fr`) to the
  server, and `admin.piquel.fr`, `staging.piquel.fr`, `*.staging.piquel.fr` and
  `*.dev.piquel.fr` and `grafana.piquel.fr` to the apps node's tailnet addresses. Through the Cloudflare Tunnel, a public
  host is a proxied CNAME to the tunnel; on ports 80/443, an A record, and Caddy
  obtains its certificate over HTTP-01.
- `ingress.webhook_hostname` for deploy-on-push.
- `reconciliation.prepare_timeout_seconds = 1200` for cold Rust builds.

## Setup

The manifest declares both environments and where each deploys from: staging
follows pushes to `main` (`sync = true`), production is `promote_from =
"staging"`. Saving it creates them, or converts an existing application's, and
every later save or push to `main` keeps them in line; edit the manifest rather
than running `piquelctl env create`, `env source` or `env sync`.

Once, after this manifest is on `main`:

```sh
piquelctl --timeout 30m app apply --file infra/piqueld.toml --deploy --yes   # deploys staging
piquelctl app repository webhook rotate piquel-fr   # prints the secret once
piquelctl app repository webhook show piquel-fr     # prints the payload URL
```

Add a GitHub webhook to this repository with that URL and secret,
`application/json`, and the `push` event. Staging follows `main` from then on;
production waits for its first promotion.

## Releasing

```sh
piquelctl env promote piquel-fr production --plan   # review the release and changes
piquelctl env promote piquel-fr production --yes
```

`--deployment ID` refuses to promote anything but the staging deployment you
tested. `piquelctl app releases piquel-fr` lists earlier releases; `env promote
--release ID` rolls back to one.

## Previews

`just preview` deploys the current worktree, uncommitted files included, and
prints its URLs. `just preview-delete` removes it with its database. Pushed
branches can also be previewed with `piquelctl preview create piquel-fr --branch
NAME`, and redeploy on push. `.agents/skills/preview` and
`.agents/skills/test-change` describe the workflow for agents. Agents need a
token with `previews:deploy` and `previews:delete` on `piquel-fr`, which cannot
touch staging or production.

Preview databases start empty and registration needs no invitation. The
daemon's `[previews]` limits bound their CPU, memory and replicas.

## Database

Each environment and preview has its own PostgreSQL 18 volume. Auth connects
over TCP to `postgres:5432` on the application's private network, which ingress
and other environments cannot reach, so the URL opts into plaintext with
`sslmode=disable`; connections require SCRAM password authentication.

Auth connects as `piquel_auth`, a role with only row access to the app tables
(see [roles](../architecture/database.md#roles)). Only PostgreSQL itself and the
`migrate` job get the superuser `piquel`'s password. It applies migrations before every rollout, once
PostgreSQL is healthy, then creates `piquel_auth` or resets its privileges and
password. Environment volumes survive deletion. PostgreSQL major upgrades require
an explicit data migration.

## Secrets

piqueld generates `database-password`, `database-runtime-password`,
`key-encryption-key`, `token-digest-key` and `signing-key`
for each environment and preview on the first deployment that uses them, and
never changes them; `piquelctl env secret piquel-fr --env ENV regenerate NAME`
rotates one. A new `database-password` does not change the one an existing
database volume stores. A new `database-runtime-password` takes effect on
the next deploy, whose `migrate` job sets it before the rollout. From then until
the new auth replicas are healthy, the old ones keep their open connections but
cannot open new ones. If that deploy fails after `migrate`, auth goes down as its
pool's connections expire (within 30 minutes), so rotate it during a deploy you
watch, and fix forward if it fails: a retry reuses the same secret.

`key-encryption-key` (`AUTH_KEY_ENCRYPTION_KEY`) and `token-digest-key` are 32
random bytes as unpadded base64url text. Never regenerate `key-encryption-key`:
the signing keys sealed with it would no longer open. Change the token digest
key only as [changing the token digest key](signing-keys.md#changing-the-token-digest-key)
describes, or every refresh token ends. Signing keys are not secrets of the
manifest: auth keeps them in its database and rotates them on its own (see
[signing keys](signing-keys.md), which also has the runbook for a compromised
key):

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service keys list
```

## Running auth-service commands

Every [administration](administration.md) command runs in an auth container,
through `piquelctl app exec`. Staging and production require invitations:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service invite create
```

OIDC clients are registered and changed the same way, with the `client` command
(see [OIDC clients](clients.md)); a change applies at once, without a
deploy:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service client list
```

An environment needs no OIDC client: the dashboard signs administrators in
itself (see [the admin dashboard](administration.md#the-admin-dashboard)).

## Documentation

The `docs` service serves the documentation book, built by
`infra/docs.Dockerfile` from the deployment's own commit: production at
`docs.piquel.fr`, staging at `docs.staging.piquel.fr`, and each preview at
`docs-<slug>.dev.piquel.fr`. Production's book therefore always describes the
release production runs, and a preview's shows a branch's documentation as it
would be published. The book is static files, served by
[static-web-server](https://static-web-server.net), with mdBook's page for any
missing one.

## Client addresses

Auth uses
the gateway ranges in `PIQUELD_INGRESS_PROXIES` to trust ingress's overwritten
`X-Forwarded-For` address and throttle each client separately.
`AUTH_TRUSTED_PROXIES` overrides those ranges when set.

## Caching

Auth decides every response's `Cache-Control` itself; the edge needs no rule.
Handlers mark a response cacheable with `Cached` (`apps/auth-service/src/security`),
and anything else, including any error and any response that sets a cookie, is
`no-store`. Every value also carries `no-transform`, so Cloudflare never rewrites
a body: its Email Address Obfuscation would replace addresses with a link to a
decoding script the pages' Content-Security-Policy blocks.

| Class | `Cache-Control` | Responses |
| --- | --- | --- |
| `NoStore` | `no-store, no-transform` | APIs, OAuth, server-rendered pages, errors, everything not below |
| `Immutable` | `public, max-age=31536000, immutable, no-transform` | the pages' content-hashed stylesheet and script, under `/assets/`, and profile pictures, under `/pictures/`, named by their upload |
| `Public` | `public, max-age=N, no-transform` | discovery and JWKS, for an hour |

Every page is server-rendered and `no-store`, so a deploy never leaves a cached page
pointing at a stylesheet or script the new binary no longer serves. The Cloudflare Tunnel
caches the immutable files, as it does any static file type the origin lets it
store. Profile pictures have no file extension, so it keeps none of them: a
removed picture stops being served at once. `Public` responses are the same for everyone, with
`Access-Control-Allow-Origin: *` and no credentials, as profile pictures have;
the stylesheet and script carry no CORS headers. Staging and previews are private routes and bypass
Cloudflare.

## Running several replicas

`auth_replicas` sets how many auth replicas run (default 1). Two already overlap
on every deploy: auth mounts no volume, so piqueld starts the new replica before
stopping the old one, after the `migrate` job. On one node, a second replica
removes the restart gap after a crash; it adds no capacity.

- **Shared state.** Sessions, ceremonies, federation state, rate-limit budgets and
  refresh-token rotation live in PostgreSQL. Database tests build two instances
  on one database to check that sign-in, logout, budgets and refresh rotation
  span them.
- **Configuration.** Replicas must run with the same `AUTH_*` settings. The
  manifest gives every replica the same `key-encryption-key`, which opens the
  signing keys in the database, and the same token digest keys, from which
  refresh-token digests and email and recovery links derive. Audit checkpoints are signed
  with a separate key (`AUTH_AUDIT_KEY_PROVIDER`): the stored
  `audit-key-production` and `audit-key-staging` secrets, or a preview's
  generated `audit-key`.
- **Per-replica state.** Only signing keys are cached per replica: Google's,
  and auth's own key set, which every replica reloads each minute. OIDC
  clients, and the public-client origins CORS allows, are read from the
  database on each request, so a client change reaches every replica at once.
- **Background work.** Jobs run through one runner
  (`apps/auth-service/src/jobs/mod.rs`). An exclusive job, such as expired-state
  cleanup or the purge of deleted accounts, each every five minutes, or audit
  sealing every five seconds, holds a PostgreSQL advisory lock while it runs, so
  one replica at a time runs it and the others skip that run. A run that fails
  or panics is logged and retried at the next interval. On shutdown, once
  in-flight requests drain, running jobs get 10 seconds to finish (cleanup stops
  after its current batch), then are cancelled, which closes their connection and
  releases the lock. Signing key rotation runs on every replica each minute, in
  a transaction that takes a transaction-level advisory lock if it is free, so
  one replica at a time advances it; the `keys` commands wait for the same lock.
- **Migrations.** During a deploy the previous release runs against the new
  schema, so migrations expand, then contract
  ([database](../architecture/database.md)).

## piquel.fr

piquel.fr is its own service, `web` (`apps/web`, built by `infra/web.Dockerfile`),
which the `web` route reaches. It serves the homepage at `/`, the privacy policy at
`/privacy` and the terms of service at `/terms`, which Google's OAuth branding
links, and auth's pages link the policies there (`AUTH_WEB_ORIGIN`). It keeps no
state, so it has no database or secret, and any number of replicas can serve it.

Every other path redirects, temporarily (`307`) and with its query, to the same
one on auth, so links to piquel.fr's settings paths (`/settings`,
`/settings/emails`, `/settings/emails/verify`, `/settings/sessions` and
`/settings/history`) open auth's page, and browsers keep a verification link's
fragment (`/settings/emails/verify#token=…`). Notice emails link to
`/settings/history` and never expire: keep the redirect, and those paths on
auth, for as long as piquel.fr serves nothing at them. A path ending in a slash
redirects to the page.

Cloudflare's edge also sets piquel.fr's `Strict-Transport-Security`, with the
values piquel-web sends: `max-age=31536000`, without `includeSubDomains` or
`preload`.
