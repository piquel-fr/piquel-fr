# Piqueld deployments

`infra/piqueld.toml` deploys piquel.fr as one repository-backed piqueld
application, `piquel-fr`: auth, which also serves the account settings and the
admin dashboard, and PostgreSQL. Its environments and previews share the
manifest; variables give each its own hostnames. A second application,
`telemetry` (`infra/telemetry.toml`), stores and shows their traces, metrics and
logs; see [Telemetry](#telemetry).

| Deployment | Source | Web, redirects to auth | Auth | Admin | www, redirects to web | Reachable from |
| --- | --- | --- | --- | --- | --- | --- |
| `production` | promoted from staging | `piquel.fr` | `auth.piquel.fr` | `admin.piquel.fr` | `www.piquel.fr` | internet; admin from the tailnet |
| `staging` | `main`, on every push | `staging.piquel.fr` | `auth.staging.piquel.fr` | `admin.staging.piquel.fr` | `www.staging.piquel.fr` | tailnet |
| previews | a branch or a local worktree | `<slug>.dev.piquel.fr` | `auth-<slug>.dev.piquel.fr` | `admin-<slug>.dev.piquel.fr` | `www-<slug>.dev.piquel.fr` | tailnet |

The gateway answers both redirects itself, keeping the path and query. `web` is
temporary (307), so browsers cache nothing once piquel.fr serves pages of its own
again: `piquel.fr/settings/emails?x=1` goes to
`auth.piquel.fr/settings/emails?x=1` (see [Web](#web)). `www` is permanent (308)
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
  environments (`main` after #233).
- Managed ingress with the private apps node, and a DNS provider for
  `piquel.fr`: private routes get DNS-01 certificates (`*.dev.piquel.fr` covers
  every preview).
- DNS records for every hostname: `manage_records = true` on that provider, or by
  hand: public hosts (`piquel.fr`, `auth.piquel.fr`, `www.piquel.fr`) to the
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
(see `docs/architecture/database-crate.md`). Only PostgreSQL itself and the
`migrate` job get the superuser `piquel`'s password. It applies migrations before every rollout, once
PostgreSQL is healthy, then creates `piquel_auth` or resets its privileges and
password. Environment volumes survive deletion. PostgreSQL major upgrades require
an explicit data migration.

## Auth

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
key only as "Changing the token digest key" in the root README describes, or
every refresh token ends. Signing keys are not secrets of the manifest:
auth keeps them in its database and rotates them on its own (see "Signing keys"
in the root README, which also has the runbook for a compromised key):

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service keys list
```

### Moving signing keys to the database

Auth used to sign with the `signing-key` PEM secret alone, and derived the
digests of refresh tokens, codes and pending logins, passkey decoys and email
verification links from it. The move to the database (#48) keeps everything issued before it valid,
through rolling deploys and rollbacks:

1. The first release reading keys from the database runs the
   `signing-key-import` job before it serves: it imports `signing-key` as the
   active key `primary`, the ID its tokens name. Later deploys import nothing.
   `signing-key` stays the token digest key (`AUTH_TOKEN_DIGEST_KEY`), so the
   previous release checks every digest this one makes, and
   `token-digest-key` is already accepted (`AUTH_TOKEN_DIGEST_KEY_ACCEPTED`).
2. In a later deploy, swap the two: `AUTH_TOKEN_DIGEST_KEY` points at
   `token-digest-key`, and `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` at `signing-key`.
   Passkey decoys change once then, and so does the email verification key:
   links already sent keep working, but one still queued then does not, and its
   owner sends another. From this deploy on, a rollback lands on a
   release that reads signing keys from the database.
3. Only then rotate once by hand to see rotation work: `auth-service keys
   rotate`, then a day later `keys list` shows the new key active and `primary`
   retiring. Rotating earlier would let a rollback to the release before step 1
   reject every token the new key signs; the schedule itself waits 90 days.
4. Once `auth-service keys digest-usage` lists only `current` keys, about 30
   days after step 2, remove `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`, the
   `signing-key-import` job, and the `signing-key` mount and secret together.

Staging and production require invitations:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service invite create
```

OIDC clients are registered and changed the same way, with the `client` command
(see "OIDC clients" in the root README); a change applies at once, without a
deploy:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service client list
```

No external identity providers are configured by default, and an environment
needs no client: the dashboard signs administrators in itself (see
[Admin](#admin)). Auth uses
the gateway ranges in `PIQUELD_INGRESS_PROXIES` to trust ingress's overwritten
`X-Forwarded-For` address and throttle each client separately.
`AUTH_TRUSTED_PROXIES` overrides those ranges when set.

### Caching

Auth decides every response's `Cache-Control` itself; the edge needs no rule.
Handlers mark a response cacheable with `Cached` (`apps/auth-service/src/security`),
and anything else, including any error and any response that sets a cookie, is
`no-store`. Every value also carries `no-transform`, so Cloudflare never rewrites
a body: its Email Address Obfuscation would replace addresses with a link to a
decoding script the pages' Content-Security-Policy blocks.

| Class | `Cache-Control` | Responses |
| --- | --- | --- |
| `NoStore` | `no-store, no-transform` | APIs, OAuth, server-rendered pages, errors, everything not below |
| `Immutable` | `public, max-age=31536000, immutable, no-transform` | the pages' content-hashed stylesheet and script, under `/assets/` |
| `Public` | `public, max-age=N, no-transform` | discovery and JWKS, for an hour |

Every page is server-rendered and `no-store`, so a deploy never leaves a cached page
pointing at a stylesheet or script the new binary no longer serves. The Cloudflare Tunnel
caches the immutable files, as it does any static file type the origin lets it
store. `Public` responses are the same for everyone, with
`Access-Control-Allow-Origin: *` and no credentials; the immutable files carry
no CORS headers. Staging and previews are private routes and bypass
Cloudflare.

### Running several replicas

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
  refresh-token digests and passkey decoys derive.
- **Per-replica state.** Only signing keys are cached per replica: Google's,
  and auth's own key set, which every replica reloads each minute. OIDC
  clients, and the public-client origins CORS allows, are read from the
  database on each request, so a client change reaches every replica at once.
- **Background work.** Jobs run through one runner
  (`apps/auth-service/src/jobs.rs`). An exclusive job, such as expired-state
  cleanup or the purge of deleted accounts, each every five minutes, holds a
  PostgreSQL advisory lock while it runs, so
  one replica at a time runs it and the others skip that run. A run that fails
  or panics is logged and retried at the next interval. On shutdown, once
  in-flight requests drain, running jobs get 10 seconds to finish (cleanup stops
  after its current batch), then are cancelled, which closes their connection and
  releases the lock. Signing key rotation runs on every replica each minute, in
  a transaction that takes a transaction-level advisory lock if it is free, so
  one replica at a time advances it; the `keys` commands wait for the same lock.
- **Migrations.** During a deploy the previous release runs against the new
  schema, so migrations expand, then contract
  (`docs/architecture/database-crate.md`).

## Email

Auth sends through [Resend](https://resend.com)'s SMTP relay in every
environment, over implicit TLS (`smtps://resend@smtp.resend.com:465`), so a
preview sends exactly like production. Environments differ only in their sender
and key, set by the `email_from` and `smtp_secret` variables:

| Environment | Sender | Stored secret |
| --- | --- | --- |
| production | `security@piquel.fr` | `resend-production` |
| staging, previews | `security@dev.piquel.fr` | `resend-dev` |

Each key is a Resend API key with sending access only, restricted to its domain,
so a key leaked from a preview cannot send as `piquel.fr`, and test mail never
spends production's sender reputation. piqueld does not generate these secrets:
set them by hand, before the first deployment that mounts them, which fails
without them:

```sh
piquelctl app secret piquel-fr set resend-production --stdin --environments production --no-previews
piquelctl app secret piquel-fr set resend-dev --stdin --environments staging --previews
```

Run the same command again to rotate a key; the next deployment mounts the new
one. Resend does not sign in through Piquel, so a broken auth can still email
people.

To follow a message end to end from a preview, add an address at a Resend
receiving domain (`*.resend.app`, or ours with an MX record) to an account: the
message arrives in Resend's dashboard, where its link can be opened as a user
would. `delivered@resend.dev`, `bounced@resend.dev` and `complained@resend.dev`
produce those outcomes on purpose.

Both sending domains need three DNS records, which Resend lists for each, or
providers file the mail as spam:

- **SPF**: a TXT record on the domain listing the provider, e.g.
  `v=spf1 include:<provider's SPF domain> -all`. Keep a single SPF record: merge
  the provider's `include:` into an existing one.
- **DKIM**: the TXT or CNAME records the provider gives for its selector, e.g.
  `<selector>._domainkey.piquel.fr`, so it signs the mail for `piquel.fr`.
- **DMARC**: a TXT record at `_dmarc.piquel.fr`, starting with
  `v=DMARC1; p=quarantine; rua=mailto:<reports address>` and moving to
  `p=reject` once the reports show only aligned mail. SPF and DKIM must align with
  the `From` domain.

`auth-service deliveries list --channel email --status failed` lists what did
not go out; a delivery's error is the SMTP reply code, never its text. A rejected
password (`535`) is retried for 24 hours, so mail queued while the Resend key
was wrong goes out once auth runs with the fixed secret.

## Admin

Auth serves the admin dashboard on its admin listener, port 8081, for the
environment's admin host (`AUTH_ADMIN_ORIGIN`). Only the private `admin` route
reaches that port, in every environment; auth's health check stays on 8080. The
dashboard signs administrators in by a handoff from auth's own passkey session,
so it needs no OIDC client or secret. The `piquel-admin` client that the dashboard
used to be is deleted by migration `0020`, and the `admin-client-secret` piqueld
generated is no longer used: delete it with `piquelctl env secret piquel-fr --env
ENV delete admin-client-secret` once the release is out.

Only administrators can use it. Grant the first one with the CLI:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service admin grant USERNAME
```

An administrator's dashboard session lasts while their auth session does, and
survives restarts and replicas: it is stored, as a digest, in PostgreSQL.

## Web

piquel.fr runs no service. Auth serves the account settings at the paths
piquel.fr used (`/settings`, `/settings/emails`, `/settings/emails/verify`,
`/settings/sessions` and `/settings/history`), and answers `/` with a redirect to
`/settings`. The `web` route sends every path to auth, so links sent before the
move still open the same page, and browsers keep a verification link's fragment
(`/settings/emails/verify#token=…`). Notice emails link to `/settings/history`
and never expire: keep the redirect, and those paths on auth, for as long as
piquel.fr serves nothing at them. A path ending in a slash, which piquel.fr's
settings also accepted, redirects to the page.

A redirect route sends no headers of its own, so piquel.fr's
`Strict-Transport-Security` is set at Cloudflare's edge, with the values piquel-web
sent: `max-age=31536000`, without `includeSubDomains` or `preload`.

## Telemetry

`infra/telemetry.toml` is the `telemetry` application, with one environment,
`production`, that follows `main`:

| Service | Image | Role |
| --- | --- | --- |
| `collector` | `otel/opentelemetry-collector-contrib` | OTLP/HTTP on port 4318; memory limit, batching, and deletion of query strings, headers and client addresses |
| `prometheus` | `prom/prometheus` | Metrics, received over OTLP, kept 30 days |
| `tempo` | `grafana/tempo` | Traces, kept 14 days |
| `loki` | `grafana/loki` | Logs, received over OTLP, kept 30 days |
| `grafana` | `grafana/grafana` | Dashboards at `grafana.piquel.fr` |

Their configuration is in `infra/telemetry/`, mounted as piqueld files. Grafana
provisions the three data sources, linked so a log line opens its trace and a
trace its logs, and two dashboards in the `piquel.fr` folder:

- **Auth overview**: traffic, errors and latency by route, sign-ins,
  registrations, tokens, refresh revocations, throttling, events by kind, the
  database pool, cleanup, logs and traces.
- **Admin activity**: what administrators and operators did, to notice a stolen
  administrator session or a compromised server. Its first row counts, over the
  chosen range, administrator rights changed, dashboard requests refused for a
  sign-in or rights the dashboard's own pages never lack, changes refused because
  they targeted an administrator, command-line changes, disabled accounts and
  viewed accounts. Below are their timelines, the dashboard's traffic, actions by
  administrator, and
  the matching log lines and traces. Its counts come from the event and failure
  log lines, so they are exact.

To look up a failed request, paste the `X-Trace-Id` of its response, or the
trace ID the admin dashboard shows for an event, into Explore > Tempo.

Grafana's route is private, and it never signs in through auth: it is needed
most when auth is down (see "Recovering auth" in
`docs/architecture/surfaces.md`). Sign in as `admin` with the password piqueld
generated:

```sh
piquelctl app exec telemetry grafana -- cat /run/secrets/grafana-admin-password
```

Grafana stores that password on its first start, so regenerating the secret
changes nothing; change it in Grafana instead.

piquel-fr imports the collector (`[[spec.imports]]` in `infra/piqueld.toml`),
so its staging and production reach it as `collector.telemetry`. Their auth
service sets:

| Variable | Value |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://collector.telemetry:4318`, from the `otlp_endpoint` variable; empty in previews, which keep telemetry on stderr |
| `OTEL_RESOURCE_ATTRIBUTES` | `deployment.environment.name=${{ env.name }}`, so dashboards tell staging and production apart |

Every other `OTEL_*` variable keeps its default; see
`docs/architecture/telemetry.md`. Telemetry never blocks a deploy: until the
collector is deployed and linked, export fails, the SDK logs a warning on
stderr, and the services serve normally.

Once, after `infra/telemetry.toml` is on `main`:

```sh
piquelctl --timeout 30m app apply --file infra/telemetry.toml --deploy --yes
piquelctl app repository webhook rotate telemetry   # prints the secret once
piquelctl app repository webhook show telemetry     # prints the payload URL
```

Add that webhook to this repository as for piquel-fr. `just infra telemetry`
runs the same dashboards locally.
