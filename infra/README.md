# Piqueld deployments

`infra/piqueld.toml` deploys piquel.fr as one repository-backed piqueld
application, `piquel-fr`: auth, the web settings frontend, the admin dashboard,
and PostgreSQL. Its environments and previews share the manifest; variables give
each its own hostnames.

| Deployment | Source | Web | Auth | Admin | Redirects to web | Reachable from |
| --- | --- | --- | --- | --- | --- | --- |
| `production` | promoted from staging | `piquel.fr` | `auth.piquel.fr` | `admin.piquel.fr` | `www.piquel.fr` | internet; admin from the tailnet |
| `staging` | `main`, on every push | `staging.piquel.fr` | `auth.staging.piquel.fr` | `admin.staging.piquel.fr` | `www.staging.piquel.fr` | tailnet |
| previews | a branch or a local worktree | `<slug>.dev.piquel.fr` | `auth-<slug>.dev.piquel.fr` | `admin-<slug>.dev.piquel.fr` | `www-<slug>.dev.piquel.fr` | tailnet |

The `www` route is a permanent (308) redirect that the gateway answers itself,
keeping the path and query: `www.piquel.fr/settings?x=1` goes to
`piquel.fr/settings?x=1`. piqueld renders every route in every environment, so
staging and previews get one too; their names fall under the existing wildcard
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
  `*.dev.piquel.fr` to the apps node's tailnet addresses. Through the Cloudflare Tunnel, a public
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

The `migrate` job applies migrations before every rollout, once PostgreSQL is
healthy. Environment volumes survive deletion. PostgreSQL major upgrades require
an explicit data migration.

## Auth

piqueld generates `database-password`, `signing-key` and `admin-client-secret`
for each environment and preview on its first deployment and never changes them;
`piquelctl env secret piquel-fr --env ENV regenerate NAME` rotates one. A new
password does not change the one an existing database volume stores.

Staging and production require invitations:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service invite
```

OIDC clients are registered and changed the same way, with the `client` command
(see "OIDC clients" in the root README); a change applies at once, without a
deploy:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service client list
```

No external identity providers are configured by default. The only client an
environment needs, the dashboard's, is registered by a deploy job (see
[Admin](#admin)). Auth uses
the gateway ranges in `PIQUELD_INGRESS_PROXIES` to trust ingress's overwritten
`X-Forwarded-For` address and throttle each client separately.
`AUTH_TRUSTED_PROXIES` overrides those ranges when set.

### Running several replicas

`auth_replicas` sets how many auth replicas run (default 1). Two already overlap
on every deploy: auth mounts no volume, so piqueld starts the new replica before
stopping the old one, after the `migrate` job. On one node, a second replica
removes the restart gap after a crash; it adds no capacity.

- **Shared state.** Sessions, ceremonies, federation state, rate-limit budgets and
  refresh-token rotation live in PostgreSQL. Database tests build two instances
  on one database to check that sign-in, logout, budgets and refresh rotation
  span them.
- **Configuration.** Replicas must run with the same `AUTH_*` settings. Signing
  keys, refresh-token digests and passkey decoys all derive from the
  `signing-key` secret (`AUTH_KEY_PROVIDER`), which the manifest gives every
  replica. Audit checkpoints are signed with a separate key
  (`AUTH_AUDIT_KEY_PROVIDER`): the stored `audit-key-production` and
  `audit-key-staging` secrets, or a preview's generated `audit-key`.
- **Per-replica state.** Only Google's signing keys are cached per replica. OIDC
  clients, and the public-client origins CORS allows, are read from the
  database on each request, so a client change reaches every replica at once.
- **Background work.** Jobs run through one runner
  (`apps/auth-service/src/jobs.rs`). An exclusive job, such as expired-state
  cleanup every five minutes or audit sealing every five seconds, holds a PostgreSQL advisory lock while it runs, so
  one replica at a time runs it and the others skip that run. A run that fails
  or panics is logged and retried at the next interval. On shutdown, once
  in-flight requests drain, running jobs get 10 seconds to finish (cleanup stops
  after its current batch), then are cancelled, which closes their connection and
  releases the lock.
- **Migrations.** During a deploy the previous release runs against the new
  schema, so migrations expand, then contract
  (`docs/architecture/database-crate.md`).

## Admin

The admin service is the dashboard in `apps/admin-web`, on port 8080 as a non-root
user, behind a private route in every environment. It calls the admin API at
`http://auth:8081`, auth's private listener, which only services of the same
environment reach; it has no database credentials. Its health check,
`GET /healthz`, does not call auth: the dashboard discovers auth in the
background, since auth's route may not serve yet when it starts.

Its OIDC client, `piquel-admin`, needs no setup. After `migrate`, the
`admin-client` job runs `auth-service client apply` on every deploy: it registers
the client with the environment's admin host and the `admin-client-secret` that
piqueld generated, or updates what differs. After `piquelctl env secret piquel-fr
--env ENV regenerate admin-client-secret`, the next deploy registers the new
secret; the previous one keeps working for an hour, while the dashboard rolls out.

Only administrators can use it. Grant the first one with the CLI:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service admin grant USERNAME
```

Administrators sign in to the dashboard again after it restarts; their sign-ins
live in its memory. That is silent while their auth session lasts.

## Web

The web service is the piquel-web SvelteKit server on Node (`node build`, port
8080, as a non-root user). Its image is built without an auth origin: the server
reads `AUTH_ORIGIN` at startup, refuses to start unless it is an `https://`
origin, passes it to pages as layout data and narrows their CSP `connect-src` to
it. `ORIGIN` gives the server its public URL behind ingress. The health check,
`GET /healthz`, does not call auth, so a server that fails to start blocks the
deployment without coupling it to auth's health.
