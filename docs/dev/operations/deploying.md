# Deploying with piqueld

This page helps you run SourceOrigin's deployments: set up its environments on a
piqueld daemon, ship a change to staging and then to production, roll
production back, and try a branch on a preview.

`infra/piqueld.toml` deploys SourceOrigin as one piqueld application, `sourceorigin`,
read from this repository. It runs four services in every environment:

| Service | What it serves |
| --- | --- |
| `auth` | auth.sourceorigin.dev, with the account settings and the developer console, and the admin dashboard on a second listener |
| `web` | sourceorigin.dev: the homepage and the policies (see [sourceorigin.dev](#sourceorigindev)) |
| `docs` | this book (see [documentation](#documentation)) |
| `postgres` | the environment's database (see [database](#database)) |

The environments and previews share the manifest. Its variables give each
deployment its own hostnames:

| Deployment | Source | Web | Auth | Admin | Docs | Reachable from |
| --- | --- | --- | --- | --- | --- | --- |
| `production` | promoted from staging | `sourceorigin.dev` | `auth.sourceorigin.dev` | `admin.sourceorigin.dev` | `docs.sourceorigin.dev` | internet; admin from the tailnet |
| `staging` | `main`, on every push | `staging.sourceorigin.dev` | `auth.staging.sourceorigin.dev` | `admin.staging.sourceorigin.dev` | `docs.staging.sourceorigin.dev` | tailnet |
| previews | a branch or a local worktree | `<slug>.dev.sourceorigin.dev` | `auth-<slug>.dev.sourceorigin.dev` | `admin-<slug>.dev.sourceorigin.dev` | `docs-<slug>.dev.sourceorigin.dev` | tailnet |

A second application, `sourceorigin-observability` (`infra/telemetry.toml`), stores and shows
staging's and production's traces, metrics and logs: see
[the telemetry stack](telemetry.md).

## Before you start

- `piquelctl`, signed in to the daemon, with `apps:deploy` on `sourceorigin`,
  `apps:exec` to run commands in its containers, and `secrets:write` to change
  its secrets.
- A piqueld daemon with in-container HTTP probes, local previews and
  manifest-declared environments, configured with:
  - managed ingress, with the private apps node, and a DNS provider for
    `sourceorigin.dev`. Private routes get DNS-01 certificates: `*.dev.sourceorigin.dev`
    covers every preview.
  - `ingress.webhook_hostname`, for deploy-on-push.
  - `reconciliation.prepare_timeout_seconds = 1200`, for cold Rust builds.
- A DNS record for every hostname, either from the provider with
  `manage_records = true` or by hand:
  - the public hosts, `sourceorigin.dev`, `auth.sourceorigin.dev`, `docs.sourceorigin.dev` and
    `www.sourceorigin.dev`, point at the server. Through the Cloudflare Tunnel, each is
    a proxied CNAME to the tunnel. On ports 80 and 443, each is an A record, and
    Caddy obtains its certificate over HTTP-01.
  - `admin.sourceorigin.dev`, `staging.sourceorigin.dev`, `*.staging.sourceorigin.dev`,
    `*.dev.sourceorigin.dev` and `grafana.sourceorigin.dev` point at the apps node's tailnet
    addresses.

## Set up the environments

The manifest declares both environments and where each deploys from: staging
follows pushes to `main` (`sync = true`), and production receives releases
promoted from staging (`promote_from = "staging"`). Saving the manifest creates
them, and every later push to `main` keeps them in line with it. Change them in
the manifest, never with `piquelctl env create`, `env source` or `env sync`. CI
validates every change to it with `piquelctl app validate`, and
`just infra check` runs the same check locally.

To set them up on a new daemon, once the manifest is on `main`:

1. Save the manifest, which creates the application and its environments
   without deploying them:

   ```sh
   piquelctl app apply --file infra/piqueld.toml
   ```

2. Store the secrets piqueld can't generate: the Resend keys, the sign-in
   providers' client secrets and the audit keys. See
   [stored secrets](secrets.md#stored-secrets). A deployment that mounts a
   missing secret fails.
3. Deploy staging:

   ```sh
   piquelctl --timeout 30m env deploy sourceorigin staging
   ```

   piqueld generates each environment's other secrets on its first deployment.
4. Create the webhook's secret, then print its payload URL:

   ```sh
   piquelctl app repository webhook rotate sourceorigin   # prints the secret once
   piquelctl app repository webhook show sourceorigin     # prints the payload URL
   ```

5. Add a webhook to this repository on GitHub, with that URL and secret, the
   `application/json` content type and the `push` event.
6. Grant staging its first administrator, as
   [grant the first administrator](administration.md#grant-the-first-administrator)
   describes with `--env staging`.

Staging now follows `main`. Production waits for its first
[promotion](#promote-to-production); once it runs, grant its first
administrator the same way.

## Deploy staging

Merge to `main`. The push reaches piqueld through the webhook, and staging
builds and deploys that commit. Every deployment runs one job before its
rollout: `migrate`, which applies migrations.

To follow it:

```sh
piquelctl env history sourceorigin staging                   # its deployments, newest first
piquelctl --timeout 30m env wait sourceorigin staging --ready routes
piquelctl env logs sourceorigin staging --service auth
```

`env wait` returns once the deployment succeeded and every route answers. To
deploy `main` again without a push, run
`piquelctl --timeout 30m env deploy sourceorigin staging`.

## Promote to production

Production never builds: it runs the images staging built and ran, never
rebuilt. So nothing a build reads may differ between environments, and every
per-environment value is a runtime `environment` entry.

1. Test staging, from a device on the tailnet.
2. Note the ID of the deployment you tested, the newest one
   `piquelctl env history sourceorigin staging` lists.
3. Review what the promotion would change:

   ```sh
   piquelctl env promote sourceorigin production --deployment <deployment-id> --plan
   ```

4. Promote it:

   ```sh
   piquelctl --timeout 30m env promote sourceorigin production --deployment <deployment-id> --yes
   ```

piqueld refuses the promotion unless staging's current deployment succeeded and
every service runs healthy. With `--deployment`, it also refuses if staging
deployed again since, so it never promotes something you didn't test.

Production renders the release with its own variables and its current secrets,
and runs its jobs before the rollout. Check it with `piquelctl env history
sourceorigin production`, and `piquelctl env url sourceorigin production`, which says
whether each route is ready.

## Roll back production

When a rollout fails, because a new container exits or fails its health check,
production restores its last successful deployment on its own: piqueld rolls
promoted environments back automatically. Staging doesn't: it stays degraded
until you deploy or restore it.

To return production to an earlier deployment yourself, such as when a release
misbehaves without failing its health check:

1. List its deployments:

   ```sh
   piquelctl env history sourceorigin production --limit 10
   ```

2. Restore the one to return to:

   ```sh
   piquelctl env restore sourceorigin production <deployment-id>
   ```

A restore deploys the earlier deployment exactly as it ran, with its images,
variables and secret versions. It runs no job, so the migrations applied since
stay applied. Every migration keeps the release before it working, so restoring
the previous deployment is safe unless a migration says otherwise in its own
comments (see [database](../architecture/database.md)). Before restoring
further back, read the migrations added since.

> **Warning:** a restore, and an automatic rollback, bring back the secret
> versions the earlier deployment used. After rotating a secret, restore only a
> deployment made since, or promote again instead.

`piquelctl app releases sourceorigin` lists the releases.
`piquelctl env promote sourceorigin production --release <release-id>` deploys an
earlier one, with production's current secrets, and runs its `migrate` job.
That job fails when the database holds a migration the release doesn't know,
which stops the deployment before its rollout, so production keeps running what
it ran. Once a migration has run since that release, restore a deployment
instead.

## Pick up a changed secret in production

Production's services read a secret's new value at their next deployment.
Promoting staging would also ship whatever `main` built since, and is refused
while staging's current deployment is unhealthy. To pick up the new value
without new code, deploy production's own release again:

1. Find the release production runs: the newest deployment that succeeded in
   `piquelctl env history sourceorigin production --limit 10`.
2. Check what it would deploy, and that it can use every secret:

   ```sh
   piquelctl --timeout 30m env promote sourceorigin production --release <release-id> --plan
   ```

3. Deploy it:

   ```sh
   piquelctl --timeout 30m env promote sourceorigin production --release <release-id>
   ```

It deploys the same images with production's current secrets. Its `migrate`
job finds nothing to apply, since production already ran that release.

## Previews

A preview is a disposable copy of SourceOrigin, with its own database and secrets,
on tailnet URLs. To deploy the current worktree, uncommitted files included:

```sh
just preview          # prints its URLs once every route answers
just preview-delete   # deletes it and its database
```

`just preview --slot <name>` keeps several previews of one branch. A pushed
branch can also be previewed with `piquelctl preview create sourceorigin --branch
<branch>`, which deploys again on every push. `piquelctl preview prune
sourceorigin --branch-gone` deletes the previews whose branch is gone.

A preview's database starts empty, and anyone may register without an
invitation. Previews send mail with the development key (see
[email](email.md)), have no GitHub or Google sign-in, keep their telemetry on
stderr, and sign audit checkpoints with a key they generate. The daemon's
`[previews]` settings bound their number, CPU, memory and replicas.

Agents follow the
[`preview`](https://github.com/sourceorigin-dev/sourceorigin/tree/main/.agents/skills/preview)
and
[`test-change`](https://github.com/sourceorigin-dev/sourceorigin/tree/main/.agents/skills/test-change)
skills. Their token needs `previews:deploy` and `previews:delete` on
`sourceorigin`, which cannot touch staging or production.

## Running auth-service commands

[Administration](administration.md) and every other operations page run
`auth-service` commands. In an environment, run them in an auth container,
naming yourself with `--operator`:

```sh
piquelctl app exec sourceorigin auth --env production -- auth-service --operator alice admin list
```

The command shares the container's configuration and secrets, and `piquelctl`
exits with its exit code. The container knows nothing of who you are, so every
event the command causes records the name `--operator` gives, and an
administrative command refuses to run without one. A command that asks for
confirmation needs a terminal: add `-t`, or give the command `--yes`. For a
preview, run `piquelctl preview exec sourceorigin <branch> auth -- auth-service
--operator <you> …`.

## Documentation

The `docs` service serves this book, built by `infra/docs.Dockerfile` from the
deployment's own commit, with
[static-web-server](https://static-web-server.net). So production's book always
describes the release production runs, and a preview's shows a branch's
documentation as it would be published. A missing page gets mdBook's own
not-found page.

## Routes and redirects

The `www` route redirects permanently (`308`) to the web host, keeping the path
and query: `www.sourceorigin.dev/settings?x=1` goes to `sourceorigin.dev/settings?x=1`. The
gateway answers it itself. piqueld renders every route in every environment, so
staging and previews redirect their own `www` names too, which fall under the
existing wildcard records and certificates.

sourceorigin.dev's web server redirects every path it doesn't serve to auth: see
[sourceorigin.dev](#sourceorigindev).

## Database

Each environment and preview has its own PostgreSQL 18 volume. Auth connects
over TCP to `postgres:5432` on the application's private network, which ingress
and other environments cannot reach, so the URL opts into plaintext with
`sslmode=disable`. Connections require SCRAM password authentication.

Auth connects as `sourceorigin_auth`, a role with row access to the app tables only
(see [roles](../architecture/database.md#roles)). Only PostgreSQL itself and the
`migrate` job get the superuser `sourceorigin`'s password. Once PostgreSQL is healthy,
`migrate` applies migrations, then creates `sourceorigin_auth` or resets its
privileges and password.

An environment's volume survives the environment's deletion. A PostgreSQL major
upgrade needs an explicit data migration.

## Client addresses

Auth throttles each client separately. It trusts the client address that
ingress writes in `X-Forwarded-For` from the gateway ranges in
`PIQUELD_INGRESS_PROXIES`, which piqueld gives every service.
`AUTH_TRUSTED_PROXIES` replaces those ranges when set.

## Caching

Auth sets every response's `Cache-Control` itself, so the edge needs no rule.
Handlers mark a response cacheable with `Cached`
(`apps/auth-service/src/security`). Anything else, including every error and
every response that sets a cookie, is `no-store`. Every value also carries
`no-transform`, so Cloudflare never rewrites a body: its Email Address
Obfuscation would replace addresses with a link to a script the pages'
Content-Security-Policy blocks.

| Class | `Cache-Control` | Responses |
| --- | --- | --- |
| `NoStore` | `no-store, no-transform` | APIs, OAuth, server-rendered pages, errors, everything not below |
| `Immutable` | `public, max-age=31536000, immutable, no-transform` | the pages' content-hashed stylesheet and script, under `/assets/`, and profile pictures, under `/pictures/`, named by their upload |
| `Public` | `public, max-age=N, no-transform` | discovery and JWKS, for an hour |

Every page is `no-store`, so a deploy never leaves a cached page pointing at a
stylesheet or script the new binary no longer serves. The Cloudflare Tunnel
caches the immutable files, as it does any static file type the origin lets it
store. Profile pictures have no file extension, so it keeps none of them, and a
removed picture stops being served at once. `Public` responses are the same for
everyone, with `Access-Control-Allow-Origin: *` and no credentials, as profile
pictures have. The stylesheet and script carry no CORS headers. Staging and
previews are private routes, which bypass Cloudflare.

## Timeouts and limits

Auth bounds every connection, request and stop, so a slow client, a flood or a
stuck job can't hang it. Each listener, public and admin, applies them on its
own:

| Limit | Value | When it passes |
| --- | --- | --- |
| Request headers | 10 s | The connection closes. This also closes a kept-alive connection that starts no new request. |
| Response writes | 10 s without progress | The connection closes, as for a client that stopped reading. |
| Request deadline | 30 s, checks and handler included | The request gets `504`. |
| Requests in flight | 64 per listener | Further requests get `503` with `Retry-After: 1` at once, instead of queueing for the database pool's 10 connections. Any origin may read the refusal. Health probes are exempt. |
| Rate budgets | `AUTH_REQUESTS_PER_MINUTE` per client and category | The request gets `429` (see [security properties](../security/properties.md)). |
| Database statements, locks and idle transactions | 15 s, 5 s and 30 s | See [the database's time limits](../architecture/database.md#time-limits). |

The `sourceorigin.auth.throttled` metric counts refused requests by category. A
request refused for the in-flight limit counts as `overloaded`.

Auth serves HTTP/1.1 only. piqueld's ingress terminates TLS and HTTP/2, and
reaches auth over HTTP/1.1.

### Stopping

piqueld stops a container with `SIGTERM`, and kills it 10 seconds later. Auth
always exits within 9 seconds:

1. Both listeners stop accepting, and background jobs are told to stop, at once.
2. Open requests and running jobs get 6 seconds, together, to finish. Requests
   and jobs still running then are cancelled. A cancelled job closes its
   connection, which releases its lock.
3. Telemetry gets 3 seconds to flush. What it hasn't sent by then is lost.
4. The process exits, without waiting for blocking work still running, such as
   a DNS lookup.

## sourceorigin.dev

The `web` service (`apps/web`, built by the `web` target of
`infra/rust.Dockerfile`) serves sourceorigin.dev's homepage at `/`, the privacy
policy at `/privacy` and the terms of service at `/terms`. Google's OAuth branding links the policies, and so do
auth's pages (`AUTH_WEB_ORIGIN`). It keeps no state, so it has no database or
secret, and any number of replicas can serve it.

Every other path redirects, temporarily (`307`) and with its query, to the same
path on auth. So links to sourceorigin.dev's settings paths (`/settings`,
`/settings/emails`, `/settings/emails/verify`, `/settings/sessions` and
`/settings/history`) open auth's page, and browsers keep a verification link's
fragment (`/settings/emails/verify#token=…`). Notice emails link to
`/settings/history` and never expire: keep the redirect, and those paths on
auth, for as long as sourceorigin.dev serves nothing at them. A path ending in a slash
redirects to the page. Being temporary, the redirect leaves browsers nothing
cached once sourceorigin.dev serves pages of its own.

Cloudflare's edge sets sourceorigin.dev's `Strict-Transport-Security`, with the values
sourceorigin-web sends: `max-age=31536000`, without `includeSubDomains` or `preload`.
