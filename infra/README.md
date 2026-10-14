# Piqueld deployments

`infra/piqueld.toml` deploys piquel.fr as one repository-backed piqueld
application, `piquel-fr`: auth, the web settings frontend, and PostgreSQL. Its
environments and previews share the manifest; variables give each its own
hostnames.

| Deployment | Source | Web | Auth | Redirects to web | Reachable from |
| --- | --- | --- | --- | --- | --- |
| `production` | promoted from staging | `piquel.fr` | `auth.piquel.fr` | `www.piquel.fr` | internet |
| `staging` | `main`, on every push | `staging.piquel.fr` | `auth.staging.piquel.fr` | `www.staging.piquel.fr` | tailnet |
| previews | a branch or a local worktree | `<slug>.dev.piquel.fr` | `auth-<slug>.dev.piquel.fr` | `www-<slug>.dev.piquel.fr` | tailnet |

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

- piqueld with in-container HTTP probes and local previews (`main` after #219).
- Managed ingress with the private apps node, and a DNS provider for
  `piquel.fr`: private routes get DNS-01 certificates (`*.dev.piquel.fr` covers
  every preview).
- DNS records for every hostname: `manage_records = true` on that provider, or by
  hand: public hosts (`piquel.fr`, `auth.piquel.fr`, `www.piquel.fr`) to the
  server, and `staging.piquel.fr`, `*.staging.piquel.fr` and `*.dev.piquel.fr`
  to the apps node's tailnet addresses. Through the Cloudflare Tunnel, a public
  host is a proxied CNAME to the tunnel; on ports 80/443, an A record, and Caddy
  obtains its certificate over HTTP-01.
- `ingress.webhook_hostname` for deploy-on-push.
- `reconciliation.prepare_timeout_seconds = 1200` for cold Rust builds.

## Setup

Once, after this manifest is on `main`:

```sh
piquelctl app apply --file infra/piqueld.toml --yes
piquelctl env create piquel-fr staging --branch main --yes
piquelctl env source piquel-fr production --promote-from staging --yes
piquelctl env sync piquel-fr staging on
piquelctl app repository webhook rotate piquel-fr   # prints the secret once
piquelctl app repository webhook show piquel-fr     # prints the payload URL
```

Add a GitHub webhook to this repository with that URL and secret,
`application/json`, and the `push` event. Then deploy staging once; it follows
`main` from then on:

```sh
piquelctl --timeout 30m env deploy piquel-fr staging --yes
```

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

Each environment and preview has its own PostgreSQL 18 volume; the runtime role
setup below needs 17 or later. Auth connects
over TCP to `postgres:5432` on the application's private network, which ingress
and other environments cannot reach, so the URL opts into plaintext with
`sslmode=disable`; connections require SCRAM password authentication.

Two roles use the database. `piquel` is the image's superuser: it owns the
schema and only the `migrate` job connects as it. Auth serves as `piquel_auth`,
which has no superuser, role or database creation rights, and only row access
to the tables: it cannot change the schema, disable the email-ownership
triggers, rewrite `security_audit_log` or run server programs.

The `migrate` job runs before every rollout, once PostgreSQL is healthy. It
applies migrations as `piquel`, then creates `piquel_auth` if missing, resets its
attributes, password, privileges and settings, and grants it access to every table,
including new ones. Fresh and existing volumes therefore converge on the same
roles. If `piquel_auth` was made a member of another role, given an object in
`piquel` or a shared one, or granted more than row access by another role,
`migrate` fails without changes until that is undone. `piquel_auth` can still
connect to the cluster's other databases (`postgres`, `template1`), where
PostgreSQL's defaults give it no meaningful privileges; revoke PUBLIC's
`CONNECT` there to prevent even that. piqueld
jobs share their service's secrets, so the `auth` container also mounts the
owner password for `migrate`; `serve` and `invite` never read it.

Environment volumes survive deletion. PostgreSQL major upgrades require an
explicit data migration.

## Auth

piqueld generates `database-password` (for `piquel`), `database-runtime-password`
(for `piquel_auth`) and `signing-key` for each environment and preview on the
first deployment that mounts them (for environments created before
`piquel_auth`, the deployment that introduces it) and never changes them;
`piquelctl env secret piquel-fr --env ENV regenerate NAME` rotates one. A new
`database-runtime-password` takes effect on the next deployment, when `migrate`
sets it. Until the rollout replaces them, old replicas keep their open
connections but cannot open new ones. Open sessions survive the change, and one
holding a lock on the role makes `migrate` fail after 10 seconds. So after a
leak, regenerate the secret, lock the role out and end its sessions, then deploy;
`migrate` restores its login with the new password. A reconnecting session can
hold the role's row again, so each attempt gives up after a second and the loop
retries until `NOLOGIN` commits. A connection can pass the login check just before
it and still be starting, with no user name yet, so the final sweep also ends
those (any client's), waits for each and fails if one survives:

```sh
piquelctl env secret piquel-fr --env ENV regenerate database-runtime-password
owner_sql() { piquelctl app exec piquel-fr postgres --env ENV -- psql -U piquel -d piquel -v ON_ERROR_STOP=1 "$@"; }
end="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'piquel_auth'"
until owner_sql -c "SET lock_timeout = '1s'" -c "$end" -c "ALTER ROLE piquel_auth NOLOGIN"; do sleep 1; done
owner_sql -c "DO \$\$ BEGIN IF NOT coalesce((SELECT bool_and(pg_terminate_backend(pid, 5000))
  FROM pg_stat_activity WHERE usename = 'piquel_auth' OR backend_type = 'client backend' AND usename IS NULL),
  true) THEN RAISE EXCEPTION 'a session survived; run this again'; END IF; END \$\$"
```

Auth is unavailable until the new replicas start. Whenever `migrate` times out
waiting for a lock, run the last four lines again. A new `database-password`
does not change the one an existing database volume stores.

Staging and production require invitations:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service invite
```

No external identity providers or OIDC clients are configured by default. Auth uses
the gateway ranges in `PIQUELD_INGRESS_PROXIES` to trust ingress's overwritten
`X-Forwarded-For` address and throttle each client separately.
`AUTH_TRUSTED_PROXIES` overrides those ranges when set.

## Web

The web service is the piquel-web SvelteKit server on Node (`node build`, port
8080, as a non-root user). Its image is built without an auth origin: the server
reads `AUTH_ORIGIN` at startup, refuses to start unless it is an `https://`
origin, passes it to pages as layout data and narrows their CSP `connect-src` to
it. `ORIGIN` gives the server its public URL behind ingress. The health check,
`GET /healthz`, does not call auth, so a server that fails to start blocks the
deployment without coupling it to auth's health.
