# Piqueld deployments

`infra/piqueld.toml` deploys piquel.fr as one repository-backed piqueld
application, `piquel-fr`: auth, the web settings frontend, and PostgreSQL. Its
environments and previews share the manifest; variables give each its own
hostnames.

| Deployment | Source | Web | Auth | Reachable from |
| --- | --- | --- | --- | --- |
| `production` | promoted from staging | `piquel.fr` | `auth.piquel.fr` | internet |
| `staging` | `main`, on every push | `staging.piquel.fr` | `auth.staging.piquel.fr` | tailnet |
| previews | a branch or a local worktree | `<slug>.dev.piquel.fr` | `auth-<slug>.dev.piquel.fr` | tailnet |

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
  hand: public hosts to the server, and `staging.piquel.fr`,
  `*.staging.piquel.fr` and `*.dev.piquel.fr` to the apps node's tailnet
  addresses.
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

Each environment and preview has its own PostgreSQL 18 volume. Auth connects
over TCP to `postgres:5432` on the application's private network, which ingress
and other environments cannot reach, so the URL opts into plaintext with
`sslmode=disable`; connections require SCRAM password authentication.

The `migrate` job applies migrations before every rollout, once PostgreSQL is
healthy. Environment volumes survive deletion. PostgreSQL major upgrades require
an explicit data migration.

## Auth

piqueld generates `database-password` and `signing-key` for each environment and
preview on its first deployment and never changes them;
`piquelctl env secret piquel-fr --env ENV regenerate NAME` rotates one. A new
password does not change the one an existing database volume stores.

Staging and production require invitations:

```sh
piquelctl app exec piquel-fr auth --env production -- auth-service invite
```

No external identity providers or OIDC clients are configured by default. Auth uses
the gateway ranges in `PIQUELD_INGRESS_PROXIES` to trust ingress's overwritten
`X-Forwarded-For` address and throttle each client separately.
`AUTH_TRUSTED_PROXIES` overrides those ranges when set.

## Web

The web image is built without an auth origin. `web-entrypoint.sh` reads
`AUTH_ORIGIN` at startup; nginx serves it as `/config.json` and narrows the
page's CSP `connect-src` to it.
