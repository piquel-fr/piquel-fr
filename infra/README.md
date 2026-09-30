# Piqueld deployments

Both environments run on the server's piqueld daemon as repository-backed
applications. They share one layout: auth, the web settings frontend, and
PostgreSQL, exposed through piqueld's managed HTTPS ingress.

| Application | Manifest | Source | Auth | Settings |
| --- | --- | --- | --- | --- |
| `piquel-fr-dev` | `infra/dev.toml` | local checkout | `auth.dev.piquel.fr` | `dev.piquel.fr` |
| `piquel-fr` | `infra/prod.toml` | GitHub `main` | `auth.piquel.fr` | `piquel.fr` |

## Server prerequisites

- Git and the Docker CLI in piqueld's `PATH`. Dev reads
  `/home/piquel/Projects/piquel-fr`; production clones this repository from GitHub.
- `reconciliation.prepare_timeout_seconds = 1200` for cold Rust builds.
- `[ingress] enabled = true`, ports 80/443 reachable, and A records for all four
  hostnames. Piqueld's own `auth.public_url` must not be one of these hostnames or
  a parent domain: piqueld reserves it and its subdomains.
- Node wherever `just init` runs; it generates the secrets.

## Deploying

```sh
just dev-init                          # once: register dev, generate secrets, deploy
just dev                               # deploy the configured local branch again
just init piquel-fr infra/prod.toml    # once, after merging to main
piquelctl app deploy piquel-fr --yes   # deploy main again
```

`init` applies the manifest, stores fresh `database-password` and `signing-key`
secrets, and deploys. Run it only once per application: a new password does not
change the one stored in an existing database volume.

Dev currently selects `t3code/add-piqueld-deployment-manifests` for testing; change
all three branch settings in `dev.toml` to `main` before merging. Commit changes to
the configured branch; no push is needed. Uncommitted edits and other branches are
excluded. Piqueld resolves the manifest and service revisions independently, so
avoid moving the branch during deployment.

## Database

PostgreSQL 18 keeps its data in the `postgres-data` volume and shares its Unix
socket with auth through `postgres-socket`. It has no TCP listener. Dev and
production use different Docker volumes even though their logical names match.
Named volumes survive application deletion. PostgreSQL major upgrades require an
explicit data migration.

Both services read the `database-password` secret: PostgreSQL through
`POSTGRES_PASSWORD_FILE` when initializing an empty volume, and auth through
`AUTH_DATABASE_PASSWORD`. Socket connections require SCRAM password authentication.
Auth applies migrations before serving. Piqueld starts services independently, so
auth may restart while PostgreSQL initializes on the first deploy.

## Auth

Auth runs in production mode in both environments with a persistent signing key
from the `signing-key` secret. Registration requires an invitation. Create one in
the running auth container (find it with `docker ps`):

```sh
docker exec CONTAINER auth-service invite create
```

No external identity providers or OIDC clients are configured.

Caddy terminates TLS and proxies to each service's port 8080. Auth throttles by
direct peer IP and does not trust forwarded headers, so behind ingress every
client shares one rate limit.

## Web

Piqueld cannot pass Docker build arguments, so `web.Dockerfile` builds the
settings frontend once per auth origin. nginx serves the `dev.piquel.fr` build to
that hostname and the production build to every other host.
