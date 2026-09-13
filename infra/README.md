# Piqueld deployments

Development runs through the local piqueld daemon on the server. The two
applications are `piquel-fr-dev` and `piquel-fr-prod`.

## Development

Install `piquelctl`, Git, Node 24+, and `just` on the server. Piqueld needs Git,
the Docker CLI, and access to this checkout. Increase its
`reconciliation.prepare_timeout_seconds` to `1200` for cold Rust builds.

Commit your changes before deploying. Both the manifest template and service
sources come from the checked-out **HEAD**, including a feature branch. Dirty
files are excluded. No push to GitHub is needed.

```sh
export AUTH_DATABASE_URL='postgres://USER:PASSWORD@DB_HOST/DEV_DATABASE?sslmode=verify-full'
# Optional when using a non-default daemon socket or CLI location:
# export PIQUELD_SOCKET=/path/to/piqueld.sock
# export PIQUELCTL=/path/to/piquelctl

just dev-init  # once per application; registers it and deploys HEAD
just dev       # subsequent deployments
```

Use a separate development database. Auth applies its migrations before serving.
Remote PostgreSQL must use `sslmode=verify-full` and a certificate trusted by the
container. No database is provisioned by these manifests. Private CAs require
adding a read-only certificate volume and an `sslrootcert` URL parameter.

`dev.mjs` reads `infra/dev.json` from HEAD, pins each Git build to that commit and
this checkout's absolute path, and writes a repository-backed manifest into
`.piqueld/manifest`. It commits that generated manifest locally and asks piqueld
to Deploy. The daemon fetches the manifest and builds both images. This auxiliary
Git repository never changes the checkout's branch or index.

Keep `.piqueld` in place: subsequent manual Deploy actions fetch it. It is ignored
by Git and Docker and created with private permissions, but **contains the database
URL in Git history**, as does piqueld's deployment state. This is temporary secret
handling. Do not push that repository or reuse production credentials.
The daemon must run as a user able to read these private files and the checkout.
Keep using the same checkout for this application; changing its path requires
updating the application's repository connection in piqueld.

Auth listens on HTTP port 8080; nginx serves settings on HTTP port 8080 in its own
container. Browser URLs are `http://localhost:8080` and
`http://localhost:8081/settings`. Registration is open in dev and signing keys are
ephemeral, so a restart invalidates existing signed tokens. No external identity
providers or OIDC clients are configured.

## Browser access until piqueld supports ports

Piqueld creates a private, attachable Swarm network but cannot publish ports yet.
Deploying alone therefore does **not** expose localhost listeners. Do not manually
publish ports on managed services: reconciliation may undo those edits.

For temporary access, run an nginx forwarding container on the application's
network, publishing only `127.0.0.1:8080` and `127.0.0.1:8081` on the server.
Find the exact network and service names with `docker network ls` and
`docker service ls` (piqueld names include application IDs and hashes).
Use this forwarding configuration, replacing `AUTH_SERVICE` and `WEB_SERVICE`:

```nginx
events {}
http {
    server {
        listen 8080;
        location / { proxy_pass http://AUTH_SERVICE:8080; }
    }
    server {
        listen 8081;
        location / { proxy_pass http://WEB_SERVICE:8080; }
    }
}
```

```sh
docker run --rm --name piquel-fr-dev-access \
  --network APPLICATION_NETWORK \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 \
  -v /absolute/path/to/forwarding.conf:/etc/nginx/nginx.conf:ro \
  nginx:stable-bookworm
```

This temporary access container only forwards traffic to piqueld-managed services.
When browsing from another machine, tunnel both ports to your browser's localhost:

```sh
ssh -N -L 8080:127.0.0.1:8080 -L 8081:127.0.0.1:8081 SERVER
```

Use `localhost` in the browser, matching the configured origins. Public plain HTTP
is unsupported by passkeys and the auth service. HTTPS routing can replace this
temporary access setup once piqueld supports it.

## Production placeholder

After this change is merged to main:

```sh
piquelctl apply --file infra/prod.toml --yes
```

`prod.toml` reserves `piquel-fr-prod` and connects it to this repository's main
branch. It intentionally has no services or volumes. Do not use it to update an
existing production runtime: deploying an empty manifest removes its services.

Before adding production services, configure managed HTTPS ingress, persistent
signing keys, secrets, and the production TLS database. Disable development mode,
use `https://auth.piquel.fr` and `https://piquel.fr/settings`, and build the web
image with the production auth origin. Pin build commits when consistent releases
are required: piqueld resolves manifest and service Git revisions independently.

## Validation

Both Dockerfiles build from repository root. Auth embeds its built frontend into
the Rust binary; nginx serves prerendered pages, including `/settings`, and returns
404 for missing paths. Both images include `wget` for piqueld's health checks.
Auth readiness checks PostgreSQL. Build/lint/unit-test commands remain available
for validation; they do not start an alternate development server.
