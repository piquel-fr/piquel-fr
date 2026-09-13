# Piqueld deployments

Development runs through the local piqueld daemon on the server. The two
applications are `piquel-fr-dev` and `piquel-fr-prod`.

## Development

`infra/dev.toml` is the complete development manifest. It reads itself and builds
both services from the `main` branch of `/home/piquel/Projects/piquel-fr` on the
server. Piqueld needs Git, the Docker CLI, and read access to that repository.
Increase its `reconciliation.prepare_timeout_seconds` to `1200` for cold Rust builds.

Replace the `AUTH_DATABASE_URL` placeholder in `dev.toml` with your development
PostgreSQL URL, then commit the manifest and application changes to the configured
branch. No push to GitHub is needed. To use another checkout or branch, edit all
three repository sections in `dev.toml` (manifest, auth, and web).

```sh
just dev-init  # once: register the application and deploy
just dev       # deploy the configured local branch again
```

These recipes call `piquelctl` directly. For a non-default socket, use
`piquelctl --socket /path/to/piqueld.sock` with the same apply/deploy arguments.
Running a command from a different worktree does not change the deployment source;
uncommitted edits and other branches are excluded. Piqueld resolves the manifest
and service revisions independently, so avoid moving the branch during deployment.

Use a separate development database with `sslmode=verify-full` and a certificate
trusted by the container. Auth applies migrations before serving. No database is
provisioned here. Private CAs require adding a read-only certificate volume and an
`sslrootcert` URL parameter. The database URL is stored literally in the manifest
and deployment history as temporary secret handling; it is not expanded from your
shell environment. Replace this with managed secrets before production use.

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
