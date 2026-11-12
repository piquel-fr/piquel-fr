# The Rust services, one image per target: `auth` (the auth service, its admin
# dashboard and the operator CLI) and `web` (sourceorigin.dev's web server).
# Both binaries build together in `backend`, so building both targets compiles
# the workspace once.

# cargo-chef compiles the dependencies in a layer of their own, rebuilt only when
# a manifest, Cargo.lock or the cargo config changes.
FROM rust:1.99.0-bookworm AS chef
RUN cargo install --locked cargo-chef@0.1.78
WORKDIR /app

# The recipe lists the workspace's dependencies, from its manifests and lockfile.
# The workspace's manifests need every member, so this copies the same sources as
# `backend`.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY apps apps
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS backend
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --locked --release -p auth-service -p sourceorigin-web --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
# Checked SQL compiles from crates/database/.sqlx; no database is reachable here.
COPY .cargo .cargo
# With the shared stylesheet in crates/ui/assets, the passkey script in
# apps/auth-service/assets and the policies in apps/web/assets, which the
# executables embed.
COPY crates crates
COPY apps apps
# The committed audit verifier keys, compiled into `audit verify` and `audit prune`.
COPY docs/dev/security/audit-key.pub docs/dev/security/audit-key.pub
# Only the binaries leave this layer: without the build's target directory,
# its cached copy stays small.
RUN cargo build --locked --release -p auth-service -p sourceorigin-web \
    && mv target/release/auth-service target/release/sourceorigin-web /usr/local/bin/ \
    && rm -rf target

FROM debian:bookworm-slim AS auth
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 auth \
    && useradd --uid 10001 --gid auth --no-create-home auth
COPY --from=backend /usr/local/bin/auth-service /usr/local/bin/auth-service
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["auth-service"]
CMD ["serve"]

FROM debian:bookworm-slim AS web
# reqwest trusts the platform's roots, which its telemetry exporter loads.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 web \
    && useradd --uid 10001 --gid web --no-create-home web
COPY --from=backend /usr/local/bin/sourceorigin-web /usr/local/bin/sourceorigin-web
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["sourceorigin-web"]
