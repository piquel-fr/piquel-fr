FROM rust:1.99.0-bookworm AS backend
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Checked SQL compiles from crates/database/.sqlx; no database is reachable here.
COPY .cargo .cargo
# With the shared stylesheet and typefaces in crates/ui/assets, which the
# executable embeds with Topcoat's runtime. It serves the admin dashboard too. The workspace's manifests need every member, piquel-web's
# included, though only auth-service is built.
COPY crates crates
COPY apps apps
# The committed audit verifier keys, compiled into `audit verify` and `audit prune`.
COPY docs/dev/security/audit-key.pub docs/dev/security/audit-key.pub
RUN cargo build --locked --release -p auth-service

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 auth \
    && useradd --uid 10001 --gid auth --no-create-home auth
COPY --from=backend /app/target/release/auth-service /usr/local/bin/auth-service
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["auth-service"]
CMD ["serve"]
