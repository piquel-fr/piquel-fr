FROM rust:1.99.0-bookworm AS backend
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
# Cargo loads every workspace member; only admin-web is built.
COPY apps/auth-service apps/auth-service
COPY apps/admin-web apps/admin-web
# The shared piquel.fr styles, which the dashboard serves with its own.
COPY packages/auth-sdk/src/style.css packages/auth-sdk/src/style.css
RUN cargo build --locked --release -p admin-web

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 admin \
    && useradd --uid 10001 --gid admin --no-create-home admin
COPY --from=backend /app/target/release/admin-web /usr/local/bin/admin-web
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["admin-web"]
