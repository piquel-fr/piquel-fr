FROM rust:1.99.0-bookworm AS backend
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates/admin-api crates/admin-api
COPY crates/auth-sdk crates/auth-sdk
COPY crates/common crates/common
COPY crates/telemetry crates/telemetry
# Cargo loads every workspace member, so the ones admin-web doesn't use are only
# their manifests and an empty target: their sources never invalidate this build.
COPY apps/auth-service/Cargo.toml apps/auth-service/
COPY crates/crypto/Cargo.toml crates/crypto/
COPY crates/database/Cargo.toml crates/database/
RUN for member in apps/auth-service crates/crypto crates/database; do \
        mkdir -p "$member/src" && touch "$member/src/lib.rs"; \
    done
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
