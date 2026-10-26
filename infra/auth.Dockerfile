FROM node:24-bookworm-slim AS sdk
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install --global "$(node -p 'require("./package.json").packageManager')"
COPY packages/auth-sdk packages/auth-sdk
RUN pnpm install --frozen-lockfile --filter @piquel/auth-sdk
# The SDK's script, which auth's pages load.
RUN pnpm build

FROM rust:1.99.0-bookworm AS backend
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Checked SQL compiles from crates/database/.sqlx; no database is reachable here.
COPY .cargo .cargo
COPY crates crates
COPY apps/auth-service apps/auth-service
# Cargo loads every workspace member, so admin-web is only its manifest and an
# empty target: its sources never invalidate this build.
COPY apps/admin-web/Cargo.toml apps/admin-web/
RUN mkdir -p apps/admin-web/src && touch apps/admin-web/src/main.rs
COPY --from=sdk /app/packages/auth-sdk/build packages/auth-sdk/build
# The shared styles, which auth's pages link.
COPY packages/auth-sdk/src/style.css packages/auth-sdk/src/style.css
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
