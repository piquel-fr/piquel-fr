FROM rust:1.99.0-bookworm AS backend
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
# The workspace's manifests need every member; only sourceorigin-web and its crates
# are built. It embeds the shared stylesheet (crates/ui/assets) and the policies
# (apps/web/assets).
COPY crates crates
COPY apps apps
RUN cargo build --locked --release -p sourceorigin-web

FROM debian:bookworm-slim
RUN groupadd --gid 10001 web \
    && useradd --uid 10001 --gid web --no-create-home web
COPY --from=backend /app/target/release/sourceorigin-web /usr/local/bin/sourceorigin-web
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["sourceorigin-web"]
