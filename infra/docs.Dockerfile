# The documentation book, which the `docs` service of infra/piqueld.toml serves:
# docs.piquel.fr in production. Every deployment serves the book of its own
# commit. See "Documentation" in docs/dev/operations/deploying.md.

# mdBook's release binary, at the version `just install-tools` and CI use.
FROM debian:bookworm-slim AS book
ADD --checksum=sha256:5222beabd3e37dc5be0d18ff99b79058469354db5c220153a1b92db5ba12be89 \
    https://github.com/rust-lang/mdBook/releases/download/v0.5.4/mdbook-v0.5.4-x86_64-unknown-linux-musl.tar.gz \
    /tmp/mdbook.tar.gz
RUN tar -xzf /tmp/mdbook.tar.gz -C /usr/local/bin
WORKDIR /book
COPY book.toml ./
COPY docs docs
# The SDKs' examples, which the user guide includes.
COPY crates/auth-sdk/examples/notes.rs crates/auth-sdk/examples/
COPY packages/auth/examples/server.ts packages/auth/examples/browser.ts packages/auth/examples/resource.ts packages/auth/examples/
RUN mdbook build

# Serves the built book on port 8080, with mdBook's 404.html for missing pages.
# The image sets no user, so this runs it as an unprivileged one, which binds an
# unprivileged port and reads the world-readable book.
FROM joseluisq/static-web-server:2.44.1@sha256:94618e3d17802265a21926217e6f9e7832b311b6fbf5933684001739fafed06a
ENV SERVER_PORT=8080
COPY --from=book /book/target/book /public
USER 65532:65532
