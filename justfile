# Validate by default; database and browser tests remain explicit.
default: validate

# Rust formatting, linting, checks, audits and the auth-service build.
mod rust 'just/rust.just'

# Web formatting, linting, type checks, the TypeScript SDK's tests and the browser tests.
mod web 'just/web.just'

# Scratch PostgreSQL clusters, database tests, the SQLx query cache and migrations.
mod db 'just/db.just'

# auth-service commands with the caller's configuration, and secret generation.
mod auth 'just/auth.just'


# piqueld previews of this worktree, and a local telemetry backend.
mod infra 'just/infra.just'

alias format := fmt
alias preview := infra::preview
alias preview-delete := infra::preview-delete

validate: fmt-check lint check test web::test doc doc-test audit

install:
    @pnpm install --frozen-lockfile

# Cargo tools used by the test, audit and database recipes.
install-tools:
    @cargo install --locked cargo-nextest cargo-deny
    @cargo install --locked sqlx-cli --no-default-features --features rustls,postgres

# The release auth-service executable.
build: (rust::build "--release")

fmt: rust::fmt web::fmt

fmt-check: rust::fmt-check web::fmt-check

# Warnings fail both linters, like `-D warnings`.
lint: rust::lint web::lint

check: rust::check web::check

# Extra nextest arguments can select a package or test expression.
[positional-arguments]
test *ARGS='--workspace':
    @cargo nextest run --locked "$@"

# Rustdoc warnings, such as broken or private intra-doc links, fail the build.
doc:
    @RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps

doc-test:
    @cargo test --locked --doc --workspace

# Regenerate tests/sdk-vectors; `just test` fails while the committed files are stale.
sdk-vectors:
    @UPDATE_SDK_VECTORS=1 cargo nextest run --locked -p piquel-common --test sdk_vectors

# Regenerate the TypeScript SDK's wire types, packages/auth/src/protocol.ts, from
# piquel_common::protocol; `just test` fails while the committed file is stale.
sdk-types:
    @UPDATE_SDK_TYPES=1 cargo nextest run --locked -p piquel-common --lib protocol::typescript

audit: rust::audit web::audit
