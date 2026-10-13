# Validate by default; database and browser tests remain explicit.
default: validate

# Scratch PostgreSQL clusters, database tests, the SQLx query cache and migrations.
mod db 'just/db.just'

validate: fmt-check lint check test doc-test audit

install:
    @pnpm install --frozen-lockfile

# Cargo tools used by the test, audit and database recipes.
install-tools:
    @cargo install --locked cargo-nextest cargo-deny
    @cargo install --locked sqlx-cli --no-default-features --features rustls,postgres

# Build static browser assets before embedding them in the release executable.
build: build-web
    @cargo build --locked --release -p auth-service

build-debug: build-auth-web
    @cargo build --locked -p auth-service

build-web: build-auth-web build-settings-web

build-auth-web:
    @pnpm --filter @piquel/auth-web build

build-settings-web:
    @pnpm --filter @piquel/piquel-web build

# Refresh SvelteKit's generated types/config. Cargo generates its own asset table.
generate:
    @pnpm --filter @piquel/auth-web --filter @piquel/piquel-web -r exec svelte-kit sync

alias format := fmt

fmt: fmt-rust fmt-web

fmt-rust:
    @cargo fmt --all

fmt-web:
    @pnpm format

fmt-check: fmt-check-rust fmt-check-web

fmt-check-rust:
    @cargo fmt --all -- --check

fmt-check-web:
    @pnpm format:check

# Warnings fail both linters, like `-D warnings`.
lint: lint-rust lint-web

lint-rust:
    @cargo clippy --locked --workspace --all-targets -- -D warnings

# Type-aware linting reads SvelteKit's generated tsconfig files.
lint-web: generate
    @pnpm lint

check: check-rust check-web

check-rust:
    @cargo check --locked --workspace --all-targets

check-web:
    @pnpm check

# Extra nextest arguments can select a package or test expression.
[positional-arguments]
test *ARGS='--workspace':
    @cargo nextest run --locked "$@"

doc-test:
    @cargo test --locked --doc --workspace

# Requires running auth/settings servers; see tests/browser/README.md.
[positional-arguments]
test-browser *ARGS:
    @pnpm test:browser "$@"

audit: deny audit-web

deny:
    @cargo deny check advisories licenses

audit-web:
    @pnpm audit

# Run an auth-service subcommand with the caller's configuration.
[positional-arguments]
run *ARGS:
    @cargo run --locked -p auth-service -- "$@"

serve: build-auth-web
    @just run serve

[positional-arguments]
invite *ARGS:
    @just run invite "$@"

# Print a random secret, e.g. for a confidential OIDC client.
secret:
    @just run secret

# Write a new RSA signing key; refuses to overwrite an existing file.
generate-key PATH:
    #!/usr/bin/env bash
    set -euo pipefail
    path={{ quote(PATH) }}
    if [[ -e "$path" ]]; then echo "$path already exists" >&2; exit 1; fi
    umask 077
    mkdir -p "$(dirname "$path")"
    key_tmp=$(mktemp "$path.XXXXXX")
    trap 'rm -f "$key_tmp"' EXIT
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$key_tmp"
    mv -n "$key_tmp" "$path"

# `--slot NAME` keeps several previews of one branch.
# Deploy this worktree, uncommitted changes included, to its preview; print its URLs.
preview *args:
    piquelctl --timeout 30m preview deploy piquel-fr --local {{args}}
    piquelctl --timeout 10m preview wait piquel-fr "$(git branch --show-current)" {{args}} --ready routes

# Delete this worktree's preview with its database.
preview-delete *args:
    piquelctl preview delete piquel-fr "$(git branch --show-current)" {{args}} --yes
