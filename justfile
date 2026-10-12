# Validate by default; database and browser tests remain explicit.
default: validate

validate: fmt-check lint check test doc-test audit

install:
    @pnpm install --frozen-lockfile

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

# TEST_DATABASE_URL must identify a disposable loopback database.
[positional-arguments]
test-database *ARGS:
    @test -n "${TEST_DATABASE_URL:?Set a disposable TEST_DATABASE_URL}"
    @cargo nextest run --locked -p auth-service -p piquel-repository --run-ignored all "$@"

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

migrate:
    @just run migrate

[positional-arguments]
invite *ARGS:
    @just run invite create "$@"

# Generate once; never rotate a configured or existing local key on restart.
generate-dev-key:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "${AUTH_KEY_PROVIDER:-}" || -f .dev/signing-key.pem ]]; then exit 0; fi
    umask 077
    mkdir -p .dev
    key_tmp=$(mktemp .dev/signing-key.XXXXXX)
    trap 'rm -f "$key_tmp"' EXIT
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$key_tmp"
    mv -n "$key_tmp" .dev/signing-key.pem

# Build embedded assets and apply migrations before the dev servers start.
dev-prepare: _dev-check build-auth-web generate-dev-key
    @just _dev-run migrate

# Restart the real backend, applying new migrations before each run.
dev-rust: dev-prepare
    @cargo watch -w apps/auth-service -w crates -w Cargo.toml -w Cargo.lock -w rust-toolchain.toml -s 'just _dev-run migrate' -s 'just _dev-run serve'

# Requires dev-rust in another terminal when used on its own.
dev-auth:
    @pnpm --filter @piquel/auth-web dev

dev-settings:
    @VITE_AUTH_ORIGIN=http://localhost:3000 pnpm --filter @piquel/piquel-web dev --host localhost --port 4173 --strictPort

# Full local development; stop all sessions on Ctrl+C or a server failure.
dev: dev-prepare
    #!/usr/bin/env bash
    set -euo pipefail
    child_pids=()
    cleanup() {
        trap - EXIT INT TERM
        for child in "${child_pids[@]}"; do
            pkill -TERM --session "$child" 2>/dev/null || true
        done
        # cargo-watch creates its own process groups. Clean up entire sessions,
        # including descendants whose supervisor has already exited.
        deadline=$((SECONDS + 5))
        while ((SECONDS < deadline)); do
            running=false
            for child in "${child_pids[@]}"; do
                if pgrep --session "$child" >/dev/null; then running=true; break; fi
            done
            "$running" || break
            sleep 0.1
        done
        for child in "${child_pids[@]}"; do
            pkill -KILL --session "$child" 2>/dev/null || true
        done
        wait 2>/dev/null || true
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for recipe in dev-rust dev-auth dev-settings; do
        setsid just --no-deps "$recipe" &
        child_pids+=("$!")
    done
    wait -n "${child_pids[@]}"

[private]
_dev-check:
    @test -n "${AUTH_DATABASE_URL:?Set AUTH_DATABASE_URL to a local development PostgreSQL database}"
    @cargo watch --version
    @command -v setsid pkill pgrep >/dev/null

# Fixed browser origins match Vite. All other auth settings remain caller-owned.
[positional-arguments]
[private]
_dev-run *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    export AUTH_DEVELOPMENT_MODE=true
    export AUTH_PUBLIC_BASE_URL=http://localhost:3000
    export AUTH_PUBLIC_LISTENER=127.0.0.1:8080
    export AUTH_SETTINGS_URL=http://localhost:4173/settings
    export AUTH_KEY_PROVIDER="${AUTH_KEY_PROVIDER:-file://{{ justfile_directory() }}/.dev/signing-key.pem}"
    exec cargo run --locked -p auth-service -- "$@"

# `--slot NAME` keeps several previews of one branch.
# Deploy this worktree, uncommitted changes included, to its preview; print its URLs.
preview *args:
    piquelctl --timeout 30m preview deploy piquel-fr --local {{args}}
    piquelctl --timeout 10m preview wait piquel-fr "$(git branch --show-current)" {{args}} --ready routes

# Delete this worktree's preview with its database.
preview-delete *args:
    piquelctl preview delete piquel-fr "$(git branch --show-current)" {{args}} --yes
