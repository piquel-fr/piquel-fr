# Build browser assets before compiling the single auth executable.
build:
    pnpm build
    cargo build --release -p auth-service

format:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets
    pnpm check

check:
    cargo check --workspace --all-targets

test:
    cargo nextest run --workspace

# TEST_DATABASE_URL must identify a disposable local database.
test-database:
    test -n "${TEST_DATABASE_URL:?Set a disposable TEST_DATABASE_URL}"
    cargo nextest run -p auth-service -p piquel-repository --run-ignored all

migrate:
    cargo run -p auth-service -- migrate

audit:
    cargo deny check advisories licenses
    pnpm audit

# `--slot NAME` keeps several previews of one branch.
# Deploy this worktree, uncommitted changes included, to its preview; print its URLs.
preview *args:
    piquelctl --timeout 30m preview deploy piquel-fr --local {{args}}
    piquelctl --timeout 10m preview wait piquel-fr "$(git branch --show-current)" {{args}} --ready routes

# Delete this worktree's preview with its database.
preview-delete *args:
    piquelctl preview delete piquel-fr "$(git branch --show-current)" {{args}} --yes
