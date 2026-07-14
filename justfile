format:
    cargo fmt --all

check:
    cargo check --workspace --all-targets

test:
    cargo test --workspace

test-database:
    cargo test -p piquel-repository --test identity -- --ignored --test-threads=1
    cargo test -p auth-service --test http_flow -- --ignored --test-threads=1
    cargo test -p auth-service --test rpc_flow -- --ignored --test-threads=1

check-web:
    pnpm check:web

test-web:
    pnpm test:web

test-browser:
    pnpm test:browser

ci:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace
    cargo test -p piquel-repository --test identity -- --ignored --test-threads=1
    cargo test -p auth-service --test http_flow -- --ignored --test-threads=1
    cargo test -p auth-service --test rpc_flow -- --ignored --test-threads=1
    pnpm check:web
    pnpm test:web
    pnpm test:browser
    cargo deny check advisories
    pnpm audit --audit-level=high

migrate:
    cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    cargo sqlx prepare --workspace
