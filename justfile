format:
    cargo fmt --all

check:
    cargo check --workspace --all-targets

test:
    cargo test --workspace

test-database:
    cargo test -p piquel-repository --test identity -- --ignored --test-threads=1

check-web:
    pnpm check:web

test-web:
    pnpm test:web

ci:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace
    pnpm check:web
    pnpm test:web

migrate:
    cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    cargo sqlx prepare --workspace
