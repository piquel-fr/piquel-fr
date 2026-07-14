format:
    cargo fmt --all

check:
    cargo check --workspace --all-targets

test:
    cargo test --workspace

migrate:
    cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    cargo sqlx prepare --workspace
