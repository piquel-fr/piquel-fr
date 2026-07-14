format:
    cargo fmt --all

check:
    cargo check --workspace --all-targets

test:
    @cargo nextest run --workspace

migrate:
    cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    cargo sqlx prepare --workspace
