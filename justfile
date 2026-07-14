format:
    cargo fmt --all

check:
    cargo check --workspace --all-targets

test:
    cargo test --workspace

migrate database_url:
    DATABASE_URL={{database_url}} cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    cargo sqlx prepare --workspace
