format:
    @cargo fmt --all

lint:
    @cargo clippy --workspace

check:
    @cargo check --workspace --all-targets

test:
    @cargo nextest run --workspace

doc-test:
    @cargo test --doc --workspace

migrate:
    @cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    @cargo sqlx prepare --workspace
