format:
    @cargo fmt --all

lint:
    @cargo clippy --workspace

check:
    @cargo check --workspace --all-targets

test:
    @cargo nextest run --workspace

test-database:
    @cargo nextest run -p piquel-repository --test identity -- --ignored --test-threads=1

doc-test:
    @cargo test --doc --workspace

migrate:
    @cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    @cargo sqlx prepare --workspace

validate: lint check test test-database doc-test

