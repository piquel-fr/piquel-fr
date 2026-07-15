format:
    @cargo fmt --all

lint:
    @cargo clippy --workspace

check:
    @cargo check --workspace --all-targets

test:
    @cargo nextest run --workspace

test-database:
    @echo "No test database is configured; database tests will not run."

doc-test:
    @cargo test --doc --workspace

migrate:
    @cargo run -p piquel-repository --bin migrate

prepare-sqlx:
    @cargo sqlx prepare --workspace

validate: lint check test test-database doc-test
