set working-directory := '..'

check:
    @cargo check --locked --workspace --all-targets

fmt:
    @cargo fmt --all

fmt-check:
    @cargo fmt --all -- --check

lint:
    @cargo clippy --locked --workspace --all-targets -- -D warnings

audit:
    @cargo deny check advisories licenses

# Build auth-service after the auth pages it embeds; pass `--release` for release.
[positional-arguments]
build *ARGS:
    @just web build-auth
    @cargo build --locked -p auth-service "$@"
