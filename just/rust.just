set working-directory := '..'

check:
    @cargo check --locked --workspace --all-targets

fmt:
    @cargo fmt --all

fmt-check:
    @cargo fmt --all -- --check

lint:
    @cargo clippy --locked --workspace --all-targets -- -D warnings

# Dependencies a crate declares but never names, by cargo-machete.
unused:
    @cargo machete

audit:
    @cargo deny check advisories licenses

# Build auth-service and piquel-web; pass `--release` for release.
[positional-arguments]
build *ARGS:
    @cargo build --locked -p auth-service -p piquel-web "$@"
