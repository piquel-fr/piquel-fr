set working-directory := '..'

check:
    @cargo check --locked --workspace --all-targets

fmt:
    @cargo fmt --all

fmt-check:
    @cargo fmt --all -- --check

# The workspace pass unifies features, so a crate's own tests can compile only
# because another crate's dev-dependency enables a feature such as `test-util`.
# Linting each crate alone too catches that.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo clippy --locked --workspace --all-targets -- -D warnings
    for manifest in apps/*/Cargo.toml crates/*/Cargo.toml; do
        cargo clippy --locked --manifest-path "$manifest" --all-targets -- -D warnings
    done

# Dependencies a crate declares but never names, by cargo-machete.
unused:
    @cargo machete

audit:
    @cargo deny check advisories licenses

# Build auth-service and piquel-web; pass `--release` for release.
[positional-arguments]
build *ARGS:
    @cargo build --locked -p auth-service -p piquel-web "$@"
