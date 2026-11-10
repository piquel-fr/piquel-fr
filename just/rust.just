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

# Advisories, licenses, wildcard requirements and sources other than crates.io,
# as deny.toml configures them. Every feature is on, so the audit covers what
# the SDKs' features pull in even when no workspace crate enables them.
audit:
    @cargo deny --all-features check

# Build auth-service and sourceorigin-web; pass `--release` for release.
[positional-arguments]
build *ARGS:
    @cargo build --locked -p auth-service -p sourceorigin-web "$@"
