# Validate by default; database and browser tests remain explicit.
default: validate

# Rust formatting, linting, checks, audits and the auth-service and sourceorigin-web builds.
mod rust 'just/rust.just'

# Web formatting, linting, type checks, the TypeScript SDK's tests and the browser tests.
mod web 'just/web.just'

# Scratch PostgreSQL clusters, database tests, the SQLx query cache and migrations.
mod db 'just/db.just'

# auth-service commands with the caller's configuration, and secret generation.
mod auth 'just/auth.just'

# piqueld previews of this worktree, and a local telemetry backend.
mod infra 'just/infra.just'

# The documentation book: `just docs` builds and checks it, `just docs serve` previews it.
mod docs 'just/docs.just'

alias format := fmt
alias preview := infra::preview
alias preview-delete := infra::preview-delete

validate: fmt-check lint unused check test web::test doc doc-test audit

install:
    @pnpm install --frozen-lockfile

# Cargo tools used by the test, coverage, audit, database and docs recipes. CI
# installs mdBook and lychee at the same versions.
install-tools: db::install-sqlx
    @cargo install --locked cargo-nextest cargo-llvm-cov cargo-deny cargo-machete cargo-semver-checks
    @cargo install --locked mdbook@0.5.4 lychee@0.24.2

# Publish the SDKs: the Rust crates to crates.io, then @sourceorigin/auth to npm,
# skipping versions already published; see docs/dev/releasing.md. `--dry-run`
# packages and builds them without uploading; `--allow-dirty` allows uncommitted
# changes.
[positional-arguments]
publish *ARGS:
    @cargo xtask publish "$@"

# Release the workspace version from the latest main: publish the SDKs, tag the
# commit, create its GitHub release and close its milestone; see
# docs/dev/releasing.md. `--dry-run` runs the checks and the publish dry run, and
# only prints the other steps and the release notes.
[positional-arguments]
release *ARGS:
    @cargo xtask release "$@"

# The release auth-service executable.
build: (rust::build "--release")

fmt: rust::fmt web::fmt

fmt-check: rust::fmt-check web::fmt-check

# Warnings fail both linters, like `-D warnings`.
lint: rust::lint web::lint

check: rust::check web::check

# Unused Rust dependencies, and unused web files, exports and dependencies.
unused: rust::unused web::unused

# Extra nextest arguments can select a package or test expression.
[positional-arguments]
test *ARGS='--workspace':
    @cargo nextest run --locked "$@"

# Rustdoc warnings, such as broken or private intra-doc links, fail the build.
doc:
    @RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps

doc-test:
    @cargo test --locked --doc --workspace

# Uses a scratch cluster unless TEST_DATABASE_URL names a disposable database,
# which the database tests leave migrated. Instrumented builds live in
# target/llvm-cov-target; `cargo llvm-cov report --html` renders the last run.
# Extra arguments go to `cargo llvm-cov nextest`; target/lcov.info has the
# coverage per line.
# Coverage per crate of every Rust test, database tests included.
[positional-arguments]
coverage *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -z "${TEST_DATABASE_URL:-}" ]]; then exec just db scratch just coverage "$@"; fi
    cargo llvm-cov nextest --locked --workspace --run-ignored all --lcov --output-path target/lcov.info "$@"
    # lcov names each source file by absolute path; its crate is the
    # apps/<name> or crates/<name> directory holding it.
    awk -v root="$PWD/" '
        function row(name, hit, lines, fn_hit, fns) {
            return sprintf("%-20s %6.2f%% of %6d lines   %6.2f%% of %5d functions", name, 100 * hit / lines, lines, 100 * fn_hit / fns, fns)
        }
        /^SF:/ { split(substr($0, length(root) + 4), path, "/"); crate = path[1] "/" path[2] }
        /^LF:/ { lf[crate] += substr($0, 4) } /^LH:/ { lh[crate] += substr($0, 4) }
        /^FNF:/ { ff[crate] += substr($0, 5) } /^FNH:/ { fh[crate] += substr($0, 5) }
        END {
            for (c in lf) { print row(c, lh[c], lf[c], fh[c], ff[c]) | "sort"; LH += lh[c]; LF += lf[c]; FH += fh[c]; FF += ff[c] }
            close("sort"); print row("workspace", LH, LF, FH, FF)
        }' target/lcov.info

# Without a target, it builds and starts auth itself, on PostgreSQL and Caddy in
# Docker. With a URL, such as a preview's, CONFORMANCE_CLI must run that
# deployment's CLI. `release` tests staging's release on the OpenID Foundation's
# hosted suite, then offers to promote it to production. Needs Docker and
# Playwright's Chromium; see tests/conformance/README.md.
# Run the OpenID conformance suite against auth, and compare with expected.json.
conformance TARGET='':
    @tests/conformance/run.sh {{ quote(TARGET) }}

# Regenerate tests/sdk-vectors; `just test` fails while the committed files are stale.
sdk-vectors:
    @UPDATE_SDK_VECTORS=1 cargo nextest run --locked -p sourceorigin-crypto --test sdk_vectors

# Regenerate the TypeScript SDK's wire types, packages/auth/src/protocol.ts, from
# sourceorigin_common::protocol; `just test` fails while the committed file is stale.
sdk-types:
    @UPDATE_SDK_TYPES=1 cargo nextest run --locked -p sourceorigin-common --lib protocol::typescript

audit: rust::audit web::audit
