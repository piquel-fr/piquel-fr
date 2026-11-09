set working-directory := '..'

# Uses a scratch cluster unless TEST_DATABASE_URL names a disposable database.
# Run the database tests, then check the query cache against the tested schema.
[positional-arguments]
test *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -z "${TEST_DATABASE_URL:-}" ]]; then exec just db scratch just db test "$@"; fi
    cargo nextest run --locked -p auth-service -p sourceorigin-repository --run-ignored all "$@"
    just db prepare-check

# Catches a migration that renames a column a cached query uses, and a cached
# query the code no longer uses. `test` runs it last; CI runs it after its
# database tests migrate the database.
# Fail unless the query cache matches exactly what the code compiles against
# TEST_DATABASE_URL's migrated schema.
prepare-check:
    #!/usr/bin/env bash
    set -euo pipefail
    DATABASE_URL="${TEST_DATABASE_URL:?TEST_DATABASE_URL must name a migrated database}" just db _prepare --check
    # --check fails on a missing or changed query but only warns about a leftover
    # one. It regenerates the cache into the target directory first, so compare
    # that with the committed cache; a sqlx-cli that moves it fails here too.
    target=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
    if ! diff -r crates/database/.sqlx "$target/sqlx-prepare-check"; then
        echo 'prepare check failed: crates/database/.sqlx differs from the regenerated cache; run `just db prepare`' >&2
        exit 1
    fi

# Regenerate crates/database/.sqlx from a scratch cluster; commit the result.
prepare:
    @just db scratch just db _prepare

# Test targets and the `test-util` feature are included so checked queries
# compiled only for tests are cached too.
[positional-arguments]
_prepare *ARGS:
    @cd crates/database && cargo sqlx prepare "$@" -- --all-targets --all-features

# DATABASE_URL, TEST_DATABASE_URL and libpq's PG* variables point at the cluster,
# which listens only on a socket under /tmp (socket paths are limited to about 100
# bytes, which a long TMPDIR can exceed). Needs the PostgreSQL 18 server binaries.
# Run a command against a throwaway migrated cluster, e.g. `just db scratch -- psql`.
# Every test fixture pools a few connections, and nextest runs one test per core,
# so the cluster allows more than PostgreSQL's hundred.
[positional-arguments]
scratch *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ "${1-}" == -- ]] && shift
    # PostgreSQL 18 finds its share directory next to the invoked path, so call
    # the real binaries rather than profile symlinks (Nix, Homebrew).
    bin=$(dirname "$(realpath "$(command -v initdb)")")
    dir=$(mktemp -d /tmp/sourceorigin-db.XXXXXX)
    trap '"$bin/pg_ctl" --pgdata "$dir/data" --mode immediate stop >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
    "$bin/initdb" --pgdata "$dir/data" --username sourceorigin --auth trust --no-sync >/dev/null
    "$bin/pg_ctl" --pgdata "$dir/data" --log "$dir/postgres.log" --wait \
        --options "-c listen_addresses='' -c unix_socket_directories='$dir' -c fsync=off -c max_connections=400" \
        start >/dev/null
    export DATABASE_URL="postgres://sourceorigin@localhost/postgres?host=$dir"
    export TEST_DATABASE_URL="$DATABASE_URL" PGHOST="$dir" PGUSER=sourceorigin PGDATABASE=postgres
    sqlx migrate run --source crates/database/migrations >/dev/null
    "$@"

# The sqlx-cli build the recipes here use; `just install-tools` installs it too.
install-sqlx:
    @cargo install --locked sqlx-cli --no-default-features --features rustls,postgres

# Apply migrations with the caller's auth configuration.
migrate:
    @just auth run migrate
