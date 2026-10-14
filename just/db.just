set working-directory := '..'

# Uses a scratch cluster unless TEST_DATABASE_URL names a disposable database.
# Run the database tests, then check the query cache against the tested schema.
[positional-arguments]
test *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -z "${TEST_DATABASE_URL:-}" ]]; then exec just db scratch just db test "$@"; fi
    cargo nextest run --locked -p auth-service -p piquel-repository --run-ignored all "$@"
    DATABASE_URL="$TEST_DATABASE_URL" just db _prepare --check

# Regenerate crates/database/.sqlx from a scratch cluster; commit the result.
prepare:
    @just db scratch just db _prepare

# Test targets and the `test-support` feature are included so checked queries
# compiled only for tests are cached too.
[positional-arguments]
_prepare *ARGS:
    @cd crates/database && cargo sqlx prepare "$@" -- --all-targets --all-features

# DATABASE_URL, TEST_DATABASE_URL and libpq's PG* variables point at the cluster,
# which listens only on a socket under /tmp (socket paths are limited to about 100
# bytes, which a long TMPDIR can exceed). Needs the PostgreSQL 18 server binaries.
# Run a command against a throwaway migrated cluster, e.g. `just db scratch -- psql`.
[positional-arguments]
scratch *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ "${1-}" == -- ]] && shift
    # PostgreSQL 18 finds its share directory next to the invoked path, so call
    # the real binaries rather than profile symlinks (Nix, Homebrew).
    bin=$(dirname "$(realpath "$(command -v initdb)")")
    dir=$(mktemp -d /tmp/piquel-db.XXXXXX)
    trap '"$bin/pg_ctl" --pgdata "$dir/data" --mode immediate stop >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
    "$bin/initdb" --pgdata "$dir/data" --username piquel --auth trust --no-sync >/dev/null
    "$bin/pg_ctl" --pgdata "$dir/data" --log "$dir/postgres.log" --wait \
        --options "-c listen_addresses='' -c unix_socket_directories='$dir' -c fsync=off" \
        start >/dev/null
    export DATABASE_URL="postgres://piquel@localhost/postgres?host=$dir"
    export TEST_DATABASE_URL="$DATABASE_URL" PGHOST="$dir" PGUSER=piquel PGDATABASE=postgres
    sqlx migrate run --source crates/database/migrations >/dev/null
    "$@"

# Apply migrations with the caller's auth configuration.
migrate:
    @just run migrate
