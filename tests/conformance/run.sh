#!/usr/bin/env bash
# `just conformance [TARGET]`: runs the OpenID conformance suite and compares every
# result with expected.json. See README.md.
#
#   (none)   the suite on this machine, against a local auth this script builds
#            and starts with its own PostgreSQL and Mailpit
#   <url>    the suite on this machine, against auth at <url>, such as a preview,
#            whose CLI CONFORMANCE_CLI runs
#   release  the OpenID Foundation's hosted suite, against staging's current
#            release promoted into the public `conformance` environment, stopped
#            afterwards; then offers to promote that release to production
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

# Results, screenshots and logs, which CI uploads.
export CONFORMANCE_OUTPUT=${CONFORMANCE_OUTPUT:-$root/target/conformance}
rm -rf "$CONFORMANCE_OUTPUT"
mkdir -p "$CONFORMANCE_OUTPUT"

# Steps undoing what the script started, run on exit, last first.
cleanup=()
finish() {
    for ((i = ${#cleanup[@]} - 1; i >= 0; i--)); do eval "${cleanup[i]}" || true; done
    cleanup=()
}
trap finish EXIT

# Starts the suite on this machine, with a local auth's services under `local`.
start_suite() {
    compose=(docker compose --file "$here/docker-compose.yml" "$@")
    cleanup+=("${compose[*]} logs --no-color > '$CONFORMANCE_OUTPUT/compose.log' 2>&1; ${compose[*]} down --volumes > /dev/null 2>&1")
    "${compose[@]}" up --detach --wait --quiet-pull
}

# Builds and starts auth on this machine, at https://localhost:7443.
start_auth() {
    start_suite --profile local
    cargo build --locked -p auth-service
    secrets=$(mktemp -d)
    cleanup+=("rm -r '$secrets'")
    just auth generate-secret "$secrets/key-encryption-key"
    just auth generate-secret "$secrets/token-digest-key"
    openssl rand -hex 32 > "$secrets/audit-key"
    export AUTH_KEY_ENCRYPTION_KEY="file://$secrets/key-encryption-key"
    export AUTH_TOKEN_DIGEST_KEY="file://$secrets/token-digest-key"
    export AUTH_AUDIT_KEY_PROVIDER="file://$secrets/audit-key"
    # Back-channel logout tokens go to the suite on this machine, whose
    # certificate Caddy's certificate authority signed.
    until "${compose[@]}" cp caddy:/data/caddy/pki/authorities/local/root.crt "$secrets/caddy-root.crt" > /dev/null 2>&1; do sleep 1; done
    export AUTH_LOOPBACK_LOGOUT_CA="file://$secrets/caddy-root.crt"
    # migrate connects as the superuser and creates the role auth runs as.
    export AUTH_DATABASE_OWNER_URL='postgres://postgres:conformance@127.0.0.1:7432/postgres?sslmode=disable'
    export AUTH_DATABASE_URL='postgres://sourceorigin_auth@127.0.0.1:7432/postgres?sslmode=disable'
    export AUTH_DATABASE_PASSWORD=env://CONFORMANCE_DATABASE_PASSWORD
    export CONFORMANCE_DATABASE_PASSWORD=conformance
    export AUTH_PUBLIC_BASE_URL=https://localhost:7443
    export AUTH_PUBLIC_LISTENER=127.0.0.1:7080
    # Signup needs an invitation, as in production.
    export AUTH_INVITE_REQUIRED=true
    # The suite signs in again for every test, from one address.
    export AUTH_REQUESTS_PER_MINUTE=1000
    export CONFORMANCE_AUTH_URL=$AUTH_PUBLIC_BASE_URL
    export CONFORMANCE_CLI="$root/target/debug/auth-service --operator conformance"
    export CONFORMANCE_BACKCHANNEL=1
    export AUTH_SMTP_URL=smtp://127.0.0.1:7025
    export CONFORMANCE_MAIL_URL=http://127.0.0.1:7026

    target/debug/auth-service migrate
    target/debug/auth-service serve > "$CONFORMANCE_OUTPUT/auth.log" 2>&1 &
    cleanup+=("kill $!")
    curl -kfs --retry 30 --retry-delay 1 --retry-all-errors "$CONFORMANCE_AUTH_URL/health/ready" >/dev/null
}

# Promotes staging's current release into `conformance`, runs the hosted suite
# against it with the expectations of the commit it was built from, stops it, and
# offers to promote the same release to production. piquelctl asks before each
# promotion.
release() {
    : "${CONFORMANCE_SUITE_TOKEN:?set CONFORMANCE_SUITE_TOKEN to where your certification.openid.net token is, such as file:///path}"
    export CONFORMANCE_SUITE_URL=https://www.certification.openid.net
    local current deployment commit
    current=$(piquelctl --json env history sourceorigin staging --limit 20 | node -e '
        const { items } = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
        const current = items.find((item) => item.current_target && item.last_successful);
        if (!current) throw new Error("staging has no current, successful deployment");
        console.log(current.operation.id, current.template.spec.manifest.repository.commit);')
    read -r deployment commit <<< "$current"
    echo "Testing staging's deployment $deployment, built from $commit."

    # The expectations, and the plans, of the commit under test.
    git fetch --quiet origin "$commit"
    local tested
    tested=$(mktemp -d)
    cleanup+=("rm -r '$tested'")
    git show "$commit:tests/conformance/expected.json" > "$tested/expected.json"
    git show "$commit:tests/conformance/plans.json" > "$tested/plans.json"
    export CONFORMANCE_EXPECTED="$tested/expected.json" CONFORMANCE_PLANS="$tested/plans.json"

    cleanup+=("piquelctl env stop sourceorigin conformance --yes")
    piquelctl --timeout 30m env promote sourceorigin conformance --deployment "$deployment"
    export CONFORMANCE_AUTH_URL=https://auth-conformance.sourceorigin.dev
    export CONFORMANCE_CLI="piquelctl app exec sourceorigin auth --env conformance -- auth-service --operator conformance"
    # The hosted suite is public, so auth posts back-channel logout tokens to it.
    export CONFORMANCE_BACKCHANNEL=1
    curl -fs --retry 30 --retry-delay 2 --retry-all-errors "$CONFORMANCE_AUTH_URL/health/ready" >/dev/null

    node "$here/driver.ts"
    finish
    piquelctl --timeout 30m env promote sourceorigin production --deployment "$deployment"
}

case "${1:-}" in
    "")
        start_auth
        node "$here/driver.ts"
        ;;
    release)
        release
        ;;
    *)
        export CONFORMANCE_AUTH_URL=$1
        : "${CONFORMANCE_CLI:?set CONFORMANCE_CLI to a command that runs auth-service on the deployment}"
        start_suite
        node "$here/driver.ts"
        ;;
esac
