#!/usr/bin/env bash
# `just conformance [AUTH_URL]`: runs the OpenID conformance suite against auth
# at AUTH_URL, whose CLI CONFORMANCE_CLI runs, or, without a URL, against a
# local auth it builds and starts with its own PostgreSQL. See README.md.
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
}
trap finish EXIT

compose=(docker compose --file "$here/docker-compose.yml")
[[ -z "${1:-}" ]] && compose+=(--profile local)
cleanup+=("${compose[*]} logs --no-color > '$CONFORMANCE_OUTPUT/compose.log' 2>&1; ${compose[*]} down --volumes > /dev/null 2>&1")
"${compose[@]}" up --detach --wait --quiet-pull

if [[ -n "${1:-}" ]]; then
    export CONFORMANCE_AUTH_URL=$1
    : "${CONFORMANCE_CLI:?set CONFORMANCE_CLI to a command that runs auth-service on the deployment}"
else
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
    export CONFORMANCE_LOCAL=1
    export AUTH_SMTP_URL=smtp://127.0.0.1:7025
    export CONFORMANCE_MAIL_URL=http://127.0.0.1:7026

    target/debug/auth-service migrate
    target/debug/auth-service serve > "$CONFORMANCE_OUTPUT/auth.log" 2>&1 &
    cleanup+=("kill $!")
    curl -kfs --retry 30 --retry-delay 1 --retry-all-errors "$CONFORMANCE_AUTH_URL/health/ready" >/dev/null
fi

node "$here/driver.ts"
