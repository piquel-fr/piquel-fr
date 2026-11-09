set working-directory := '..'

# Run an auth-service subcommand with the caller's configuration.
[positional-arguments]
run *ARGS:
    @cargo run --locked -p auth-service -- "$@"

# Serve with the caller's configuration.
serve:
    @just auth run serve

# Create, list or revoke signup invitations, e.g. `just auth invite create --reason "For Jane"`.
[positional-arguments]
invite *ARGS:
    @just auth run invite "$@"

# Search, show, disable or reactivate accounts, e.g. `just auth user show alice`.
[positional-arguments]
user *ARGS:
    @just auth run user "$@"

# End sessions, e.g. `just auth session revoke-all alice --reason "Phone stolen"`.
[positional-arguments]
session *ARGS:
    @just auth run session "$@"

# Page through, verify or prune the audit history, e.g. `just auth audit list --user alice`.
[positional-arguments]
audit *ARGS:
    @just auth run audit "$@"

# Read or change one account's settings on its owner's behalf, e.g. `just auth account alice passkeys list`.
[positional-arguments]
account *ARGS:
    @just auth run account "$@"

# Register, inspect and change OIDC clients, e.g. `just auth client list`.
[positional-arguments]
client *ARGS:
    @just auth run client "$@"

# List, retry or cancel outbound deliveries, e.g. `just auth deliveries list --status failed`.
[positional-arguments]
deliveries *ARGS:
    @just auth run deliveries "$@"

# Grant, revoke or list administrators, e.g. `just auth admin list`.
[positional-arguments]
admin *ARGS:
    @just auth run admin "$@"

# Check or rename handles, e.g. `just auth handle check`.
[positional-arguments]
handle *ARGS:
    @just auth run handle "$@"

# Point auth at the server with AUTH_SMTP_URL=smtp://localhost:1025. Stops with Ctrl-C.
# A local Mailpit SMTP server, with its mail at http://localhost:8025.
mailpit:
    @docker run --rm --name sourceorigin-mailpit -p 127.0.0.1:1025:1025 -p 127.0.0.1:8025:8025 axllent/mailpit

# Inspect, rotate, revoke and import signing keys, e.g. `just auth keys list`.
[positional-arguments]
keys *ARGS:
    @just auth run keys "$@"

# The secret is 32 random bytes in unpadded base64url. Refuses to overwrite an existing file.
# Write a secret for AUTH_KEY_ENCRYPTION_KEY or AUTH_TOKEN_DIGEST_KEY to PATH.
generate-secret PATH:
    #!/usr/bin/env bash
    set -euo pipefail
    path={{ quote(PATH) }}
    if [[ -e "$path" ]]; then echo "$path already exists" >&2; exit 1; fi
    umask 077
    mkdir -p "$(dirname "$path")"
    secret_tmp=$(mktemp "$path.XXXXXX")
    trap 'rm -f "$secret_tmp"' EXIT
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > "$secret_tmp"
    mv -n "$secret_tmp" "$path"
