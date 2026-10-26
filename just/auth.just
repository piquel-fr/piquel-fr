set working-directory := '..'

# Run an auth-service subcommand with the caller's configuration.
[positional-arguments]
run *ARGS:
    @cargo run --locked -p auth-service -- "$@"

# Build the SDK script the binary embeds, then serve.
serve:
    @just web build
    @just auth run serve

# Create, list or revoke signup invitations, e.g. `just auth invite create --expires-in 7d`.
[positional-arguments]
invite *ARGS:
    @just auth run invite "$@"

# Search, show, disable or reactivate accounts, e.g. `just auth user show alice`.
[positional-arguments]
user *ARGS:
    @just auth run user "$@"

# End sessions, e.g. `just auth session revoke-all alice`.
[positional-arguments]
session *ARGS:
    @just auth run session "$@"

# Page through the audit history, e.g. `just auth audit --user alice`.
[positional-arguments]
audit *ARGS:
    @just auth run audit "$@"

# Read or change one account's settings on its owner's behalf, e.g.
# `just auth account alice passkeys list`.
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

# Grant, revoke or list administrators, e.g. `just auth admin grant alice`.
[positional-arguments]
admin *ARGS:
    @just auth run admin "$@"

# Check or rename handles, e.g. `just auth handle check`.
[positional-arguments]
handle *ARGS:
    @just auth run handle "$@"

# A local Mailpit SMTP server: set AUTH_SMTP_URL=smtp://localhost:1025 and read
# the mail at http://localhost:8025. Stops with Ctrl-C.
mailpit:
    @docker run --rm --name piquel-mailpit -p 127.0.0.1:1025:1025 -p 127.0.0.1:8025:8025 axllent/mailpit

# Inspect, rotate, revoke and import signing keys, e.g. `just auth keys list`.
[positional-arguments]
keys *ARGS:
    @just auth run keys "$@"

# Write 32 random bytes in unpadded base64url, as AUTH_KEY_ENCRYPTION_KEY and
# AUTH_TOKEN_DIGEST_KEY take them; refuses to overwrite an existing file.
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
