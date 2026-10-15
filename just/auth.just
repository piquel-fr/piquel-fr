set working-directory := '..'

# Run an auth-service subcommand with the caller's configuration.
[positional-arguments]
run *ARGS:
    @cargo run --locked -p auth-service -- "$@"

# Build the auth pages the binary embeds, then serve.
serve:
    @just web build-auth
    @just auth run serve

[positional-arguments]
invite *ARGS:
    @just auth run invite "$@"

# Print a random secret, e.g. for a confidential OIDC client.
secret:
    @just auth run secret

# Write a new RSA signing key; refuses to overwrite an existing file.
generate-key PATH:
    #!/usr/bin/env bash
    set -euo pipefail
    path={{ quote(PATH) }}
    if [[ -e "$path" ]]; then echo "$path already exists" >&2; exit 1; fi
    umask 077
    mkdir -p "$(dirname "$path")"
    key_tmp=$(mktemp "$path.XXXXXX")
    trap 'rm -f "$key_tmp"' EXIT
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$key_tmp"
    mv -n "$key_tmp" "$path"
