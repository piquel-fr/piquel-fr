#!/bin/sh
set -eu

# Also support file-provisioned credentials when no URL is set in the environment.
if [ -z "${AUTH_DATABASE_URL:-}" ]; then
    AUTH_DATABASE_URL=$(cat /run/auth-config/database-url)
    export AUTH_DATABASE_URL
fi

# Piqueld has no one-shot jobs. Apply migrations before starting the sole replica.
if [ "${1:-}" = "serve" ]; then
    auth-service migrate
fi
exec auth-service "$@"
