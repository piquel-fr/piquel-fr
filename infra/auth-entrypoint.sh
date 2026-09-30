#!/bin/sh
set -eu

# Piqueld has no one-shot jobs. Apply migrations before starting the sole replica.
if [ "${1:-}" = "serve" ]; then
    auth-service migrate
fi
exec auth-service "$@"
