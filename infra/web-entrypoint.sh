#!/bin/sh
set -eu

# Each environment has its own auth origin. nginx serves it as /config.json and
# in the CSP header (see nginx.conf), so it must be a bare HTTPS origin. `case`
# matches the whole value, newlines included.
case "${AUTH_ORIGIN:-}" in
    https:// | https://*[!a-z0-9.:-]*) valid=false ;;
    https://*) valid=true ;;
    *) valid=false ;;
esac
if [ "$valid" = false ]; then
    echo "AUTH_ORIGIN must be an https:// origin, got '${AUTH_ORIGIN:-}'" >&2
    exit 1
fi
printf 'set $auth_origin "%s";\n' "$AUTH_ORIGIN" > /tmp/auth-origin.conf
exec nginx -g 'daemon off;'
