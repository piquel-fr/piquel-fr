# Configuration

auth-service and piquel-web read their configuration from environment variables
at startup, and refuse to start when one is missing or invalid. The lists below
are generated from the code that reads each variable. A secret is never set
directly: its variable says where to read it, through `env://NAME` or
`file:///absolute/path`.

## auth-service

{{#include variables/auth-service.md}}

### Telemetry

Both services read the standard OpenTelemetry variables, such as
`OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_RESOURCE_ATTRIBUTES`, and `RUST_LOG`:
see [telemetry](../architecture/telemetry.md#configuration).

## Generating keys

Generate the key-encryption key or a token digest key with `just auth generate-secret /absolute/path` (uses the
OpenSSL CLI; piqueld generates its own, see [deploying](deploying.md#secrets)), and an audit key
with `openssl rand -hex 32 > /absolute/path/audit-key`. Keep them across
restarts, and give every replica the same ones. To change the token digest key,
follow [changing the token digest key](signing-keys.md#changing-the-token-digest-key).

## Running auth-service

Apply migrations explicitly, then serve. Deployed images run the same
`migrate` and `serve` subcommands of the executable directly.

```sh
just db migrate
just auth serve
```

## piquel.fr

`piquel-web` serves piquel.fr: the homepage, the privacy policy at `/privacy` and
the terms of service at `/terms`. It keeps no state and needs no database or
secret. It relies on auth only to sign people in: it links auth's pages, and
redirects every other path, with its query, to the same one on auth. Its
`/health` answers `204` for piqueld's probe. Its telemetry's `service.name` is
`piquel-web`.

{{#include variables/piquel-web.md}}

The policies are HTML in `apps/web/assets/policies/`. Keep them true to what the
code does: a change to what auth stores, keeps or shares changes them too.
