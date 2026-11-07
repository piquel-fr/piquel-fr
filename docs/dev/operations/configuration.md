# Configuration

This page helps you change how auth-service and piquel-web are configured, in a
deployed environment or on your machine, and lists every variable they read.

Both read their configuration from environment variables at startup, and refuse
to start when one is missing or invalid. A secret is never set directly: its
variable says where to read it, through `env://NAME` or
`file:///absolute/path`.

## Change a setting in an environment

1. Change `infra/piqueld.toml`:
   - the `[spec.services.environment]` table of the `auth` or `web` service, for
     a value every deployment shares;
   - or a variable, under `[spec.environments.<name>.variables]` or
     `[spec.previews.variables]`, for a value one deployment sets.
2. Merge the change to `main`. Staging deploys it.
3. [Promote](deploying.md#promote-to-production) staging to apply it to
   production.

A value that names a secret, such as `AUTH_SMTP_PASSWORD`, points at the file
piqueld mounts. To change the secret itself, see [secrets](secrets.md).

## Generate a key

For a local configuration, generate the key-encryption key or a token digest
key:

```sh
just auth generate-secret /absolute/path/key-encryption-key
```

The recipe writes 32 random bytes as unpadded base64url text, with the OpenSSL
CLI, and refuses to overwrite a file. Generate an audit key with
`openssl rand -hex 32 > /absolute/path/audit-key`.

Keep the keys across restarts, and give every replica the same ones. piqueld
generates its own for each environment (see [secrets](secrets.md)). To change
the token digest key, follow
[changing the token digest key](signing-keys.md#change-the-token-digest-key).

## Run auth-service locally

Apply migrations, then serve:

```sh
just db migrate
just auth serve
```

Deployed images run the executable's same `migrate` and `serve` subcommands.

## auth-service

{{#include variables/auth-service.md}}

### Telemetry

Both services read the standard OpenTelemetry variables, such as
`OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_RESOURCE_ATTRIBUTES`, and `RUST_LOG`:
see [telemetry](../architecture/telemetry.md#configuration).

## piquel-web

`piquel-web` serves piquel.fr: the homepage, the privacy policy at `/privacy`
and the terms of service at `/terms`. It keeps no state, and needs no database
or secret. It relies on auth only to sign people in: it links auth's pages, and
redirects every other path, with its query, to the same one on auth (see
[piquel.fr](deploying.md#piquelfr)). Its `/health` answers `204` for piqueld's
probe, and its telemetry's `service.name` is `piquel-web`.

{{#include variables/piquel-web.md}}

The policies are HTML in `apps/web/assets/policies/`. Keep them true to what the
code does: a change to what auth stores, keeps or shares changes them too.
