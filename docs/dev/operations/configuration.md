# Configuration

auth-service reads its configuration from environment variables at startup,
and refuses to start when one is missing or invalid. A value described as an
env/file reference names where a secret is read from instead of holding it:
`env://NAME` or `file:///absolute/path`.

## auth-service

| Variable | Meaning |
| --- | --- |
| `AUTH_DATABASE_URL` | PostgreSQL URL; TCP requires `sslmode=verify-full`, or an explicit `sslmode=disable` on a trusted private network; local Unix sockets are also supported |
| `AUTH_DATABASE_PASSWORD` | Optional env/file reference for the database password, when omitted from the URL |
| `AUTH_DATABASE_OWNER_URL`, `AUTH_DATABASE_OWNER_PASSWORD` | Optional schema owner `migrate` connects as instead, in the same formats. It then creates or resets the role `AUTH_DATABASE_URL` names, with the `AUTH_DATABASE_PASSWORD` password and only row access to the app tables. The owner must be a superuser |
| `AUTH_PUBLIC_BASE_URL` | Exact auth origin, normally `https://auth.piquel.fr` |
| `AUTH_TRUSTED_PROXIES` | Optional comma-separated proxy peer IPs or CIDRs; these peers must overwrite `X-Forwarded-For` with one client IP. Defaults to piqueld's `PIQUELD_INGRESS_PROXIES` |
| `AUTH_REQUESTS_PER_MINUTE` | Optional requests a client may make a minute in each rate category (pages, sign-in, tokens, …); defaults to `120` |
| `AUTH_PUBLIC_LISTENER` | Listener address; defaults to `127.0.0.1:8080` |
| `AUTH_ADMIN_LISTENER`, `AUTH_ADMIN_ORIGIN` | Optional address of the admin dashboard's listener, e.g. `0.0.0.0:8081`, and the dashboard's origin, e.g. `https://admin.piquel.fr`, set together. Only a private route may reach the listener. Without them, auth serves no dashboard |
| `AUTH_WEB_ORIGIN` | piquel.fr's origin, whose privacy policy and terms every page links and discovery advertises; defaults to `https://piquel.fr` |
| `AUTH_KEY_ENCRYPTION_KEY` | Required env/file reference to the key that seals [signing keys](signing-keys.md) in the database: 32 bytes as unpadded base64url text. A trailing newline is ignored |
| `AUTH_TOKEN_DIGEST_KEY` | Required env/file reference to the key under which refresh tokens, authorization codes and pending logins are stored as HMAC digests. Its raw bytes are the key, at least 32 of them. Email verification links and recovery links derive from it too |
| `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` | Optional env/file reference to another token digest key, accepted but never used for new digests: the next key, or the old one (see [changing the token digest key](signing-keys.md#changing-the-token-digest-key)) |
| `AUTH_AUDIT_KEY_PROVIDER` | Required env/file reference to the key that signs audit checkpoints: a 32-byte Ed25519 seed as 64 hex characters. See [audit history](../security/audit-history.md) |
| `AUTH_INVITE_REQUIRED` | `true` by default; set `false` to allow public registration |
| `AUTH_GITHUB_CLIENT_ID`, `AUTH_GITHUB_CLIENT_SECRET` | Both required to enable GitHub; secret is an env/file reference. An empty client ID turns GitHub off, and its secret is then not read. See [sign-in providers](sign-in-providers.md) |
| `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` | Both required to enable Google, as for GitHub |
| `AUTH_SMTP_URL` | Optional SMTP relay, `smtps://USER@HOST:465` (implicit TLS) or `smtp://USER@HOST:587` (STARTTLS required); unset disables email. Only a loopback host, such as a local Mailpit, may be reached without TLS |
| `AUTH_SMTP_PASSWORD` | Env/file reference for the URL user's password; required with a user, never in the URL |
| `AUTH_EMAIL_FROM` | Sender of every message; defaults to `Piquel <security@piquel.fr>` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Optional OTLP/HTTP base URL that traces, metrics and logs are exported to; unset, logs only go to stderr |
| `OTEL_RESOURCE_ATTRIBUTES`, other `OTEL_*`, `RUST_LOG` | Standard telemetry settings, e.g. `deployment.environment.name=staging`; see [telemetry](../architecture/telemetry.md#configuration) |

For a local Unix socket, use `localhost` as the URL host and an absolute socket
directory in the `host` query parameter, e.g.
`postgres://USER:PASSWORD@localhost/piquel?host=/run/postgresql&sslmode=disable`.

## Keys

Generate either key with `just auth generate-secret /absolute/path` (uses the
OpenSSL CLI; piqueld generates its own, see [deploying](deploying.md#secrets)), and an audit key
with `openssl rand -hex 32 > /absolute/path/audit-key`. Keep them across
restarts, and give every replica the same ones. The key-encryption key cannot be
changed yet: the stored signing keys would no longer open. Replacing the token
digest key at once ends every refresh token and every login in progress, so
change it in two deploys, as [signing keys](signing-keys.md#changing-the-token-digest-key)
describes.

## Running

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
`/health` answers `204` for piqueld's probe.

| Variable | Meaning |
| --- | --- |
| `WEB_AUTH_ORIGIN` | Required auth origin, e.g. `https://auth.piquel.fr` |
| `WEB_LISTENER` | Listener address; defaults to `127.0.0.1:8080` |
| `OTEL_*`, `RUST_LOG` | Telemetry, as auth's; its `service.name` is `piquel-web` |

The policies are HTML in `apps/web/assets/policies/`. Keep them true to what the
code does: a change to what auth stores, keeps or shares changes them too.
