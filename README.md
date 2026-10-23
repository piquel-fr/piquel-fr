# piquel.fr

A monorepo for piquel.fr and its services. The first release is a passkey-first
OIDC/SSO authority at `auth.piquel.fr`, with account settings on `piquel.fr`.

The authentication service is **one Rust executable** containing its login,
onboarding, consent and passkey pages. PostgreSQL is its only external data
service. GitHub and Google are optional login providers. The separate settings
frontend calls the public authentication API, and the admin dashboard
(`apps/admin-web`, at `admin.piquel.fr`) its private admin API. See
[infra/README.md](infra/README.md) for repository-driven piqueld deployments.

## Build

Requires Rust (pinned by `rust-toolchain.toml`), Node 24+, just 1.42+, and pnpm (the workspace pins its version).
Building needs no database: SQL is checked against the committed query cache in
`crates/database/.sqlx/`.

```sh
just install
just build
```

The executable is `target/release/auth-service`. Auth assets are embedded at compile
time; rebuild Rust after changing `apps/auth-web`. piquel.fr's settings server builds to
`apps/piquel-web/build` and runs on Node (see its README). Auth needs Node only
to build its pages.

## Development

Develop through the HTTPS preview on piqueld:

```sh
just preview
```

This snapshots this checkout, including uncommitted changes, builds both frontends
and auth, applies migrations, and prints the web and auth URLs. The preview has its
own database and signing key. URLs work from devices on the tailnet. Run the same
command after changing code. `just preview-delete` removes it. `just dev` serves
piquel-web with Vite against an auth service on `http://localhost:3000`.

## Configuration

| Variable | Meaning |
| --- | --- |
| `AUTH_DATABASE_URL` | PostgreSQL URL; TCP requires `sslmode=verify-full`, or an explicit `sslmode=disable` on a trusted private network; local Unix sockets are also supported |
| `AUTH_DATABASE_PASSWORD` | Optional env/file reference for the database password, when omitted from the URL |
| `AUTH_DATABASE_OWNER_URL`, `AUTH_DATABASE_OWNER_PASSWORD` | Optional schema owner `migrate` connects as instead, in the same formats. It then creates or resets the role `AUTH_DATABASE_URL` names, with the `AUTH_DATABASE_PASSWORD` password and only row access to the app tables. Requires the right to create roles |
| `AUTH_PUBLIC_BASE_URL` | Exact auth origin, normally `https://auth.piquel.fr` |
| `AUTH_SETTINGS_URL` | Exact settings destination; defaults to `https://piquel.fr/settings`. Its origin is a frontend origin: it may call the account API, and sign-in may return to any URL on it |
| `AUTH_TRUSTED_PROXIES` | Optional comma-separated proxy peer IPs or CIDRs; these peers must overwrite `X-Forwarded-For` with one client IP. Defaults to piqueld's `PIQUELD_INGRESS_PROXIES` |
| `AUTH_PUBLIC_LISTENER` | Listener address; defaults to `127.0.0.1:8080` |
| `AUTH_ADMIN_LISTENER` | Optional address of the private admin API listener, e.g. `0.0.0.0:8081`. No ingress route may reach it. Without it, auth serves no admin API |
| `AUTH_KEY_PROVIDER` | Required persistent RSA private-key reference, `file:///absolute/path/key.pem` or `env://VARIABLE_NAME` |
| `AUTH_SIGNING_KEY_ID` | Stable ID for that signing key; defaults to `primary` |
| `AUTH_INVITE_REQUIRED` | `true` by default; set `false` to allow public registration |
| `AUTH_GITHUB_CLIENT_ID`, `AUTH_GITHUB_CLIENT_SECRET` | Both required to enable GitHub; secret is an env/file reference |
| `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` | Both required to enable Google; secret is an env/file reference |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Optional OTLP/HTTP base URL that traces, metrics and logs are exported to; unset, logs only go to stderr |
| `OTEL_RESOURCE_ATTRIBUTES`, other `OTEL_*`, `RUST_LOG` | Standard telemetry settings, e.g. `deployment.environment.name=staging`; see `docs/architecture/telemetry.md` |

For a local Unix socket, use `localhost` as the URL host and an absolute socket
directory in the `host` query parameter, e.g.
`postgres://USER:PASSWORD@localhost/piquel?host=/run/postgresql&sslmode=disable`.

Generate a persistent RSA key with `just auth generate-key /absolute/path/key.pem` (uses the
OpenSSL CLI; piqueld generates its own, see `infra/README.md`).
Keep the same key and ID across restarts. Replacing the only configured key
invalidates issued tokens; overlapping signing-key rotation is not implemented.
It also changes the decoy passkey IDs that username sign-in returns for unknown
usernames, while real accounts keep theirs, so comparing responses from before and
after a replacement reveals which usernames exist.

Provider callback URLs are `/login/github/callback` and `/login/google/callback`
on the auth origin. GitHub uses `read:user user:email`; Google uses `openid email profile`.
To add another provider, see `docs/architecture/federation-providers.md`.
Never put provider secrets or confidential-client secrets in frontend configuration.
Enabled provider secrets are loaded and validated at startup; restart the service
after rotating their referenced values.

Apply migrations explicitly, then serve. Deployed images run the same
`migrate` and `serve` subcommands of the executable directly.

```sh
just db migrate
just auth serve
```

The schema intentionally replaces the throwaway prototype. Use a fresh database;
there is no migration path for prototype account data.

### Invitations

```sh
just auth invite --expires-in 7d
```

This prints one signup link. The database stores a digest, expiry and redemption
time. Tokens expire after seven days by default; `h` and `d` are supported. A token
is redeemed atomically with account creation, so a failed signup does not spend it.
Disabling invitation enforcement affects signup only; existing users keep access.
Administrators can also list, create and revoke invitations through the admin API.

### Administration

```sh
just auth admin grant alice    # the first administrator is granted here
just auth admin grant bob
just auth admin list
just auth admin revoke bob     # the last administrator's rights stay
```

Administrators manage accounts, sessions, invitations and other administrators
through the admin API, from the admin dashboard
([apps/admin-web](apps/admin-web/README.md)). Auth serves the API only on
`AUTH_ADMIN_LISTENER`, which no ingress route reaches: the dashboard calls it from
its server, over the application's private network. Its routes, bodies and typed
client are in `crates/admin-api`.

Every request carries an access token that auth issued to the dashboard,
registered as the confidential OIDC client `piquel-admin` (the tokens' audience;
deployments register it with `client apply`, see [OIDC clients](#oidc-clients)),
for an administrator who signed in with a passkey. Auth checks on every request
that the account is still an administrator and the token's session still active, so
revoking either takes effect at once. Mutations also need a passkey confirmation
from the last five minutes. Otherwise the API answers `401` with an RFC 9470
step-up challenge, and the dashboard signs the administrator in again.

The API never changes an administrator's account: revoke their rights first.
Administrators cannot grant or revoke their own rights, and nobody can revoke the last
administrator's. Every change is recorded as a domain event with its administrator
or CLI operator.

### Outbound deliveries

Messages for other systems wait in a queue in the database until a worker sends
them. No channel uses it yet; back-channel logout (#65) will be the first.
Inspect and repair it with:

```sh
just auth deliveries list --status failed
just auth deliveries retry <id>
just auth deliveries cancel <id>
```

A failed delivery with an ordering key holds back the ones after it until it is
retried or cancelled. After 30 days, cleanup deletes it and cancels the ones
behind it. See `docs/architecture/delivery-queue.md`.

### OIDC clients

Clients live in the database. Register and change them with `auth-service client`
(`just auth client` here). A change applies to the next request on every replica,
without a restart, and is recorded as an event attributed to the operator.

```sh
just auth client create piquel-web --name Piquel --trusted \
    --redirect-uri https://piquel.fr/callback --post-logout-uri https://piquel.fr/
just auth client create notes --name Notes --confidential --refresh \
    --redirect-uri https://notes.example/callback --scope openid --scope notes:read
just auth client list                # --output json for scripts
just auth client show notes          # registration and secret lifetimes
just auth client update piquel-web --add-redirect-uri https://piquel.fr/auth/callback
just auth client disable notes       # enable undoes it
just auth client rotate-secret notes --grace 24h
```

Clients are public by default and authenticate with PKCE alone (`none`).
Confidential clients (`--confidential`) use `client_secret_basic` with a secret
that auth generates; both require S256 PKCE. `create` and `rotate-secret` print
the secret once, and auth stores only its SHA-256 digest. Secrets start with
`pqcs_` so secret scanners can recognize them. After `rotate-secret`, the earlier
secrets keep working for the grace period (24 hours by default, at most 30 days;
`--grace 0` revokes them at once), so the client can switch without downtime.

A client that a deployment manages, such as the admin dashboard, is registered
with `client apply` instead, which takes the same options as `create`. It
registers the client, or updates what differs and records nothing when nothing
does, so a deploy job can run it every time. A confidential client's secret comes
from the deployment, `--secret file://PATH` (or `env://NAME`): 32 random bytes in
unpadded base64url, never printed. The client's other secrets keep working for
`--grace` at most (1 hour by default) while the deployment rolls out; `--grace 0`
revokes them.

Redirect URIs must match exactly. They use HTTPS, or HTTP on a loopback IP for
native apps, without credentials or a fragment, and are written as URL parsing
normalizes them: `https://app.example/`, not `https://APP.example`. The origins of
an enabled public client's redirect URIs may call the token, revocation and
userinfo endpoints from a browser. Scopes default to `openid`, `profile` and
`email`. `--refresh` allows refresh tokens when the client also requests
`offline_access`; `--trusted` skips the consent screen and is meant for
first-party clients only. `--require-par` makes the client push its authorization
requests (`update --no-require-par` lifts it).

`AUTH_CLIENTS_FILE` was removed, and startup refuses to run while it is set. The
clients it registered are already in the database.

Discovery is served at both `/.well-known/openid-configuration` (OIDC) and
`/.well-known/oauth-authorization-server` (RFC 8414, read by OAuth-only and MCP
clients); the two are the same document. JWKS is `/.well-known/jwks.json`. All three
are cacheable for an hour and readable from any origin, without credentials.
Every authorization response redirected to a client, success or error, carries
`iss` (RFC 9207), so clients that use several issuers can reject mix-ups; discovery
advertises `authorization_response_iss_parameter_supported`.

A client may push its authorization request (RFC 9126) instead of sending it
through the browser: it posts the usual parameters to `/oauth/par`, authenticated
as at the token endpoint, and receives a `request_uri` valid for 60 seconds. The
browser then opens `/oauth/authorize?client_id=…&request_uri=…`. The `request_uri`
works once, only for that client, and auth ignores every other parameter sent
with it. A pushed request is validated exactly like a browser one, but its errors
come back as JSON. Discovery advertises `pushed_authorization_request_endpoint`.
Client-hosted request objects (`request` and `request_uri` from RFC 9101) are not
supported.
The endpoints implement code exchange, RS256 ID/access tokens, userinfo, opt-in
rotating refresh tokens, revocation and RP-initiated logout. Access tokens are
intended for the configured client audience. Only requested claims are released;
passkey-only accounts have no email claim. Browser clients should keep tokens in
memory and use SSO again after reload. Refresh permission is off unless explicitly
enabled and `offline_access` is allowed/requested. Consent is remembered per user,
client and scope; explicitly trusted clients bypass consent.

### Authentication claims

ID and access tokens report how the browser session behind the grant
authenticated:

| Claim | Values |
| --- | --- |
| `acr` | `phr` once a passkey signed in or confirmed the session: phishing-resistant multi-factor authentication ([OpenID Connect EAP ACR Values](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)). `urn:piquel:acr:social` for a session signed in with GitHub or Google only: the provider's authentication, whatever it was |
| `amr` | Every method the session used (RFC 8176): `pop`, `mfa` and `user` for a passkey, which proves possession of a key and requires user verification; `fed` for a provider sign-in. RFC 8176 registers no value for federation, so `fed` is Piquel's own |
| `auth_time` | The latest authentication at the session's `acr`: its last passkey confirmation, or else its sign-in |

`phr` satisfies a `urn:piquel:acr:social` requirement, not the reverse. Both values
are listed in discovery's `acr_values_supported`. An authorization request may send
`acr_values` in order of preference: the first known value becomes its target, and
unknown values are ignored. A session below the target signs in again, on a login
page offering only passkeys for `phr`; with `prompt=none` the request fails with
`login_required`. With no known value, the tokens report what the session reached.

Signing in again (`prompt=login`, `max_age`, a target) re-authenticates the
browser's session rather than starting another, so `sid` stays the same: a passkey
confirms it, and a social sign-in renews it only before any passkey confirmation,
since it would lower `acr`. Every re-authentication, including a passkey
confirmation for a settings change, replaces the session cookie, so a copied cookie
never gains the new authentication. Signing in as another account revokes the previous
session. A refresh token keeps reporting the authentication of the code it came
from, even after the session re-authenticates.

An API that needs a stronger or more recent sign-in answers with an RFC 9470
step-up challenge, and its client signs the user in again with that challenge's
`acr_values` and `max_age`. [Step-up authentication](docs/guides/step-up-authentication.md)
explains how to choose a requirement and handle the challenge.

## Security behavior

- Passkeys require user verification and prefer resident credentials. Synced
  passkeys and security keys are accepted. Android enrollment offers an explicit
  Google Password Manager option for devices with Google services. Authentication supports the browser
  account picker and a username fallback.
- Social-first signup remains pending until its first passkey is committed. Only
  a registration that names the pending identity shown on the signup page attaches
  it; plain registration ignores it. A social login can never replace an
  established account's passkeys.
- Sensitive changes (adding or removing a passkey, linking or unlinking a provider)
  need a passkey confirmation of the current browser session from the last five
  minutes. A passkey sign-in counts; social sign-in never does. The age counts from
  the confirmation and is never extended by use, and it never applies to another
  session. Without one, the API answers `403` with `"code": "step_up_required"` and
  `max_age`; the frontend confirms on auth's `/confirm` page and finishes the change.
  Reads and renaming a passkey need only ordinary login.
- Matching verified email suggests linking; it never grants account access.
  Linking requires possession of the provider account and the target account's
  passkey confirmation. Explicit linking, started from settings, permits
  different/missing provider email and is bound to the session that started it.
- One Google and one GitHub identity may be linked. Unlinking releases the provider
  identity so another account can link it; account data and credentials never move.
  Settings keep listing identities of disabled providers so they can be unlinked.
- The last passkey cannot be removed. Removing a passkey/provider revokes other
  central sessions. There is no recovery if every passkey is lost.
- Sessions last at most 30 days. Access tokens last five minutes. Refresh rotation
  detects reuse and stops when its central session expires or is revoked. Logout
  does not destroy application-owned sessions or already issued access tokens.
- Browser state and opaque secrets are random, hashed where lookup is needed, and
  bound to the initiating browser. Auth cookies are host-only, Secure and HttpOnly.
  Mutations require an exact allowed origin and CSRF header; OIDC back-channel
  endpoints instead validate their protocol credentials.
- Request throttling and expiring-state cleanup use PostgreSQL. Throttling uses separate login, token, userinfo and account budgets per client IP, and covers every API route except health probes and discovery.
  By default it uses the direct peer IP; only peers in `AUTH_TRUSTED_PROXIES`
  may supply a single overwritten `X-Forwarded-For`. Configure this when terminating TLS
  at a reverse proxy so users do not share the proxy’s budget. Untrusted headers
  are ignored; missing/ambiguous headers from a trusted proxy fail closed. Security events are
  retained; the IP addresses, browser families and provider subjects recorded with
  them are deleted after 90 days. Readiness checks PostgreSQL; startup validates configured signing/provider
  secrets. Request and provider calls have bounded timeouts.

## Validation

`just` runs `validate` by default.
`just install-tools` installs `cargo-nextest`, `cargo-deny` and `sqlx-cli`. The
`db` recipes also need the PostgreSQL 18 server binaries (`initdb`, `pg_ctl`).
Recipes are grouped into `rust`, `web`, `db`, `auth`, `admin` and `infra` modules under
`just/`; `just --list --list-submodules` shows every recipe. The root `fmt`,
`fmt-check`, `lint`, `check` and `audit` run the same recipe in `rust` and `web`.
Use individual recipes while iterating:

| Task | Recipe |
| --- | --- |
| Full validation (format, Clippy/ESLint, Rust/Svelte checks, unit/web/doc tests, audits) | `just validate` |
| Format Rust and web / check formatting | `just fmt` / `just fmt-check` |
| Rust / frontend checks (svelte-check, tsc) | `just rust check` / `just web check` |
| Clippy and ESLint, warnings denied | `just lint` (`just rust lint` / `just web lint`) |
| Unit tests / focused package tests | `just test` / `just test -p auth-service` |
| piquel-web server tests (builds it first) | `just web test` |
| Documentation tests | `just doc-test` |
| Database integration tests and query cache check, in a scratch cluster | `just db test` |
| Regenerate the query cache after changing SQL or migrations | `just db prepare` |
| Run any command against a scratch cluster | `just db scratch -- psql` |
| Browser tests against running servers | `just web test-browser` |
| Dependency audits | `just audit` (`just rust audit` runs cargo-deny, `just web audit` pnpm) |
| SvelteKit generated types/config | `just web generate` |
| Frontends / embedded debug binary / release binary | `just web build` / `just rust build` / `just build` |
| Run with caller-provided auth configuration | `just auth serve`, `just db migrate`, `just auth invite --expires-in 7d`, `just auth admin list` |

CI runs these recipes on every pull request whose changes they can affect,
including the database and browser tests, and on every push to `main`.
Require its `ci` check: it summarizes the others.

Web code is formatted by Prettier and linted by type-aware ESLint (typescript-eslint
`strictTypeChecked`), configured once at the repository root.
Test recipes forward extra arguments to nextest or Playwright, including quoted
filter expressions. `just auth run` forwards arguments to the auth binary. `just auth serve` builds auth assets before compiling and serving.
Cargo generates the embedded asset table and embeds migrations during compilation.

Queries in `crates/database` are checked at compile time against
`crates/database/.sqlx/`. Changing a query's text without `just db prepare` fails
the build, so `just validate` catches it without a database. Commit the cache with
the query or migration that changed it.

Database integration tests are explicitly marked ignored for the ordinary test
command. `just db test` runs them in a throwaway PostgreSQL cluster that listens
only on a private Unix socket and is deleted afterwards, then runs
`cargo sqlx prepare --check` against the migrated schema, which catches a
migration that breaks a cached query. To use an existing disposable database
instead, set `TEST_DATABASE_URL`; TCP URLs must include `sslmode=disable` or
`sslmode=verify-full`. It must not target a real account database.
For browser validation against the actual binary, see [tests/browser/README.md](tests/browser/README.md).

Backend tests use signed software-authenticator responses and local GitHub/Google
HTTP fixtures, including real signed Google ID tokens. Browser tests use Chromium's
synced virtual authenticator and real Rust/PostgreSQL endpoints. Actual Apple/Google
device synchronization and live provider credentials require separate validation;
virtual authenticators and provider fixtures do not establish that evidence.
