# piquel.fr

A monorepo for piquel.fr and its services. The first release is a passkey-first
OIDC/SSO authority at `auth.piquel.fr`, with account settings on `piquel.fr`.

The authentication service is **one Rust executable** containing its login,
onboarding, consent and passkey pages. PostgreSQL is its only external data
service. GitHub and Google are optional login providers. The separate settings
frontend calls the public authentication API. See [infra/README.md](infra/README.md)
for repository-driven piqueld deployments.

## Build

Requires Rust (pinned by `rust-toolchain.toml`), Node 24+, just, and pnpm (the workspace pins its version).
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
| `AUTH_DATABASE_URL` | PostgreSQL URL the service connects with; TCP requires `sslmode=verify-full`, or an explicit `sslmode=disable` on a trusted private network; local Unix sockets are also supported |
| `AUTH_DATABASE_PASSWORD` | Optional env/file reference for the database password, when omitted from the URL; required with `AUTH_DATABASE_OWNER_URL` |
| `AUTH_DATABASE_OWNER_URL`, `AUTH_DATABASE_OWNER_PASSWORD` | Optional schema-owner connection for `migrate`, same rules as above. When set, `migrate` also makes the `AUTH_DATABASE_URL` user a restricted runtime role (see below); this needs PostgreSQL 17 or later and a superuser owner |
| `AUTH_PUBLIC_BASE_URL` | Exact auth origin, normally `https://auth.piquel.fr` |
| `AUTH_SETTINGS_URL` | Exact settings destination; defaults to `https://piquel.fr/settings` |
| `AUTH_TRUSTED_PROXIES` | Optional comma-separated proxy peer IPs or CIDRs; these peers must overwrite `X-Forwarded-For` with one client IP. Defaults to piqueld's `PIQUELD_INGRESS_PROXIES` |
| `AUTH_PUBLIC_LISTENER` | Listener address; defaults to `127.0.0.1:8080` |
| `AUTH_KEY_PROVIDER` | Required persistent RSA private-key reference, `file:///absolute/path/key.pem` or `env://VARIABLE_NAME` |
| `AUTH_SIGNING_KEY_ID` | Stable ID for that signing key; defaults to `primary` |
| `AUTH_CLIENTS_FILE` | JSON client configuration; omitted means no OIDC clients |
| `AUTH_INVITE_REQUIRED` | `true` by default; set `false` to allow public registration |
| `AUTH_GITHUB_CLIENT_ID`, `AUTH_GITHUB_CLIENT_SECRET` | Both required to enable GitHub; secret is an env/file reference |
| `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` | Both required to enable Google; secret is an env/file reference |

For a local Unix socket, use `localhost` as the URL host and an absolute socket
directory in the `host` query parameter, e.g.
`postgres://USER:PASSWORD@localhost/piquel?host=/run/postgresql&sslmode=disable`.

Generate a persistent RSA key with `just generate-key /absolute/path/key.pem` (uses the
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
just serve
```

Without `AUTH_DATABASE_OWNER_URL`, both connect as the `AUTH_DATABASE_URL` user,
which must then own the schema. With it, `migrate` connects as the owner, applies
migrations, then creates or updates the `AUTH_DATABASE_URL` user: a login role
without superuser, role or database creation, given the `AUTH_DATABASE_PASSWORD`
password and only row access to the tables. It cannot change the schema, disable
triggers, rewrite the security audit log, read migration history, or create
temporary tables or large objects, or take advisory locks. This needs PostgreSQL
17 or later, and the owner must be a different role and a superuser (`migrate`
checks both): only a superuser can set the role's attributes and revoke PUBLIC's
defaults on built-in functions.

Each run, `migrate` revokes everything granted to the role and resets its
settings before granting again, so new tables are covered and changes made by
hand are removed. It also resets the password, so changing
`AUTH_DATABASE_PASSWORD` and running `migrate` rotates it. Sessions already open
keep working, so after a leak also end them as the owner with
`pg_terminate_backend`. It refuses, changing nothing, a role that belongs to
another role or owns an object in this database or a shared one, or that still
holds more than row access afterwards, e.g. through another role's grant. Other
databases in the cluster are out of scope: by PostgreSQL's defaults the role may
connect to them, e.g. `postgres`, but gains no meaningful privileges there;
objects and settings it creates there are ignored. Revoke PUBLIC's `CONNECT` on
them if you prefer.

The schema intentionally replaces the throwaway prototype. Use a fresh database;
there is no migration path for prototype account data.

### Invitations

```sh
just invite --expires-in 7d
```

This prints one signup link. The database stores a digest, expiry and redemption
time. Tokens expire after seven days by default; `h` and `d` are supported. A token
is redeemed atomically with account creation, so a failed signup does not spend it.
Disabling invitation enforcement affects signup only; existing users keep access.

### OIDC clients

`AUTH_CLIENTS_FILE` is authoritative: startup disables clients omitted from it.
Client IDs must be unique. A minimal public web client looks like:

```json
[
  {
    "id": "piquel-web",
    "display_name": "Piquel",
    "redirect_uris": ["https://piquel.fr/callback"],
    "post_logout_uris": ["https://piquel.fr/"],
    "allowed_scopes": ["openid", "profile", "email"],
    "trusted": true,
    "allow_refresh": false
  }
]
```

For a confidential backend client, add `"client_secret": "env://MY_CLIENT_SECRET"`.
Generate its random secret with `just secret`. Clients use
`client_secret_basic` when confidential and `none` when public; both require S256
PKCE. Redirect URLs must match exactly and use HTTPS.

Discovery is served at both `/.well-known/openid-configuration` (OIDC) and
`/.well-known/oauth-authorization-server` (RFC 8414, read by OAuth-only and MCP
clients); the two are the same document. JWKS is `/.well-known/jwks.json`. All three
are cacheable for an hour and readable from any origin, without credentials.
Every authorization response redirected to a client, success or error, carries
`iss` (RFC 9207), so clients that use several issuers can reject mix-ups; discovery
advertises `authorization_response_iss_parameter_supported`.
The endpoints implement code exchange, RS256 ID/access tokens, userinfo, opt-in
rotating refresh tokens, revocation and RP-initiated logout. Access tokens are
intended for the configured client audience. Only requested claims are released;
passkey-only accounts have no email claim. Browser clients should keep tokens in
memory and use SSO again after reload. Refresh permission is off unless explicitly
enabled and `offline_access` is allowed/requested. Consent is remembered per user,
client and scope; explicitly trusted clients bypass consent.

## Security behavior

- Passkeys require user verification and prefer resident credentials. Synced
  passkeys and security keys are accepted. Android enrollment offers an explicit
  Google Password Manager option for devices with Google services. Authentication supports the browser
  account picker and a username fallback.
- Social-first signup remains pending until its first passkey is committed. Only
  a registration that names the pending identity shown on the signup page attaches
  it; plain registration ignores it. A social login can never replace an
  established account's passkeys.
- A passkey confirmation opens a fixed two-minute management window for the
  current account and browser session. It permits repeated sensitive changes and
  does not slide or renew through social login. Reads need only ordinary login.
- Matching verified email suggests linking; it never grants account access.
  Linking requires possession of the provider account and the target account's
  passkey authorization. Explicit linking, started from settings, permits
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
  are ignored; missing/ambiguous headers from a trusted proxy fail closed. Security audit records are
  retained. Readiness checks PostgreSQL; startup validates configured signing/provider
  secrets. Request and provider calls have bounded timeouts.

## Validation

`just` runs `validate` by default.
`just install-tools` installs `cargo-nextest`, `cargo-deny` and `sqlx-cli`. The
`db` recipes also need the PostgreSQL 18 server binaries (`initdb`, `pg_ctl`).
Use individual recipes while iterating:

| Task | Recipe |
| --- | --- |
| Full validation (format, Clippy/ESLint, Rust/Svelte checks, unit/web/doc tests, audits) | `just validate` |
| Format Rust and web / check formatting | `just fmt` / `just fmt-check` (`-rust` / `-web` variants) |
| Rust / frontend checks (svelte-check, tsc) | `just check-rust` / `just check-web` |
| Clippy and ESLint, warnings denied | `just lint` (`just lint-rust` / `just lint-web`) |
| Unit tests / focused package tests | `just test` / `just test -p auth-service` |
| piquel-web server tests (builds it first) | `just test-web` |
| Documentation tests | `just doc-test` |
| Database integration tests and query cache check, in a scratch cluster | `just db test` |
| Regenerate the query cache after changing SQL or migrations | `just db prepare` |
| Run any command against a scratch cluster | `just db scratch -- psql` |
| Browser tests against running servers | `just test-browser` |
| Dependency audits | `just audit` (`deny` + `audit-web`) |
| SvelteKit generated types/config | `just generate` |
| Frontends / embedded debug binary / release binary | `just build-web` / `just build-debug` / `just build` |
| Run with caller-provided auth configuration | `just serve`, `just db migrate`, `just invite --expires-in 7d` |

CI runs these recipes on every pull request whose changes they can affect,
including the database and browser tests, and on every push to `main`.
Require its `ci` check: it summarizes the others.

Web code is formatted by Prettier and linted by type-aware ESLint (typescript-eslint
`strictTypeChecked`), configured once at the repository root.
`just --list --list-submodules` shows every recipe. Test recipes forward extra arguments to nextest
or Playwright, including quoted filter expressions. `just run` forwards arguments
to the auth binary. `just serve` builds auth assets before compiling and serving.
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
