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

```sh
just install
just build
```

The executable is `target/release/auth-service`. Auth assets are embedded at compile
time; rebuild Rust after changing `apps/auth-web`. The standalone settings build
is `apps/piquel-web/build`. Node is needed to build the frontends, not to run auth.

## Development

Install the build prerequisites above, then the Cargo tools with `just install-tools`.
Local signing-key generation uses the OpenSSL CLI. The combined development recipe
uses Bash, `setsid` (util-linux), and `pkill`/`pgrep` (procps) on Linux.
Create a local PostgreSQL database, then run:

```sh
just install
export AUTH_DATABASE_URL='postgres://localhost/piquel_dev'
just dev
```

This applies migrations to that database, builds the embedded auth assets once,
and starts all three processes. Ctrl+C stops them together:

- Auth UI and API: `http://localhost:3000` (Vite proxies API requests to Rust).
- Rust listener: `127.0.0.1:8080` (use the public auth URL in the browser).
- Account settings: `http://localhost:4173/settings` (a separate origin, as in production).

Svelte, TypeScript and CSS edits hot reload through Vite, including the shared
`packages/auth-client` SDK. `cargo-watch` rebuilds and restarts the normal
`auth-service serve` command when Rust sources, migrations or Cargo configuration
change. Frontend edits do not
restart Rust. A backend restart briefly interrupts requests; retry after it starts.
Restart `just dev` after changing environment configuration.
New database migrations are also applied before each watched backend restart.

The development recipes set these fixed local origins and `AUTH_DEVELOPMENT_MODE=true`
for their child processes. They retain other auth configuration, including invitations, clients
and optional social providers. Signup still requires an invitation by default;
set `AUTH_INVITE_REQUIRED=false` explicitly for an unrestricted local signup flow.
Provider callbacks must use `http://localhost:3000/login/<provider>/callback`.
The configured providers must accept that local callback URL.

The same Rust routes, database, origin checks, CSRF checks and Secure/HttpOnly
cookies run in development. Use **localhost**, not the backend address. Local HTTP
uses browsers' localhost secure-context exception; production uses HTTPS. Vite's
development rendering/HMR does not exercise the static build's per-page CSP hashes,
so use `just build` and serve the resulting executable for final production checks.
There are no development-only auth handlers or cookie rewrites.

Unless `AUTH_KEY_PROVIDER` is set, `just generate-dev-key` creates a private signing key at
`.dev/signing-key.pem` and reuses it across restarts, preserving token validity.
That directory is ignored by Git. The embedded frontend is refreshed at launcher
startup; it remains the production asset-serving path.

## Configuration

| Variable | Meaning |
| --- | --- |
| `AUTH_DATABASE_URL` | PostgreSQL URL; TCP requires `sslmode=verify-full`, or an explicit `sslmode=disable` on a trusted private network; local Unix sockets are also supported |
| `AUTH_DATABASE_PASSWORD` | Optional env/file reference for the database password, when omitted from the URL |
| `AUTH_PUBLIC_BASE_URL` | Exact auth origin, normally `https://auth.piquel.fr` |
| `AUTH_SETTINGS_URL` | Exact settings destination; defaults to `https://piquel.fr/settings` |
| `AUTH_TRUSTED_PROXIES` | Optional comma-separated proxy peer IPs or CIDRs; these peers must overwrite `X-Forwarded-For` with one client IP. Defaults to piqueld's `PIQUELD_INGRESS_PROXIES` |
| `AUTH_PUBLIC_LISTENER` | Listener address; defaults to `127.0.0.1:8080` |
| `AUTH_KEY_PROVIDER` | RSA private-key reference, `file:///absolute/path/key.pem` or `env://VARIABLE_NAME` |
| `AUTH_SIGNING_KEY_ID` | Stable ID for that signing key; defaults to `primary` |
| `AUTH_CLIENTS_FILE` | JSON client configuration; omitted means no OIDC clients |
| `AUTH_INVITE_REQUIRED` | `true` by default; set `false` to allow public registration |
| `AUTH_GITHUB_CLIENT_ID`, `AUTH_GITHUB_CLIENT_SECRET` | Both required to enable GitHub; secret is an env/file reference |
| `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` | Both required to enable Google; secret is an env/file reference |
| `AUTH_DEVELOPMENT_MODE` | Explicit `true` permits HTTP and PostgreSQL on loopback without `sslmode`, plus ephemeral signing keys |

Development mode also accepts remote PostgreSQL when using `sslmode=verify-full`.
For a local Unix socket, use `localhost` as the URL host and an absolute socket
directory in the `host` query parameter, e.g.
`postgres://USER:PASSWORD@localhost/piquel?host=/run/postgresql&sslmode=disable`.

Generate a persistent RSA key with `just generate-key /absolute/path/key.pem` (uses the
OpenSSL CLI; piqueld generates its own, see `infra/README.md`).
Keep the same key and ID across restarts. Replacing the only configured key
invalidates issued tokens; overlapping signing-key rotation is not implemented.

Provider callback URLs are `/login/github/callback` and `/login/google/callback`
on the auth origin. GitHub uses `read:user user:email`; Google uses `openid email profile`.
Never put provider secrets or confidential-client secrets in frontend configuration.
Enabled provider secrets are loaded and validated at startup; restart the service
after rotating their referenced values.

Apply migrations explicitly, then serve. Deployed images run the same
`migrate` and `serve` subcommands of the executable directly.

```sh
just migrate
just serve
```

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
PKCE. Redirect URLs must match exactly. HTTP loopback callbacks are permitted for
local testing. Non-loopback callbacks require HTTPS.

Discovery is `/.well-known/openid-configuration`; JWKS is `/.well-known/jwks.json`.
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
- Request throttling and expiring-state cleanup use PostgreSQL. Throttling uses separate login, token and account budgets per client IP.
  By default it uses the direct peer IP; only peers in `AUTH_TRUSTED_PROXIES`
  may supply a single overwritten `X-Forwarded-For`. Configure this when terminating TLS
  at a reverse proxy so users do not share the proxy’s budget. Untrusted headers
  are ignored; missing/ambiguous headers from a trusted proxy fail closed. Security audit records are
  retained. Readiness checks PostgreSQL; startup validates configured signing/provider
  secrets. Request and provider calls have bounded timeouts.

## Validation

`just` runs `validate` by default.
Install `cargo-nextest` and `cargo-deny` to run the complete validation suite.
Use individual recipes while iterating:

| Task | Recipe |
| --- | --- |
| Full validation (format, Clippy/ESLint, Rust/Svelte checks, unit/doc tests, audits) | `just validate` |
| Format Rust and web / check formatting | `just fmt` / `just fmt-check` (`-rust` / `-web` variants) |
| Rust / frontend checks (svelte-check, tsc) | `just check-rust` / `just check-web` |
| Clippy and ESLint, warnings denied | `just lint` (`just lint-rust` / `just lint-web`) |
| Unit tests / focused package tests | `just test` / `just test -p auth-service` |
| Documentation tests | `just doc-test` |
| Database integration tests | `TEST_DATABASE_URL=postgres://... just test-database` |
| Browser tests against running servers | `just test-browser` |
| Dependency audits | `just audit` (`deny` + `audit-web`) |
| SvelteKit generated types/config | `just generate` |
| Static frontends / embedded debug binary / release binary | `just build-web` / `just build-debug` / `just build` |
| Run with caller-provided auth configuration | `just serve`, `just migrate`, `just invite --expires-in 7d` |

Web code is formatted by Prettier and linted by type-aware ESLint (typescript-eslint
`strictTypeChecked`), configured once at the repository root.
`just --list` shows every recipe. Test recipes forward extra arguments to nextest
or Playwright, including quoted filter expressions. `just run` forwards arguments
to the auth binary. `just serve` builds auth assets before compiling and serving.
Cargo generates the embedded asset table and embeds migrations during compilation;
there is no separate API/schema code-generation step.

`just dev` runs all development servers. For separate terminal logs, run
`just dev-rust`, `just dev-auth`, and `just dev-settings`; `dev-rust` prepares the
assets, signing key and database first. Use `just dev-prepare` for preparation alone.

Database integration tests are explicitly marked ignored for the ordinary test
command. The database command above runs them against a **disposable loopback test
database** and applies migrations. It must not target a real account database.
For browser validation against the actual binary, see [tests/browser/README.md](tests/browser/README.md).

Backend tests use signed software-authenticator responses and local GitHub/Google
HTTP fixtures, including real signed Google ID tokens. Browser tests use Chromium's
synced virtual authenticator and real Rust/PostgreSQL endpoints. Actual Apple/Google
device synchronization and live provider credentials require separate validation;
virtual authenticators and provider fixtures do not establish that evidence.
