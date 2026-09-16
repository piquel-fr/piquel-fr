# piquel.fr

A monorepo for piquel.fr and its services. The first release is a passkey-first
OIDC/SSO authority at `auth.piquel.fr`, with account settings on `piquel.fr`.

The authentication service is **one Rust executable** containing its login,
onboarding, consent and passkey pages. PostgreSQL is its only external data
service. GitHub and Google are optional login providers. The separate settings
frontend calls the public authentication API. See [infra/README.md](infra/README.md)
for repository-driven piqueld deployments.

## Build

Requires Rust 1.97+, Node 24+, and pnpm (the workspace pins its version).

```sh
pnpm install --frozen-lockfile
pnpm build
cargo build --release -p auth-service
```

The executable is `target/release/auth-service`. Auth assets are embedded at compile
time; rebuild Rust after changing `apps/auth-web`. The standalone settings build
is `apps/piquel-web/build`. Node is needed to build the frontends, not to run auth.

## Configuration

| Variable | Meaning |
| --- | --- |
| `AUTH_DATABASE_URL` | PostgreSQL URL; TCP in production requires `sslmode=verify-full`; local Unix sockets are also supported |
| `AUTH_PUBLIC_BASE_URL` | Exact auth origin, normally `https://auth.piquel.fr` |
| `AUTH_SETTINGS_URL` | Exact settings destination; defaults to `https://piquel.fr/settings` |
| `AUTH_PUBLIC_LISTENER` | Listener address; defaults to `127.0.0.1:8080` |
| `AUTH_KEY_PROVIDER` | RSA private-key reference, `file:///absolute/path/key.pem` or `env://VARIABLE_NAME` |
| `AUTH_SIGNING_KEY_ID` | Stable ID for that signing key; defaults to `primary` |
| `AUTH_CLIENTS_FILE` | JSON client configuration; omitted means no OIDC clients |
| `AUTH_INVITE_REQUIRED` | `true` by default; set `false` to allow public registration |
| `AUTH_GITHUB_CLIENT_ID`, `AUTH_GITHUB_CLIENT_SECRET` | Both required to enable GitHub; secret is an env/file reference |
| `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` | Both required to enable Google; secret is an env/file reference |
| `AUTH_DEVELOPMENT_MODE` | Explicit `true` permits HTTP and unencrypted PostgreSQL on loopback only, plus ephemeral signing keys |

Development mode also accepts remote PostgreSQL when using `sslmode=verify-full`.
For a local Unix socket, use `localhost` as the URL host and an absolute socket
directory in the `host` query parameter, e.g.
`postgres://USER:PASSWORD@localhost/piquel?host=/run/postgresql&sslmode=disable`.

Generate a persistent RSA key with OpenSSL, for example
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /absolute/path/key.pem`.
Keep the same key and ID across restarts. Replacing the only configured key
invalidates issued tokens; overlapping signing-key rotation is not implemented.

Provider callback URLs are `/login/github/callback` and `/login/google/callback`
on the auth origin. GitHub uses `read:user user:email`; Google uses `openid email profile`.
Never put provider secrets or confidential-client secrets in frontend configuration.

Apply migrations explicitly, then run the same executable:

```sh
auth-service migrate
auth-service serve
```

The schema intentionally replaces the throwaway prototype. Use a fresh database;
there is no migration path for prototype account data.

### Invitations

```sh
auth-service invite create --expires-in 7d
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
Generate its random secret with `auth-service secret`. Clients use
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
- Social-first signup remains pending until its first passkey is committed. A
  social login can never replace an established account's passkeys.
- A passkey confirmation opens a fixed two-minute management window for the
  current account and browser session. It permits repeated sensitive changes and
  does not slide or renew through social login. Reads need only ordinary login.
- Matching verified email suggests linking; it never grants account access.
  Linking requires possession of the provider account and the target account's
  passkey authorization. Explicit linking permits different/missing provider email.
- One Google and one GitHub identity may be linked. Unlinking releases the provider
  identity so another account can link it; account data and credentials never move.
- The last passkey cannot be removed. Removing a passkey/provider revokes other
  central sessions. There is no recovery if every passkey is lost.
- Sessions last at most 30 days. Access tokens last five minutes. Refresh rotation
  detects reuse and stops when its central session expires or is revoked. Logout
  does not destroy application-owned sessions or already issued access tokens.
- Browser state and opaque secrets are random, hashed where lookup is needed, and
  bound to the initiating browser. Auth cookies are host-only, Secure and HttpOnly.
  Mutations require an exact allowed origin and CSRF header; OIDC back-channel
  endpoints instead validate their protocol credentials.
- Request throttling and expiring-state cleanup use PostgreSQL. Throttling uses the
  direct peer IP; forwarded IP headers are not trusted. Security audit records are
  retained. Readiness checks PostgreSQL; startup validates configured signing/provider
  secrets. Request and provider calls have bounded timeouts.

## Validation

```sh
pnpm check
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo nextest run --workspace
TEST_DATABASE_URL=postgres://... cargo nextest run -p auth-service -p piquel-repository --run-ignored all
cargo deny check advisories licenses
pnpm audit
```

Database integration tests are explicitly marked ignored for the ordinary test
command. The database command above runs them against a **disposable loopback test
database** and applies migrations. It must not target a real account database.
For browser validation against the actual binary, see [tests/browser/README.md](tests/browser/README.md).

Backend tests use signed software-authenticator responses and local GitHub/Google
HTTP fixtures, including real signed Google ID tokens. Browser tests use Chromium's
synced virtual authenticator and real Rust/PostgreSQL endpoints. Actual Apple/Google
device synchronization and live provider credentials require separate validation;
virtual authenticators and provider fixtures do not establish that evidence.
