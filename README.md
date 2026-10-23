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
| `AUTH_DATABASE_OWNER_URL`, `AUTH_DATABASE_OWNER_PASSWORD` | Optional schema owner `migrate` connects as instead, in the same formats. It then creates or resets the role `AUTH_DATABASE_URL` names, with the `AUTH_DATABASE_PASSWORD` password and only row access to the app tables. The owner must be a superuser |
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
| `AUTH_SMTP_URL` | Optional SMTP relay, `smtps://USER@HOST:465` (implicit TLS) or `smtp://USER@HOST:587` (STARTTLS required); unset disables email. Only a loopback host, such as a local Mailpit, may be reached without TLS |
| `AUTH_SMTP_PASSWORD` | Env/file reference for the URL user's password; required with a user, never in the URL |
| `AUTH_EMAIL_FROM` | Sender of every message; defaults to `Piquel <security@piquel.fr>` |
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
just auth invite create --expires-in 7d
just auth invite list
just auth invite revoke <id>
```

`create` prints one signup link. The database stores a digest, expiry and redemption
time. Tokens expire after seven days by default; `h` and `d` are supported. A token
is redeemed atomically with account creation, so a failed signup does not spend it.
Disabling invitation enforcement affects signup only; existing users keep access.
Administrators can also list, create and revoke invitations through the admin API.

### Administration

Every administrative operation has a command, which runs the same code as the
admin API (`AdminService` in `apps/auth-service/src/admin`), and so does every
setting administrators may change on another account (`AccountService` in
`apps/auth-service/src/account`). Commands need only
`AUTH_DATABASE_URL` (`invite create` also needs `AUTH_PUBLIC_BASE_URL`, to build its
link), so they work while auth is down: they are the break-glass path when the
dashboard or auth's frontends are unreachable. In deployed environments,
run them with `piquelctl app exec piquel-fr auth --env ENV -- auth-service …` (see
[infra/README.md](infra/README.md)).

```sh
just auth admin grant alice               # the first administrator is granted here
just auth admin list
just auth admin revoke bob                # the last administrator's rights stay
just auth user search ali                 # by ID, or part of a username, name or email
just auth user show alice                 # recorded, since it shows personal data
just auth user disable alice --reason "Spam"
just auth user enable alice
just auth session revoke <session-id>     # one session, as `user show` lists it
just auth session revoke-all alice        # every session of the account
just auth audit --user alice --kind session_revoked
just auth account alice passkeys list     # the account's settings, as its owner sees them
just auth account alice passkeys revoke <passkey-id> --reason "Phone stolen"
just auth account alice emails remove <email-id> --reason "Asked by email"
```

- Accounts are named by username, ID or a verified email of an active account.
- `--output json` prints the admin API's body for `user search` (`UserPage`), `user
  show` (`UserDetail`), `audit` (`EventPage`), `client list`, `invite list` and
  `admin list`, as defined in `crates/admin-api`. It changes only as the API does.
- `user disable`, `session revoke-all`, `admin revoke`, `client
  disable|suspend|delete`, and `account … passkeys revoke`, `identities unlink` and
  `sessions revoke-all` describe what they will change and ask for confirmation.
  Without a terminal they refuse unless given `--yes`.
- `account <user>` reads and changes the settings administrators share with the
  owner: passkeys, social identities, email addresses, sessions and the security
  history, with the owner's own operations. It never adds a way to sign in or an
  address. Every change needs `--reason`, which the owner sees in their history;
  reads are recorded as views. See
  [surfaces.md](docs/architecture/surfaces.md#changing-an-account-on-its-owners-behalf)
  for what is shared.
- Each change is recorded as a domain event with the operator: `$USER` and the host
  name. Unlike the admin API, the CLI may act on administrators' accounts.
- Failures print their causes and exit with 1; usage errors exit with 2.

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

### Handles

```sh
just auth handle check                      # accounts whose handle breaks the rules
just auth handle rename old_name new-name   # --allow-reserved to assign a reserved name
```

`check` lists every account whose handle breaks the syntax, is reserved or looks like
another account's (see [Security behavior](#security-behavior)), and fails while any
remain. `rename` refuses a handle another account has, but not a look-alike: run
`check` again after renaming. A rename bumps the account's profile version, so
relying parties refresh `preferred_username`, and is recorded as a domain event with
its CLI operator.

### Email

Accounts add, verify, choose the primary of and remove their addresses on
`piquel.fr/settings/emails`; the OIDC `email` claim reports the primary verified
address. Adding an address sends a link to `settings/emails/verify#token=…`,
which works once for 24 hours. The page verifies only when its button is pressed,
since mail scanners follow links, and needs no session. Adding an address,
changing the primary one and removing one need a passkey confirmation, like other
sensitive changes. An account sends at most 5 verification emails an hour, a
client IP at most 10, and one mailbox, whatever the case and `+` tag of its
address, receives at most 3. An address another active account verified cannot be
verified again; adding it is allowed, so adding reveals nothing. The email names
the account the address would join, and a browser signed in to another account
cannot confirm it. An address that stops being primary, or is removed, is told.

Auth sends email through the delivery queue, never from a request. Messages are
transactional security notices: no tracking, no remote images, and links only to
the settings site. Without `AUTH_SMTP_URL`, adding an address is refused and
queued messages are dropped. Any SMTP provider works; deployments use Resend's
relay, as `infra/README.md` describes. The provider must not depend on Piquel's own
sign-in. For development, `just auth mailpit` runs a local Mailpit: set
`AUTH_SMTP_URL=smtp://localhost:1025` and read the mail at
`http://localhost:8025`. Sending domains need SPF, DKIM and DMARC; see
[infra/README.md](infra/README.md#email).

### Outbound deliveries

Messages for other systems, such as back-channel logout tokens and email, wait in
a queue in the database until a worker sends them. Inspect and repair it with:

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
just auth client update notes --backchannel-logout-uri https://notes.example/auth/backchannel-logout
just auth client disable notes       # enable undoes it
just auth client rotate-secret notes --grace 24h
just auth client suspend notes       # its owner cannot enable it; unsuspend lifts it
just auth client delete notes        # for good: the ID is never reused
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

Accounts can also register clients for their own applications, through the
account API: see [Managing your own OIDC clients](docs/guides/client-management.md).
Auth generates their IDs and limits their scopes to `openid`, `profile`, `email`
and `offline_access`; they are never trusted, and an account can have 10 and
register 20 a day. They never appear in the account API of other accounts, while
`client list` shows every client. Owners can disable and enable their clients;
`client suspend` disables one so that its owner cannot enable it until
`client unsuspend`, which leaves it disabled. Deleting a client, from either side, disables it, revokes its
refresh tokens and removes its secrets and consents. Its ID stays reserved, since
tokens carry it as `aud`.

### Back-channel logout

When a session at auth ends, every client that received tokens from it and
registered a `--backchannel-logout-uri` is told (OIDC Back-Channel Logout 1.0), so
it can end its own session for the user. Every way a session ends early does
this: signing out, RP-initiated logout, signing in to another account, signing out
other devices, removing a passkey, unlinking a provider, reporting a history entry,
and an administrator revoking sessions or disabling the account.
`--no-backchannel-logout-uri` stops it.

Auth posts `logout_token=<JWT>` as `application/x-www-form-urlencoded` to the URI.
The token is signed with auth's token key, with the header `typ: logout+jwt`:

```json
{ "iss": "https://auth.piquel.fr", "aud": "<client_id>", "iat": 1760000000,
  "exp": 1760000120, "jti": "<delivery id>", "sub": "<user id>",
  "sid": "<session id>",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} } }
```

`sid` is the `sid` of the ID tokens the client received. A client must validate the
token as Back-Channel Logout 1.0 §2.6 says (signature, `iss`, `aud`, `iat`, `exp`,
`events`, no `nonce`), end its sessions with that `sid` unless it already applied the
token's `jti`, and answer `200` either way. The Rust SDK's login routes do all of
this at `POST <mount>/backchannel-logout`. A `400` fails the delivery for good;
timeouts and `5xx` are retried with backoff for up to an hour. Every attempt is
signed afresh and carries the same `jti`, so a receiver applies a repeat only once.
The URI must be HTTPS and resolve to public addresses, and redirects are not
followed.
Delivery is asynchronous: an application's session may outlive auth's by the few
seconds a delivery takes, or until it expires if the client cannot be reached.

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
rotating refresh tokens, revocation, RP-initiated and back-channel logout. Access tokens are
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
  account picker and a handle fallback.
- An account's handle is its public identifier and login name, released as
  `preferred_username`: 3–32 characters of `[a-z0-9-]`, without a leading, trailing
  or double hyphen, so it is a valid DNS label. Signup trims and lowercases it, and
  refuses reserved names (infrastructure labels such as `auth` and `www`, RFC 2142
  mailboxes, piquel.fr routes and the brand) and names that look like one: hyphens
  are dropped, and `0`, `1` or `i`, `5`, `rn` and `vv` read as `o`, `l`, `s`, `m` and
  `w`. Look-alikes of other accounts' handles are refused from the next release,
  which enforces them in the database; until then `handle check` lists them.
  Usernames from before these rules still sign in until an operator renames them.
- Social-first signup remains pending until its first passkey is committed. Only
  a registration that names the pending identity shown on the signup page attaches
  it; plain registration ignores it. A social login can never replace an
  established account's passkeys.
- Sensitive changes (adding or removing a passkey, linking or unlinking a provider,
  adding, removing or changing the primary email address) need a passkey confirmation of the current browser session from the last five
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
  detects reuse and stops when its central session expires or is revoked. Ending a
  session tells the clients that registered a back-channel logout URI, which end
  their own sessions; already issued access tokens stay valid until they expire.
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
| Run with caller-provided auth configuration | `just auth serve`, `just db migrate`, `just auth invite create --expires-in 7d`, `just auth admin list` |

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
