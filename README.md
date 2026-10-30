# piquel.fr

A monorepo for piquel.fr and its services. The first release is a passkey-first
OIDC/SSO authority at `auth.piquel.fr`, which also serves the account settings and
the developer console.

The authentication service is **one Rust executable** containing its login,
onboarding, consent, passkey, settings and developer console pages. PostgreSQL is its only external
data service. GitHub and Google are optional login providers. The same executable
serves the admin dashboard at `admin.piquel.fr`, on a listener of its own, and
`piquel.fr` redirects to auth, keeping the path. See
[infra/README.md](infra/README.md) for repository-driven piqueld deployments.

## Build

Requires Rust (pinned by `rust-toolchain.toml`) and just 1.42+. Building needs no
database: SQL is checked against the committed query cache in
`crates/database/.sqlx/`. It needs no Node either: nothing builds JavaScript.

```sh
just build
```

The executable is `target/release/auth-service`. It embeds the stylesheet
(`crates/ui/assets/style.css`) and the passkey script
(`apps/auth-service/assets/passkey.js`) as they are; rebuild Rust after changing
them.

## Development

Develop through the HTTPS preview on piqueld:

```sh
just preview
```

This snapshots this checkout, including uncommitted changes, builds auth and the
admin dashboard, applies migrations, and prints the preview's URLs; the settings
are at `/settings`, and the developer console at `/developers`, on its auth URL. The preview has its own database and keys. URLs
work from devices on the tailnet. Run the same command after changing code.
`just preview-delete` removes it.

## Configuration

| Variable | Meaning |
| --- | --- |
| `AUTH_DATABASE_URL` | PostgreSQL URL; TCP requires `sslmode=verify-full`, or an explicit `sslmode=disable` on a trusted private network; local Unix sockets are also supported |
| `AUTH_DATABASE_PASSWORD` | Optional env/file reference for the database password, when omitted from the URL |
| `AUTH_DATABASE_OWNER_URL`, `AUTH_DATABASE_OWNER_PASSWORD` | Optional schema owner `migrate` connects as instead, in the same formats. It then creates or resets the role `AUTH_DATABASE_URL` names, with the `AUTH_DATABASE_PASSWORD` password and only row access to the app tables. The owner must be a superuser |
| `AUTH_PUBLIC_BASE_URL` | Exact auth origin, normally `https://auth.piquel.fr` |
| `AUTH_TRUSTED_PROXIES` | Optional comma-separated proxy peer IPs or CIDRs; these peers must overwrite `X-Forwarded-For` with one client IP. Defaults to piqueld's `PIQUELD_INGRESS_PROXIES` |
| `AUTH_PUBLIC_LISTENER` | Listener address; defaults to `127.0.0.1:8080` |
| `AUTH_ADMIN_LISTENER`, `AUTH_ADMIN_ORIGIN` | Optional address of the admin dashboard's listener, e.g. `0.0.0.0:8081`, and the dashboard's origin, e.g. `https://admin.piquel.fr`, set together. Only a private route may reach the listener. Without them, auth serves no dashboard |
| `AUTH_KEY_ENCRYPTION_KEY` | Required env/file reference to the key that seals [signing keys](#signing-keys) in the database: 32 bytes as unpadded base64url text. A trailing newline is ignored |
| `AUTH_TOKEN_DIGEST_KEY` | Required env/file reference to the key under which refresh tokens, authorization codes and pending logins are stored as HMAC digests. Its raw bytes are the key, at least 32 of them. Email verification links and recovery links derive from it too |
| `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` | Optional env/file reference to another token digest key, accepted but never used for new digests: the next key, or the old one (see [changing the token digest key](#changing-the-token-digest-key)) |
| `AUTH_AUDIT_KEY_PROVIDER` | Required env/file reference to the key that signs audit checkpoints: a 32-byte Ed25519 seed as 64 hex characters. See `docs/security/audit-history.md` |
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

Generate either key with `just auth generate-secret /absolute/path` (uses the
OpenSSL CLI; piqueld generates its own, see `infra/README.md`), and an audit key
with `openssl rand -hex 32 > /absolute/path/audit-key`. Keep them across
restarts, and give every replica the same ones. The key-encryption key cannot be
changed yet: the stored signing keys would no longer open. Replacing the token
digest key at once ends every refresh token and every login in progress, so
change it in two deploys (see below). Verification links already sent keep
working, but a verification email still queued at the change carries a link
that does not.

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

### Signing keys

Auth signs ID and access tokens with RSA keys kept in PostgreSQL, each private
key sealed with AES-256-GCM under `AUTH_KEY_ENCRYPTION_KEY`. Keys rotate without
a deploy, and every replica reloads them each minute:

| State | Signs | In JWKS | Its tokens verify | Lasts |
| --- | --- | --- | --- | --- |
| `next` | no | yes | yes | 24 hours, then it signs |
| `active` | yes | yes | yes | 90 days, then a `next` key is published |
| `retiring` | no | yes | yes | 65 minutes: the 5-minute token lifetime plus the JWKS cache lifetime |
| `retired` | no | no | as `id_token_hint` only | 30 days, the longest session, then it is deleted with its public key |

JWKS is served with `Cache-Control: public, max-age=3600`, so a `next` key is
published long before any verifier needs it. A retired key's private key is
erased, but logout and authorization still accept the expired ID tokens it
signed as hints. On first start with no keys, auth generates one that signs at
once. One replica at a time takes each step, under a PostgreSQL advisory lock
that the `keys` commands take too. None of them needs the service running:

```sh
just auth keys list                  # IDs, states and dates
just auth keys rotate                # publish a next key; it signs in 24 hours
just auth keys rotate --now          # or sign with it at once
just auth keys revoke <id>           # delete a key at once
just auth keys digest-usage          # stored token digests per digest key
just auth keys import file:///path/key.pem   # import a PEM key into an empty key set
```

`keys rotate` publishes the next key ahead of schedule. It still waits 24 hours
before signing, so no verifier meets an unknown key. `--now` skips the wait:
verifiers with a cached key set reject the new key's tokens until they fetch
keys again, which the SDKs do on an unknown `kid`, at most every 30 seconds.
Auth's own replicas reload within a minute, so until then a token from one may
fail at another.

#### Revoking a compromised key

`keys revoke <id>` deletes the key. If it was signing, the `next` and `retiring`
keys go with it, since their private keys were stored alongside, and a new key
signs at once.
Revocation takes effect in two places, at different times:

- **At auth:** within a minute, every replica stops accepting the key, for
  access tokens at `UserInfo`, and for `id_token_hint`s. The
  tokens it legitimately signed stop working at auth too, so their users sign
  in again through SSO.
- **Downstream:** verifiers that cached JWKS keep accepting the key until their
  cache expires: up to an hour with `max-age=3600`, and longer for verifiers
  that ignore `Cache-Control`. Whoever holds the key can mint tokens with any
  `exp`, so token lifetimes do not shorten this window; only the cache does.

After revoking, restart first-party resource servers, which drops their cached
keys; the SDKs keep a known key until their cache expires. Treat the hour as
the remaining exposure at third parties.

#### Changing the token digest key

Nothing rotates the token digest key; change it by hand, rarely, in two deploys,
so that during each rolling deploy, and after a rollback, every release accepts
what the other issues:

1. Set the new key as `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` and deploy.
2. Swap them: the new key as `AUTH_TOKEN_DIGEST_KEY`, the old one as
   `AUTH_TOKEN_DIGEST_KEY_ACCEPTED`, and deploy. New digests use the new key.
3. Remove `AUTH_TOKEN_DIGEST_KEY_ACCEPTED` once `keys digest-usage` lists only
   `current`: about 30 days later, since refresh tokens end with their session,
   and a redeemed code is kept while the grant it produced lives.
   Removing it sooner ends the refresh tokens still under it.

Each stored digest records a fingerprint of its key, and `keys digest-usage`
counts them per key, until cleanup deletes them, named `current`, `accepted`, `unrecorded`
(made before fingerprints were recorded, under the old PEM signing key) or
`unknown`.

### Invitations

```sh
just auth invite create --expires-in 7d
just auth invite list
just auth invite revoke <id>
```

`create` prints one signup link, to `/register` with the invitation filled in. A
signup through GitHub or Google asks for the invitation on its own page. The
database stores a digest, expiry and redemption time. Tokens expire after seven days by default; `h` and `d` are supported. A token
is redeemed atomically with account creation, so a failed signup does not spend it.
Disabling invitation enforcement affects signup only; existing users keep access.
Administrators can also list, create and revoke invitations from the admin dashboard.

### Administration

Every administrative operation has a command, which runs the same code as the
admin dashboard (`AdminService` in `apps/auth-service/src/admin`), and so does every
setting administrators may change on another account (`AccountService` in
`apps/auth-service/src/account`). Commands need only `AUTH_DATABASE_URL`, so they
work while auth is down: they are the break-glass path when the dashboard or
auth's frontends are unreachable. `invite create` also needs
`AUTH_PUBLIC_BASE_URL`, to build its link; `user recover` needs it and
`AUTH_TOKEN_DIGEST_KEY`, to derive its link; `client origin add` needs it to tell
auth's own domain apart; and `audit verify` and `audit prune` need it to pick the
environment's audit key. `audit prune` connects as the schema owner (see
[audit-history.md](docs/security/audit-history.md#pruning)). In deployed
environments, run them with `piquelctl app exec piquel-fr auth --env ENV --
auth-service …` (see [infra/README.md](infra/README.md)).

```sh
just auth admin grant alice               # the first administrator is granted here
just auth admin list
just auth admin revoke bob                # the last administrator's rights stay
just auth user search ali                 # by ID, or part of a handle, name or email
just auth user show alice                 # recorded, since it shows personal data
just auth user disable alice --reason "Spam"
just auth user enable alice
just auth user recover alice --reason "Lost every passkey"
just auth user recover alice --reason "Phone stolen" --revoke --keep <passkey-id>
just auth user undo-recovery alice --reason "Owner confirmed by phone"
just auth user delete alice --reason "Asked by email"   # see Data export and account deletion
just auth user restore alice --reason "Changed their mind"
just auth session revoke <session-id>     # one session, as `user show` lists it
just auth session revoke-all alice        # every session of the account
just auth audit list --user alice --kind session_revoked
just auth audit verify                    # recompute the tamper-evident chain
just auth account alice passkeys list     # the account's settings, as its owner sees them
just auth account alice passkeys revoke <passkey-id> --reason "Phone stolen"
just auth account alice emails remove <email-id> --reason "Asked by email"
```

- Accounts are named by handle, ID or a verified email of an active account.
- `--output json` prints the views the dashboard shows for `user search`
  (`UserPage`), `user show` (`UserDetail`), `audit list` (`EventPage`), `client
  list`, `invite list` and `admin list`, as defined in `piquel_common::admin`.
  `audit verify --output json` prints the verification.
- `audit verify` and `audit prune` are described in
  [audit-history.md](docs/security/audit-history.md). `audit prune` connects as
  the schema owner when `AUTH_DATABASE_OWNER_URL` is set, since auth's own role
  may not delete events.
- `user disable|delete`, `user recover`, `user undo-recovery`, `session revoke-all`,
  `admin revoke`, `client disable|suspend|delete`, `audit prune`, and `account …
  passkeys revoke`, `identities unlink` and
  `sessions revoke-all` describe what they will change and ask for confirmation.
  Without a terminal they refuse unless given `--yes`.
- `account <user>` reads and changes the settings administrators share with the
  owner: passkeys, social identities, email addresses, sessions and the security
  history, with the owner's own operations. It never adds a way to sign in or an
  address. Every change needs `--reason`, which the owner sees in their history;
  reads are recorded as views. See
  [surfaces.md](docs/architecture/surfaces.md#changing-an-account-on-its-owners-behalf)
  for what is shared.
- `user recover` is for an owner who lost every passkey. It signs the account
  out everywhere, removes its unverified addresses, and emails its primary
  verified address a link to auth's `/recover`, which enrolls one passkey, once,
  within a day; it prints the link too, for an owner without an address. For 15
  days after, that passkey signs in but confirms no change, and any other passkey
  of the account can undo the recovery, which takes back its passkey, every
  session and every app consent. Until then, nobody removes a passkey but the
  recovery's own.
  - It first lists the account's recoveries of the last 15 days. While one is in
    probation, it refuses: find out who used it, and undo it with `user
    undo-recovery` first. An unused link is just replaced.
  - `--revoke [--keep <passkey-id>…]` is for an account that was in someone
    else's hands: it also revokes every passkey not kept, unlinks every social
    identity and withdraws every consent, and only prints the link. Remove the
    addresses the owner doesn't recognize afterwards, before handing the link
    over.
  - `user undo-recovery` undoes the account's recovery for an owner with no other
    passkey, or whose account is disabled, once support has confirmed them.
  - Before running either, follow the evidence policy in
    [account recovery](docs/security/account-recovery.md#supports-evidence-policy).
    Every reason shows in the account's history: write what was asked, never the
    evidence.
  - It never recovers an account while it holds administrator rights: revoke them
    with `admin revoke` first (grant another administrator first if it is the
    last). `admin grant` refuses while a recovery of the account can still be
    undone; grant the rights again once it settles.
- Each change is recorded as a domain event with the operator: `$USER` and the host
  name. Unlike the dashboard, the CLI may act on administrators' accounts, except
  to recover one.
- Failures print their causes and exit with 1; usage errors exit with 2.

Administrators manage accounts, sessions, invitations, other administrators and
the origins approved for clients' pages to sign users in from the admin dashboard,
which auth serves on `AUTH_ADMIN_LISTENER` for the dashboard's origin,
`AUTH_ADMIN_ORIGIN`, and which only a private route reaches.
Its pages call `AdminService` in-process; there is no admin API.

An administrator signs in by a handoff from auth: the dashboard sends the browser
to auth's `/admin` page, which needs a session signed in with a passkey, of an
account that still holds administrator rights, and sends it back with a
single-use code bound to that session and to the dashboard's state cookie. The
dashboard's session lasts while that auth session does, and every request checks
the administrator's rights again, so revoking either takes effect at once.
Changes also need the dashboard's own passkey confirmation from the last five
minutes, which the administrator gives on auth's `/admin` page, for the dashboard
only. See [surfaces.md](docs/architecture/surfaces.md#adminpiquelfr).

The dashboard never changes an administrator's account: revoke their rights first.
Administrators cannot grant or revoke their own rights, and nobody can revoke the last
administrator's. Every change is recorded as a domain event with its administrator
or CLI operator.

### Handles

```sh
just auth handle check                                  # accounts whose handle is reserved
just auth handle rename old-name new-name --reason "…"  # --allow-reserved to assign a reserved name
just auth handle release old-name                       # let anyone claim a released handle again
```

Operators rename without the 30-day cooldown of settings renames, but not to a
handle another account holds or held, or one that looks like it (see
[Security behavior](#security-behavior)). A rename bumps the account's profile
version, so relying parties refresh `preferred_username`. `release` deletes a
handle no account holds anymore, the only way one returns to the pool, for cases
like a trademark dispute; to free a current handle, rename its account first.
Every change is recorded as a domain event with its operator; a rename also with
its reason, which the owner sees in their history. Administrators rename from the
dashboard the same way, with a reason.

Upgrading from a release that stored usernames: run its `handle check`, and rename
every account it lists with its `handle rename`, before deploying. The migration
that moves usernames into handles refuses to run, naming them, while any remain.

### Email

Accounts add, verify, choose the primary of and remove their addresses on
`auth.piquel.fr/settings/emails`; the OIDC `email` claim reports the primary verified
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
auth's settings pages. Without `AUTH_SMTP_URL`, adding an address is refused and
queued messages are dropped. Any SMTP provider works; deployments use Resend's
relay, as `infra/README.md` describes. The provider must not depend on Piquel's own
sign-in. For development, `just auth mailpit` runs a local Mailpit: set
`AUTH_SMTP_URL=smtp://localhost:1025` and read the mail at
`http://localhost:8025`. Sending domains need SPF, DKIM and DMARC; see
[infra/README.md](infra/README.md#email).

### Data export and account deletion

Owners download their data and delete their account on
`auth.piquel.fr/settings/data`. Both need a passkey confirmation from the last five
minutes, checked under the account lock, so no administrator can do either for
them, and neither can a session that never confirms, such as a recovery's
probation sign-in.

- **Download** sends one versioned JSON file (`"format": "piquel.account-export"`):
  profile, the handles it holds or held, email addresses, passkeys (label, dates
  and backup state, no key material), linked identities, devices with their IP
  addresses, an administrator's dashboard sign-ins, consents, refresh grants, the
  apps the account registered, its recoveries (dates, state and the passkey each
  enrolled, never a link) and the security history. It is read
  from one snapshot, holds no secret or digest, nothing may cache it, and it is
  recorded in the history.
- **Deleting** asks for the account's handle. The account becomes `deleting`, every
  session and refresh grant ends, their apps receive back-channel logout tokens, and
  it can no longer sign in or authorize. For 30 days, signing in with one of its
  passkeys asks to restore it instead of signing in: the offer, valid for five
  minutes and used once, lives in its own cookie, and restoring signs in with that
  passkey, as its sign-in would have: a recovery's passkey in probation confirms
  nothing.
- **Purge:** every five minutes, one replica purges the accounts past their grace
  period. It deletes the apps the account registered, leaving tombstones without
  an owner, then the account with its emails, passkeys, identities, sessions,
  grants, consents and email deliveries, and the personal data (IP, device,
  provider subjects, operators' reasons) of every event it is the subject or actor
  of. The events stay, with pseudonymous IDs only. Its handles stay in the handles
  table without an owner, so no account claims them until an operator releases
  them (`handle release`).

Administrators schedule and restore deletions from the account's page on the
admin dashboard, with a reason the owner sees in their history. Operators do the
same with the CLI, which alone also purges at once, in any status, since that
cannot be undone:

```sh
just auth user delete alice --reason "Asked by email"         # 30 days of grace
just auth user restore alice --reason "Changed their mind"
just auth user delete mallory --immediately --reason "Spam"   # cannot be undone
```

Nobody can delete the last active administrator's account. Auth does not email the
account about its deletion yet, and the signals that tell applications to erase
their records come with #66 and #97.

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
just auth client create blog --name Blog --trusted \
    --redirect-uri https://blog.piquel.fr/callback --post-logout-uri https://blog.piquel.fr/
just auth client create notes --name Notes --confidential --refresh \
    --redirect-uri https://notes.example/callback --scope openid --scope notes:read
just auth client list                # --output json for scripts
just auth client show notes          # registration and secret lifetimes
just auth client update blog --add-redirect-uri https://blog.piquel.fr/auth/callback
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

Accounts can also register clients for their own applications in the developer
console, at `auth.piquel.fr/developers`: see
[Managing your own OIDC clients](docs/guides/client-management.md).
Auth generates their IDs and limits their scopes to `openid`, `profile`, `email`
and `offline_access`; they are never trusted, and an account can have 10 and
register 20 a day. They never appear in other accounts' consoles, while
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
client and scope; explicitly trusted clients bypass consent. Users see the apps
they consented to, or whose refresh grants still work, under Connected apps in
settings (`/settings/apps`), and remove an app's access there: its refresh grants
end, it asks for consent again, and its outstanding codes stop working. Access
tokens it already holds expire within five minutes. An administrator removes one
the same way from the account's Connected apps page on the dashboard, with a
reason the owner sees in their history.

#### Passkey sign-in on an application's own pages

A trusted client's pages can sign users in with their auth passkeys without
leaving for auth's pages, through WebAuthn related origins (WebAuthn Level 3
§5.11). An administrator approves each origin on the dashboard's Clients page,
which lists them, or with the CLI:

```sh
just auth client origin add blog https://blog.example
just auth client origin list         # --output json for scripts
just auth client origin remove blog https://blog.example
```

The client must be trusted, since this sign-in skips the consent page, and the
origin must be the origin of one of its redirect URIs. Browsers honour only a few
distinct domains in the list, so approved origins may span at most 5 registrable
domains (`example` counts once for `app.example.co.uk` and `www.example.co.uk`).
Browsers count origins within auth's own domain too, as `piquel`; a host without a
registrable domain, such as `localhost`, counts none and is accepted only within
auth's domain. `/.well-known/webauthn` lists the approved origins, cacheable for
five minutes and readable from any origin. Auth refuses a removed origin's
sign-ins at once, and deleting a client removes its origins.

The page pushes an authorization request with PKCE, from its own origin, then posts
its `request_uri` as `{"request_uri": …}` to `/webauthn/related/start`, with
`content-type: application/json` and `x-piquel-csrf: 1`. It runs the WebAuthn
assertion the answer describes, then posts `{"ceremony_id": …, "credential": …}`
to `/webauthn/related/finish`, which answers `{code, state, iss}` as JSON instead
of redirecting. The page checks `state` and `iss`, and redeems the code with its
verifier as usual. These calls send no cookies and get none: the sign-in creates a
session that only the client's tokens use, recorded with the page's origin in the
user's security history. A request with `prompt=consent` or `prompt=none`, or an
`id_token_hint` naming an account without passkeys, is refused at start with
`interaction_required` and left unclaimed, so the page can send the browser to
`/oauth/authorize?client_id=…&request_uri=…` with it instead. Finish answers
`interaction_required` when the sign-in falls short of the request, such as a
recovered passkey during its probation against `acr_values=phr`, or when the
account is scheduled for deletion, which only auth's pages restore; the request was
claimed at start, so the page pushes a fresh one before sending the browser to
auth with it. The page should also redirect when the browser lacks related origins
(`PublicKeyCredential.getClientCapabilities()` has no `relatedOrigins`), and push a
fresh request first when a start or the passkey prompt failed, since auth may have
claimed the first one.

### Authentication claims

ID and access tokens report how the browser session behind the grant
authenticated:

| Claim | Values |
| --- | --- |
| `acr` | `phr` once a passkey confirmed the session, which a passkey sign-in does: phishing-resistant multi-factor authentication ([OpenID Connect EAP ACR Values](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)). `urn:piquel:acr:social` for a session signed in with GitHub or Google only, the provider's authentication, whatever it was; and for one signed in with a recovered passkey until its recovery settles |
| `amr` | Every method the session used (RFC 8176): `pop`, `mfa` and `user` for a passkey, which proves possession of a key and requires user verification; `fed` for a provider sign-in. RFC 8176 registers no value for federation, so `fed` is Piquel's own. It says how, not how strongly: gate on `acr` |
| `auth_time` | The latest authentication at the session's `acr`: its last passkey confirmation, or else its sign-in |

`phr` satisfies a `urn:piquel:acr:social` requirement, not the reverse. Both values
are listed in discovery's `acr_values_supported`. An authorization request may send
`acr_values` in order of preference: the first known value becomes its target, and
unknown values are ignored. A session below the target signs in again, on a login
page offering only passkeys for `phr`; with `prompt=none` the request fails with
`login_required`. If a passkey sign-in for the request still falls short, as a
recovered passkey does, the request fails with `unmet_authentication_requirements`
rather than asking again. With no known value, the tokens report what the session
reached.

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
  passkeys and security keys are accepted. On Android, signup and adding a passkey
  offer an explicit Google Password Manager option for devices with Google services,
  never chosen automatically; a standard passkey or security key stays the default.
  Authentication supports the browser account picker and a handle fallback.
- An account's handle is its public identifier and login name, released as
  `preferred_username`: 3–32 characters of `[a-z0-9-]`, without a leading, trailing
  or double hyphen, so it is a valid DNS label. Signup trims and lowercases it, and
  refuses reserved names (infrastructure labels such as `auth` and `www`, RFC 2142
  mailboxes, piquel.fr routes and the brand) and names that look like one: hyphens
  are dropped, and `0`, `1` or `i`, `5`, `rn` and `vv` read as `o`, `l`, `s`, `m` and
  `w`. Every handle and look-alike stays unique, current or not: a handle is not
  reassigned to another account unless an operator releases it, though its former
  owner may take it back. Handles are not secret: handle sign-in says when no
  active account has one, and signup names the look-alike that blocks one (see
  [handles.md](docs/security/handles.md)).
  The sign-in methods settings change the handle, which needs a passkey
  confirmation like other sensitive changes and is refused within 30 days of the
  last change, saying when it may change again.
- Social-first signup remains pending until its first passkey is committed. Only
  a registration that names the pending identity shown on the signup page attaches
  it; plain registration ignores it. A social login can never replace an
  established account's passkeys.
- Sensitive changes (changing the handle, adding or removing a passkey, linking or unlinking a provider,
  adding, removing or changing the primary email address, and registering an OIDC
  client, rotating its secret, deleting it or changing its redirect or post-logout
  URIs) need a passkey confirmation of the current browser session from the last five
  minutes. A passkey sign-in counts; social sign-in never does. The age counts from
  the confirmation and is never extended by use, and it never applies to another
  session. Without one, a page asks for the passkey before it posts the change, or,
  for a client's URIs, once the change is refused; the API answers `403` with
  `"code": "step_up_required"` and `max_age`. Reads, renaming a passkey and a
  client's other settings need only ordinary login.
- Matching verified email suggests linking; it never grants account access.
  Linking requires possession of the provider account and the target account's
  passkey confirmation. Explicit linking, started from settings, permits
  different/missing provider email and is bound to the session that started it.
- One Google and one GitHub identity may be linked. Unlinking releases the provider
  identity so another account can link it; account data and credentials never move.
  Settings keep listing identities of disabled providers so they can be unlinked.
- The last passkey cannot be removed. Removing a passkey/provider revokes other
  central sessions. An owner who lost every passkey is recovered with a link to
  auth's `/recover` that enrolls one new passkey; for 15 days after, it confirms
  no change, and another passkey of the account can undo the recovery on
  `/recover/undo` (see
  [surfaces.md](docs/architecture/surfaces.md#recovering-an-account)).
- Sessions last at most 30 days. Access tokens last five minutes. Refresh rotation
  detects reuse and stops when its central session expires or is revoked. Ending a
  session tells the clients that registered a back-channel logout URI, which end
  their own sessions; already issued access tokens stay valid until they expire.
- Browser state and opaque secrets are random, hashed where lookup is needed, and
  bound to the initiating browser. Auth cookies are host-only, Secure and HttpOnly.
  Mutations require an exact allowed origin and CSRF header; OIDC back-channel
  endpoints instead validate their protocol credentials. A form posted to one of
  auth's server-rendered pages must come from auth's own pages: `Sec-Fetch-Site:
  same-origin`, or the auth origin when the browser sends no `Sec-Fetch-Site`.
- Request throttling and expiring-state cleanup use PostgreSQL. Throttling uses separate login, token, userinfo, account and page budgets per client IP, and covers every API route except health probes and discovery.
  By default it uses the direct peer IP; only peers in `AUTH_TRUSTED_PROXIES`
  may supply a single overwritten `X-Forwarded-For`. Configure this when terminating TLS
  at a reverse proxy so users do not share the proxy’s budget. Untrusted headers
  are ignored; missing/ambiguous headers from a trusted proxy fail closed. Security events are
  retained; the IP addresses, browser families and provider subjects recorded with
  them are deleted after 90 days. Readiness checks PostgreSQL; startup validates configured signing/provider
  secrets. Request and provider calls have bounded timeouts.

## Validation

`just` runs `validate` by default.
`just install` installs the web tools, Prettier, ESLint, tsc and Playwright, which
need Node 24+ and pnpm (the workspace pins its version).
`just install-tools` installs `cargo-nextest`, `cargo-deny` and `sqlx-cli`. The
`db` recipes also need the PostgreSQL 18 server binaries (`initdb`, `pg_ctl`).
Recipes are grouped into `rust`, `web`, `db`, `auth`, `admin` and `infra` modules under
`just/`; `just --list --list-submodules` shows every recipe. The root `fmt`,
`fmt-check`, `lint`, `check` and `audit` run the same recipe in `rust` and `web`.
Use individual recipes while iterating:

| Task | Recipe |
| --- | --- |
| Full validation (format, Clippy/ESLint, Rust/TypeScript checks, unit/doc tests, audits) | `just validate` |
| Format Rust and web / check formatting | `just fmt` / `just fmt-check` |
| Rust / TypeScript checks (tsc, the passkey script's JSDoc types included) | `just rust check` / `just web check` |
| Clippy and ESLint, warnings denied | `just lint` (`just rust lint` / `just web lint`) |
| Unit tests / focused package tests | `just test` / `just test -p auth-service` |
| Documentation tests | `just doc-test` |
| Database integration tests and query cache check, in a scratch cluster | `just db test` |
| Regenerate the query cache after changing SQL or migrations | `just db prepare` |
| Run any command against a scratch cluster | `just db scratch -- psql` |
| Browser tests against running servers | `just web test-browser` |
| Dependency audits | `just audit` (`just rust audit` runs cargo-deny, `just web audit` pnpm) |
| Debug binary / release binary | `just rust build` / `just build` |
| Run with caller-provided auth configuration | `just auth serve`, `just db migrate`, `just auth invite create --expires-in 7d`, `just auth admin list` |

CI runs these recipes on every pull request whose changes they can affect,
including the database and browser tests, and on every push to `main`.
Require its `ci` check: it summarizes the others.

Web code is formatted by Prettier and linted by type-aware ESLint (typescript-eslint
`strictTypeChecked`), configured once at the repository root.
Test recipes forward extra arguments to nextest or Playwright, including quoted
filter expressions. `just auth run` forwards arguments to the auth binary.
Cargo embeds the stylesheet, the passkey script and migrations during compilation.

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
