# Security boundaries

This page maps where trust changes in SourceOrigin: who can send what to auth, what
auth checks at each crossing, and where in the code that check lives. Read it
before you change a listener, a role, a secret or an outbound call. The
[threat model](threat-model.md) builds on it, and
[security properties](properties.md) lists the guarantees in detail.

## The zones

```text
 Internet                                      Tailnet
 ─────────────────────────────────             ──────────────────────────────
 browsers, relying parties                     administrators, operators
        │                                              │
        ▼                                              ▼
 Cloudflare Tunnel or the gateway (TLS)        private route admin.sourceorigin.dev
        │                                              │
 ═══════╪══ piqueld application network ═══════════════╪═══════════════════
        ▼                                              ▼
 ┌──────────────────────────────── auth-service ──────────────────────────┐
 │ public listener :8080                     admin listener :8081         │
 │ OIDC, sign-in pages, settings, console    admin dashboard              │
 │                                                                        │
 │ secrets mounted from piqueld: key-encryption key, token digest keys,   │
 │ audit key, SMTP and provider secrets, runtime role password            │
 └──────┬─────────────┬──────────────┬──────────────┬─────────────┬───────┘
        │ sourceorigin_auth │ HTTPS        │ HTTPS        │ SMTP, TLS   │ OTLP
        ▼             ▼              ▼              ▼             ▼
   PostgreSQL    GitHub,        logout URIs,   Resend relay   telemetry
   (owner role:  Google         pictures:                     collector
    migrate)                    public only

 auth-service CLI ──▶ PostgreSQL directly: database access is the root of trust
```

`sourceorigin-web` and the documentation also sit behind the public routes, but hold
no state and no secret: sourceorigin.dev links to auth and never shares its database,
keys or process ([surfaces](../architecture/surfaces.md#sourceorigindev)).

## The internet and the public listener

**What crosses:** every browser request to auth.sourceorigin.dev and every relying
party's call to the OIDC endpoints. TLS ends at the Cloudflare Tunnel or the
gateway; auth listens on plain HTTP on the application's private network
(`AUTH_PUBLIC_LISTENER`, `infra/piqueld.toml`). Staging and previews are private
routes, so only the tailnet reaches them
([deploying](../operations/deploying.md)).

**What is checked**, by `HttpSecurity` in
`apps/auth-service/src/security/http.rs`, before any route runs:

- **The client's address.** Only a peer in `AUTH_TRUSTED_PROXIES`, or piqueld's
  `PIQUELD_INGRESS_PROXIES`, may name the client in `X-Forwarded-For`, and a
  missing or repeated header from one fails closed (`client_ip`).
- **The request budget.** Each route belongs to a rate category
  (`apps/auth-service/src/security/endpoint.rs`), counted per client IP in
  PostgreSQL. Only health probes and discovery are uncounted.
- **The browser's origin.** A JSON mutation needs an allowed `Origin` and the
  `x-sourceorigin-csrf` header. A form posted to a page must come from auth's own pages
  (`check_browser`). Protocol endpoints skip this and check their own
  credentials: client authentication, PKCE, codes and tokens.
- **Size and time.** Bodies are limited to 64 KiB, except a profile picture's
  upload, and each request to 30 seconds (`MAX_REQUEST_BODY_BYTES` in
  `apps/auth-service/src/lib.rs`, `REQUEST_TIMEOUT`).
- **Caching.** Auth sets every `Cache-Control` itself, and anything not marked
  cacheable is `no-store` ([caching](../operations/deploying.md#caching)).

Behind those checks, the session cookie (`__Host-sourceorigin_session`) identifies the
account. Auth stores only its SHA-256 digest
(`apps/auth-service/src/security/session.rs`). Sensitive changes also need a
passkey confirmation from the last five minutes
([properties](properties.md)).

## The tailnet and the admin listener

**What crosses:** administrators' requests to the admin dashboard. Its route is
private in every environment, so only the tailnet reaches it
(`infra/piqueld.toml`, route `admin`).

**What is checked:** the network path is a second wall, not the authorization
([admin.sourceorigin.dev](../architecture/surfaces.md#adminsourceorigindev)). The admin
listener refuses any request that does not name the dashboard's host
(`Listener::Admin` in `security/http.rs`), takes forms only from the dashboard's
own pages, and spends a budget of its own. An administrator signs in by a
handoff from an auth session that signed in with a passkey, and every change
needs the dashboard's own passkey confirmation from the last five minutes. Only
`DashboardSignIn` builds an `AdminSession`
(`apps/auth-service/src/admin/operator.rs`), so no other code acts as an
administrator.

Administrators may view and remove on an account's behalf, but never add a way
to sign in or to receive the account's email
([changing an account](../architecture/surfaces.md#changing-an-account-on-its-owners-behalf)).

## Auth and PostgreSQL

**What crosses:** every query auth makes, over TCP on the application's private
network, with SCRAM password authentication
([database](../operations/deploying.md#database)). Only `crates/database` runs
SQL.

Two roles hold different rights
([roles](../architecture/database.md#roles)):

| Role | Who connects as it | What it may do |
| --- | --- | --- |
| `sourceorigin`, the schema owner | the `migrate` job, and `audit prune` | Everything: it is PostgreSQL's superuser. It changes the schema and provisions the runtime role. |
| `sourceorigin_auth`, the runtime role | `serve` and every other command | Read and write rows. It inserts only the columns auth writes, so an event's time, transaction, position and chain columns keep their defaults on insert and it can't backdate them; sealing sets the chain columns once, in order, which triggers check, and verification checks their hashes. It may not rewrite sealed audit events or checkpoints, move the audit anchor, change the schema, disable triggers or run programs on the server. |

`Database::provision` grants the runtime role its rights on every `migrate`, from
`crates/database/src/connection/runtime_role.sql`. Triggers in the migrations
hold the rules a way into an account depends on, for every writer
([database backstops](account-recovery.md#database-backstops)).

**What it protects:** a SQL-level compromise of auth reaches rows, not history.
It cannot rewrite or delete sealed events
([audit history](audit-history.md#sealing)). It can still do anything rows
allow, such as insert a session or a passkey, so the runtime role's password is
as sensitive as the accounts themselves.

## Secrets and keys

piqueld mounts each secret into the auth containers as a file
(`infra/piqueld.toml`), and auth reads it through an `env://` or `file://`
reference at startup (`apps/auth-service/src/config`). No secret goes to a
frontend or into the image.

| Secret | Where it comes from | What it protects | Who can read it |
| --- | --- | --- | --- |
| Key-encryption key, `AUTH_KEY_ENCRYPTION_KEY` | Generated by piqueld | Seals the signing keys stored in PostgreSQL with AES-256-GCM, so a database dump holds no usable private key | Auth's containers |
| Signing keys | Generated by auth, stored sealed in `signing_keys` | Sign ID, access and logout tokens ([signing keys](../operations/signing-keys.md)) | Auth, with the key-encryption key |
| Token digest keys, `AUTH_TOKEN_DIGEST_KEY` and `_ACCEPTED` | Generated by piqueld | Refresh tokens, codes and pending logins are stored as HMAC digests under them; email verification, recovery and unsubscribe link tokens derive from them (`config/keys.rs`) | Auth's containers |
| Audit key, `AUTH_AUDIT_KEY_PROVIDER` | Stored by hand for staging and production, generated for previews | Signs audit checkpoints; its verifier keys are compiled in from `audit-key.pub` ([the audit key](audit-history.md#the-audit-key)) | Auth's containers |
| Client secrets | Generated by auth, or supplied by `client apply` | Authenticate confidential clients; auth stores only their SHA-256 digest (`ClientSecret` in `crates/crypto/src/lib.rs`) | The client's owner, once |
| GitHub and Google client secrets | Stored by hand ([sign-in providers](../operations/sign-in-providers.md)) | Auth's OAuth apps at the providers | Auth's containers |
| Resend SMTP key, `AUTH_SMTP_PASSWORD` | Stored by hand ([email](../operations/email.md#rotate-a-resend-key)) | Sending as the environment's domain only | Auth's containers |
| Database passwords | Generated by piqueld | The schema owner's goes to PostgreSQL and the `migrate` job only; the runtime role's to auth | As stated |

Session cookies, ceremony state and other browser secrets are random, and stored
only as digests where auth looks them up ([properties](properties.md)).

## The operator CLI

**What crosses:** `auth-service` commands, run in an auth container through
`piquelctl app exec`, or locally. Administrative commands need only the
database, so they work while auth is down
([administration](../operations/administration.md#the-command-line)).

**What is checked:** nothing beyond the database's own authentication. The CLI
connects as the runtime role and runs the same `AdminService` and
`AccountService` operations as the dashboard, with the same safety rules, but
needs no passkey: whoever can run it is trusted. It records its changes as
`Actor::Cli`, with `$USER` and the host name (`Operator::terminal` in
`apps/auth-service/src/admin/operator.rs`). The `keys` commands also need the
key-encryption key, and `user recover` the token digest key.

Database access is therefore the root of trust. Nothing SourceOrigin runs on may
require auth to sign in ([recovering auth](../architecture/surfaces.md#recovering-auth)),
and support's [evidence policy](account-recovery.md#supports-evidence-policy)
is what stands between an operator and a request to recover an account.

## Relying parties

**What crosses:** authorization requests, code exchanges, refreshes, UserInfo
calls and logout. Out go ID and access tokens, signed with RS256, and
back-channel logout tokens.

**What is checked** (`apps/auth-service/src/oidc`):

- Redirect URIs must match a registered one exactly, and every client uses S256
  PKCE (`oidc/authorize/parameters.rs`). A confidential client also
  authenticates with its secret.
- A code is tried once, and every step re-reads the client's registration
  ([codes, tokens and consent](../../user/reference/oidc.md#codes-tokens-and-consent)).
- Only the claims a client asked for, and the user consented to, are released.
  Apps registered in the developer console are never trusted, so they ask for
  consent unless the user already gave it for the scopes asked, and their scopes
  are limited ([OIDC clients](../operations/clients.md)).
- Browsers may call the token, revocation and UserInfo endpoints only from an
  enabled public client's redirect origins. Related-origin passkey sign-in is
  open only to the origins an administrator approved for a trusted client
  ([passkey sign-in](../../user/apps/passkey-sign-in.md)).

Access tokens last five minutes. Once issued, a token is the relying party's to
protect; ending the session doesn't recall it.

## GitHub and Google

**What crosses:** the browser's redirect to the provider and back, then auth's
own calls to exchange the code and read the identity
(`apps/auth-service/src/federation`).

**What is checked:** the flow is bound to the browser that started it by a
cookie, and the code exchange uses PKCE. Google's ID token is checked for its
signature against Google's keys, its issuer, an audience of auth's client alone
and the flow's nonce (`federation/providers/google.rs`). From GitHub, auth reads
the numeric account ID and, if shared, the verified primary email
(`federation/providers/github.rs`).

A provider's email suggests linking but never grants access, and a social
sign-in never counts as a passkey confirmation
([properties](properties.md)). Whoever controls a linked provider account can
therefore sign in, but can add no way in.

## Outbound deliveries

**What crosses:** back-channel logout tokens to the URIs clients register, the
profile picture a social signup imports, and email
([delivery queue](../architecture/delivery-queue.md)).

**What is checked:**

- **HTTP.** Destinations come from client registrations, which any account can
  supply. `OutboundClient` (`apps/auth-service/src/deliveries/outbound.rs`)
  sends only over HTTPS, to hosts that resolve only to public addresses,
  connects to the addresses it checked, uses no proxy, follows no redirect, and
  reads no answer's body except a profile picture's, up to its size limit
  ([outbound HTTP](../architecture/delivery-queue.md#outbound-http)).
- **Email.** Auth sends through the SMTP relay over TLS. Only a loopback relay
  may be reached without it (`config/email.rs`). A delivery stores no link
  token: the sender derives it again when it sends.

Payloads never hold a plaintext secret, and a delivery's error keeps a status
code or kind, never the receiver's answer.

## Telemetry

**What crosses:** traces, metrics and logs, over OTLP/HTTP to the telemetry
application's collector, inside piqueld (`OTEL_EXPORTER_OTLP_ENDPOINT`).

**What is checked:** nothing secret may be recorded: no cookie, code, token,
ceremony state, invitation or client secret, no request path, query string,
request header, client IP or user agent. Metric labels are `&'static str`, so no user or IP can
become one. The collector deletes path, query, address and header attributes as a
second line of defense (`infra/telemetry/collector.yaml`), and a test fails if
a sign-in or code exchange exports a secret
([what never goes in telemetry](../architecture/telemetry.md#what-never-goes-in-telemetry)).
User IDs are pseudonymous and may appear.
