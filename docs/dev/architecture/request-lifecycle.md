# Request lifecycle

This page follows one HTTP request through auth-service, from the listener to the
response. Read it before adding a route, so the route gets the right origin,
CSRF, rate and cache policy without code of its own.

```text
TCP listener (axum::serve, peer address attached)
 └─ HttpTelemetry::trace            span, access log, duration, X-Trace-Id
     └─ HttpSecurity::protect       30 s deadline around everything below
         ├─ host check              admin listener only
         ├─ origin check            Origin header against the endpoint's class
         ├─ preflight               OPTIONS answered here
         ├─ browser proof           same-origin forms, CSRF header
         ├─ rate limit              budget per category and client IP
         ├─ DefaultBodyLimit        64 KiB
         └─ router → extractors → handler → service → DatabaseTransaction
         decorate                   Cache-Control, isolation and CORS headers
```

## Listeners and routers

`Command::serve` (`apps/auth-service/src/cli/serve.rs`) binds the public listener
and, when the dashboard is configured, the admin listener. Each serves its router
with `into_make_service_with_connect_info::<SocketAddr>()`, so every request
carries its TCP peer's address.

The public router is `AuthConfig::router` (`src/lib.rs`). It merges every
feature's `XApplication::routes()`: the health probes, passkeys, federation,
history, notifications, audit checkpoints, account settings, email, pictures, the
server-rendered pages and OIDC. Paths it doesn't match fall back to the embedded
assets (`EmbeddedAssets::serve`). Every path is a constant in `src/routes.rs`,
which the routers, the discovery document and the security layer all read, so
they cannot disagree.

The admin router is `AuthConfig::admin_router`: only the dashboard's pages
(`AdminApplication` in `src/web/admin`), under a security layer of its own.

Both routers are wrapped the same way, outermost first: `HttpTelemetry`, then
`HttpSecurity::protect`, then the 64 KiB `DefaultBodyLimit`. The layers run after
routing, so they know the route template a request matched (`MatchedPath`).

## Telemetry

`HttpTelemetry` (`crates/telemetry/src/http`) wraps everything, so a request the
security layer throttles or refuses is still traced. Each request gets a root
span named after its method and route template, an access log line and a
duration measurement. A 5xx response marks the span failed and carries its trace
ID in `X-Trace-Id`. The admin listener labels all of it
`piquel.listener = "admin"`, and the health probes log at debug level only.
[Telemetry](telemetry.md) covers the rest.

## The security layer

`HttpSecurity::protect` (`src/security/http.rs`) runs every check and the handler
under one 30-second deadline; a request past it answers `504`. Each listener has
its own `HttpSecurity`: `HttpSecurity::new` for the public one, whose own origin is
auth's, and `HttpSecurity::admin` for the dashboard's.

### Endpoint classes

On the public listener, `Endpoint::classify` (`src/security/endpoint.rs`) sorts the
matched route template into one class, which the origin, CSRF and rate rules all
read:

| Class | Routes | Allowed origins | Rate category |
| --- | --- | --- | --- |
| `OAuthBackChannel` | token, revocation, PAR | auth, enabled public clients' redirect origins | `token` |
| `UserInfo` | userinfo | auth, enabled public clients' redirect origins | `userinfo` |
| `Discovery` | discovery, JWKS, `/.well-known/webauthn` | any | none |
| `Checkpoints` | audit checkpoints | any | `audit` |
| `Picture` | `/pictures/{id}` | any | `picture` |
| `Health` | `/health/live`, `/health/ready` | auth | none |
| `Authorize` | `/oauth/authorize` | auth | `login` |
| `Logout` | `/oidc/logout` | auth | `login` |
| `RelatedLogin` | `/webauthn/related/*` | approved related origins | `login` |
| `Account` | `/account/…` JSON APIs | auth | `account` |
| `Page` | every route in `routes::page::ALL`, and `/` | auth | `page` |
| `Other` | passkey ceremonies, providers' callbacks, the rest | auth | `login` |

Every request on the admin listener is `Dashboard`, with its own `dashboard`
budget, and only the dashboard's origin is allowed. A route that should differ
from `Other` must be listed in `classify`.

### Host

The admin listener first refuses, with `421`, a request whose `Host` header, or
HTTP/2 authority, is not the dashboard's host, so a misrouted ingress or a
rebound DNS name reaches nothing.

### Origin

When a request carries an `Origin` header, `allowed_origin` decides whether that
origin is allowed on the endpoint. An allowed origin gets CORS headers on the
response. One that is not gets none, and the browser-proof rule below decides
whether the request is refused. Auth's own origin is always allowed. Discovery, checkpoints
and pictures take any origin. The back channel and userinfo also take the
redirect origins of enabled public clients, and related sign-in the approved
origins of trusted clients: both are looked up in the database on each request,
so a registration change applies at once on every replica.

### Preflights and browser proof

An `OPTIONS` request is answered `204` if its origin is allowed, and `403`
otherwise. Then `check_browser` applies the CSRF rule of the endpoint's class:

- **Protocol endpoints** (`OAuthBackChannel`, `UserInfo`, `Authorize`, `Logout`)
  are exempt: their handlers check client credentials, bearer tokens or their own
  hints.
- **Pages and the dashboard** take any navigation, but a form only from their own
  origin's pages, by `BrowserRequest::is_same_origin`
  (`piquel_common::protocol::same_origin`): `Sec-Fetch-Site: same-origin` when the
  browser sends it, otherwise an `Origin` equal to the site's. A plain form
  cannot send a custom header, and sends `Origin: null` under
  `Referrer-Policy: no-referrer`, so the CSRF header would not work there.
- **Every other route**, the account APIs and ceremonies included, refuses an
  origin that is not allowed, and a mutation (any method but `GET` and `HEAD`)
  without an allowed `Origin` or without the `x-piquel-csrf` header. The passkey
  script sends the header; a cross-site form cannot.

### Rate limit

A matched route with a rate category spends one request of its client's budget:
`AUTH_REQUESTS_PER_MINUTE` (120 by default) per category and client IP, in a fixed
one-minute window, counted in PostgreSQL (`SecurityRepository::allow_request`)
under a SHA-256 of `<category>:<ip>`, so every replica shares it. Categories are
independent: an app's userinfo calls never block its code exchanges, and browsing
auth's pages never blocks a passkey ceremony. An exhausted budget answers `429`
with `Retry-After: 60` and counts `piquel.auth.throttled{category}`. Discovery and
health probes spend nothing, and an unmatched path has no route, so it spends
nothing either.

The client IP is the TCP peer's, unless the peer is in `AUTH_TRUSTED_PROXIES`, or
by default piqueld's `PIQUELD_INGRESS_PROXIES`: then it must have sent exactly one
`X-Forwarded-For` header holding one IP address, which the gateway overwrites.
Anything else answers `400` (`HttpSecurity::client_ip`).

A rate-limited route then gets a `RequestContext` in its extensions: the client
IP and the coarse browser family of its `User-Agent`, never the raw header.
Handlers attribute their events to it.

## Handlers

Handlers take their inputs as extractors, which reject a request before the
handler runs:

- `RequestContext` (`src/security/context.rs`): where the request came from. A
  handler on a route without a rate category has none, and fails with `500`.
- `OptionalSession`, `Session` and `Confirmed<MAX_AGE>`
  (`src/security/session.rs`): the browser's session, required, or required with
  a recent passkey confirmation. Resolving one records its activity. See
  [sessions](sessions.md).
- `Owner`, `ConfirmedOwner` and `ConfirmedSubject` (`src/account/subject.rs`): the
  account's owner, acting through their session cookie, for settings operations.

Pages are different. `WebApplication::routes` (`src/web/mod.rs`) mounts one
Topcoat router on each page's route and its trailing-slash twin, answering `GET`
with the page and `POST` with its form's result. The security layer has already
classified them as `Page`, so Topcoat's own origin policy is off.

A handler resolves who acts, then calls a service in-process: `AccountService`,
`OidcApplication`, `AdminService` and the like. There is no internal API: the
pages, the JSON routes and the CLI call the same operations. A change opens a
`DatabaseTransaction`, locks what it changes, records its domain events with
`tx.record` in the same transaction, and commits. A cookie is set on the response
only after the commit. [The PostgreSQL boundary](database.md) describes the
transactions, locks and events.

## Errors

Each kind of route renders its errors its own way, and none sends an internal
cause to the client:

- **JSON routes** answer `ApiError` (`src/security/mod.rs`):
  `{"error": message, "code": …}`, where `code` is an `ErrorCode` a script can
  act on, such as `step_up_required`. Failures of the security layer
  (`HttpSecurityError`), sessions and the database map into it. An internal
  failure is logged once, with its whole cause chain (`ApiError::log_error`), and
  answers `500` with a generic message; a replica whose signing keys are stale
  answers `503`, since another may serve the request.
- **OIDC endpoints** answer `OAuthError` (`src/oidc/error.rs`): an OAuth error
  JSON body, or, once the redirect URI is verified, a redirect to the client with
  `error`, `state` and `iss`. Its consent and logout pages show what the code
  means.
- **Pages** answer a `Failure` (`src/web/mod.rs`), which renders the page
  explaining it at its status. An internal failure is logged and shows a server
  error with its trace ID, since a browser never shows `X-Trace-Id`.

## Responses

On the way out, `HttpSecurity::decorate` sets the headers of every response,
errors and preflights included:

- **`Cache-Control`**, always replacing the handler's. A handler marks a response
  cacheable only by wrapping it in `Cached(CacheClass, …)`, and the class holds
  only for a `200` that sets no cookie; anything else is
  `no-store, no-transform`. [Caching](../operations/deploying.md#caching) lists
  the classes and what uses them.
- **Isolation:** `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY` and `Strict-Transport-Security: max-age=31536000`.
- **CORS**, once the origin check allowed the request's origin: `*` for public
  documents, or the exact origin with `Vary: Origin` and the methods and headers
  its class takes, which may then read `X-Trace-Id`.

Pages add their own `Content-Security-Policy` when they render
(`WebApplication::render_document`): the stylesheet, the passkey and picture
scripts, auth's own images and the `blob:` of a picture being chosen, and a
`form-action` naming auth and the origins the form may redirect to.
