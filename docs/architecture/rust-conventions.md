# Rust conventions

Keep implementations simple. Follow neighbouring modules and share repeated logic.

## Crates

- `piquel-common` (`crates/common`): the one home for shared types, depending on
  no other workspace crate. IDs, account status, authentication methods,
  providers, `Personal<T>`, error-chain formatting, `str_enum!`, and under
  `protocol` the wire types shared with the SDKs: token claims, metadata, JWK sets,
  OAuth/OIDC vocabulary and errors, bearer challenges, and the same-origin rule
  for browser requests. Server-only parts are features: `config` (environment
  variables, validated origins, secret references), `email` (address normalization),
  `events` (domain events) and `sqlx` (column decoding).
- `piquel-crypto` (`crates/crypto`): random secrets, digests, HMAC, constant-time
  comparison, PKCE, RS256 signing, key sets and AES-256-GCM sealing of keys at rest.
- `piquel-auth` (`crates/auth-sdk`): the public Rust SDK, following
  [sdk.md](sdk.md). It depends only on `piquel-common`, without features, among
  the workspace crates, since it is published.
- `piquel-repository` (`crates/database`): the only SQLx consumer; typed
  repositories, transactions and storage vocabulary.
- `piquel-telemetry` (`crates/telemetry`): logs, traces and metrics, following
  [telemetry.md](telemetry.md).
- `piquel-ui` (`crates/ui`): the Topcoat components and layouts of auth's
  server-rendered pages, the strings they show, titles and notices included, and
  the changes and queries their forms and links send. They render plain data,
  `piquel-common` IDs, vocabularies and events, or plain rows such as `EmailRow`
  or `ClientRow` that the pages map the service's views into, and take URLs as
  props; they know nothing of the domain, the database or HTTP. `form` holds what
  every form shares, including the `Checkbox` and `Lines` types for values a form
  sends as text; `clients` the client views the console shares with the future
  dashboard; `settings` and `developers` each section's pages; `asset` the
  files pages link, embedded under paths naming their content, and the shared
  stylesheet, `STYLESHEET`, which the admin dashboard serves with its own. It
  depends only on `piquel-common`
  (with `events`), `chrono`, `serde`, `serde_urlencoded` and Topcoat's `view`, so
  it compiles beside the database crate.

Application code uses `Secret`, `Digest`, `Pkce`, `Rs256Key`, `KeySet` and
`KeyEncryptionKey` instead of calling `openssl`, `sha2` or `rand` directly.
Environment reads go through `Variable`.
Keep cryptographic implementations in the crypto crate so they can be audited together.

## Configuration

There is no development mode. Use `just preview` for development over HTTPS through
piqueld. Every environment needs HTTPS URLs, a key-encryption key and a token
digest key.

Declare each environment variable as a `Variable` constant beside its configuration
section. `ConfigurationError` names the variable, explains how to fix it and retains
safe underlying sources. Parse configuration into validated types such as `Origin`
at startup; downstream code uses those values without revalidation.
OIDC clients are not configuration: they live in the database (see below).

`AuthConfig` combines `PasskeyConfig`, `FederationConfig` and `OidcConfig`, each with
`from_environment`. Use `Config` and `ConfigError` suffixes for feature settings.
`SecretReference` resolves `env://` and `file://` references into redacted bytes;
`utf8` borrows their text. Load persistent keys and provider secrets before serving.

## Applications and routes

Every HTTP feature owns an `XApplication` with `new(database, &config)` and
`routes(self) -> Router`. Infallible constructors return `Self`; fallible ones return
`Result<Self, XConfigError>`. Handlers and helpers live in `impl XApplication` blocks,
which may span files. Put domain errors and their HTTP mapping in `error.rs`.

Validation belongs on the value it produces, such as `ReturnTo::parse` or
`NormalizedEmail::parse`. Use methods on real owning types; reserve free functions
for trivial helpers with no natural owner. Avoid structs used only as namespaces
when an existing type can own the operations.

`apps/auth-service/src/routes.rs` owns HTTP paths used by routers, discovery,
redirects and endpoint policy. Browser handlers use `Session`, `OptionalSession`
or `Confirmed` extractors, with `FromRef<Application> for Database`. They resolve
it with `Session::resolve`, which records its activity, so no handler does. `Confirmed`
requires a recent passkey confirmation when the request arrives; account
operations check it again under the account lock with `Owner::lock_confirmed`.
Code that only needs the session locked against logout uses `Session::lock`.
Protocol and conditional flows may use `Session` methods directly. Create sessions
inside the account transaction, and end them with `Session::revoke`, which records
one event per session; set cookies after commit with `BrowserCookie::set_on`
and clear them with `clear_on`. Both preserve other Set-Cookie headers. A page
never sets or clears a flow cookie: the federation operation it calls returns the
change as a `FlowCookie`, which the page applies to its response. Pages write only
the notice cookie, with `BrowserCookie::set_notice_on`, and the session cookie only
through `AccountService::sign_out`, whose `SignedOut` clears it on the response.

`AuthConfig::router` builds applications without writing to the database, so tests
build two on one database as replicas (`Replicas` in `src/tests.rs`).
The router installs origin/CSRF checks, rate limits, a deadline and browser
isolation headers. Public-client origins for CORS are looked up per request.

Server-rendered pages live in `src/web` (`WebApplication`). Each page path in
`routes::page` gets a Topcoat `RouteFn` for `GET`, showing the page, and one for
`POST`, its form's result; axum mounts the Topcoat router with `route_service` on
those paths only, and their twins ending in a slash, which Topcoat redirects, never
as the fallback, so the security layer classifies them as pages, by the route
template they match (`/developers/clients/{id}`), with a request context and the
`page` budget. A page handler resolves who
acts, calls the service in-process and renders `piquel-ui` components, or returns
a `Failure`, which `WebApplication::answer` turns into the page explaining it. A
form that succeeds answers `303`. Pages use no Topcoat browser runtime, `suspense`, `live!`
or `asset!`, and register every route explicitly. Their Content-Security-Policy
loads only the stylesheet and the passkey script embedded under `/assets/`, lets the
script fetch only auth itself (`connect-src 'self'`), for its passkey ceremonies,
and lets forms post only to auth and to where they redirect, since browsers apply
`form-action` to a form's redirects: the consent and logout pages' redirect
targets, the enabled providers' authorization origins on the sign-in and sign-in
methods pages, whose forms go on to the provider, and, when a sign-in continues an
authorization, the client's redirect origin. A target no policy can name, such as an IP address, gets
a page linking there instead of the `303`. The security layer accepts a
page's form only from auth's own pages (`BrowserRequest::is_same_origin`): plain
forms send no CSRF header, and send `Origin: null` under `Referrer-Policy:
no-referrer`.

Each page of the signed-in account, a settings tab (`src/web/settings`) or a
developer console page (`src/web/developers`), is an `AccountPage`
(`src/web/account.rs`): its section, path, the change its form posts, its query, how
it makes a change and how it renders. `WebApplication::show` and `submit` serve
them all the same way; the address verification page, reached from its emailed
link, has its own `verify` and `confirm_address`. They find who acts with
`AccountService::owner`, and a page renders for a `Reader`, the owner and how recently
they confirmed with a passkey; a settings page reads through `Viewer::from(&owner)`,
and a change takes the owner, as a `Subject` when an administrator may make it too.
A console page acts on the owner's client its path names: one that is not theirs,
or does not exist, is a `Failure::Missing`, a `404`. Each page's change and query are types in
`piquel-ui`, such as `SignInChange` and `SignInState`: forms and links serialize
them, and the page deserializes the same types, so a field's name is written once.
A change names itself in a hidden `action` field, as an internally tagged enum, so
its fields must deserialize from text. A change that succeeds answers `303` to the
page, which says once what it did, from a short-lived cookie, so no link can claim
a change; or on to where it leads, such as the provider a link starts at, what a
report left to undo, or the apps after one is deleted. A change that makes a secret
renders the page at `200` with it, so it is in no URL, cookie or history entry, and
pages are never cached. One that fails renders the page again, with the change's
row open, what was typed into it and the service's message, beside its input when
it names a setting. A
query that does not parse opens nothing, and a form that does not decode changes
nothing, logging why at debug level.

The sign-in pages (`src/web/auth/login`), `/login` and `/register`, serve signed-out
browsers, so they are pages of their own rather than `AccountPage`s. Their query,
`LoginQuery`, is the one auth's pages, flows and invitation links serialize for
every link to them; it
parses field by field, so a bad value drops only itself, never the `transaction` or
`return_to` it continues. One `Step` comes from the query, the pending social sign-in and the
session: signing in, signing up, or linking a provider. The server decides where a
sign-in continues, an authorization or a path, renders it into each form's action,
and answers the form with it: an authorization continues in-process and goes on
through the onward page when no policy can name its client. A provider's sign-in for
such a client links to the provider rather than redirecting there, since a provider
the user already allowed sends the browser straight back and on to the client. A
passkey ceremony runs in the browser through the passkey script, then posts the
form's change: signing in or up changes nothing and continues, and linking while
signed out links once the sign-in succeeds. While the account has a recovery that
can be undone, a passkey sign-in that continues an authorization first asks whether
it was the owner's, and goes on by a plain link that resumes the authorization. The
recovery pages (`src/web/auth/recovery`), `/recover` and `/recover/undo`, which a
recovery's emails link to, serve signed-out browsers too, so they are pages of their
own as well.

The passkey script (`apps/auth-service/assets/passkey.js`) wires the pages' forms by
their attributes. It keeps a form marked `data-submit-once` from posting twice, and
confirms with a passkey before posting one marked `data-passkey-confirm`, which a
page marks while the session has no recent confirmation. A `data-passkey-sign-in`
form signs in with a passkey, with its `username` when typed, and a
`data-passkey-register` form creates the account and its passkey; both then post. A
`data-passkey-enroll` form runs the passkey enrollment, then posts, so its page says
so. A `data-passkey-recover` form enrolls a passkey with the recovery link's token
its attribute carries, so the form's post never sends the token again, and a
`data-passkey-undo` form undoes the recovery its attribute names with an older
passkey; both then post, the undo saying whether it signed the browser in. A
`data-fragment-form` copies the link's fragment into its inputs as it posts, so an
emailed link's token never reaches the server in a URL. A ceremony form's or a
fragment form's button starts disabled, with a `data-unavailable` note saying why,
until the script finds it can work. While a ceremony runs, its form's button is
disabled and says it waits for the passkey, and the form's last error hides. A
`data-dismiss` element, rendered hidden, shows unless the browser's local storage
holds its key, which a `data-dismisses` button with that key stores as it hides the
element; without local storage, it shows on every page. A `data-copy` button copies
a value, and a `data-replace-url` element makes a page that shows a secret reload by
`GET`. The script is plain JavaScript, embedded as written: `tsc` checks its JSDoc
types, and ESLint lints it as it does the browser tests.

Administrative operations are methods of `AdminService` (`src/admin/service.rs`);
the admin dashboard's pages (`src/web/admin`) and the CLI's commands (`src/cli`)
are thin adapters that
say which `Operator` acts. Every method takes that `Operator` and checks it itself,
so a caller in the same process needs no check of its own: a read first calls
`Operator::authorize_read` (rights, session and a passkey sign-in), and a change
calls `Operator::authorize` (the same, with a recent confirmation) after its last
write. A test runs every read as an administrator who may no longer read. Each
operation joins `AdminOperation`: the admin router
maps it to its route, or to none when only the CLI runs it, and every CLI command
names the operation it runs. A test parses a command line for each operation and
checks that it names that operation. The matches are exhaustive, so a new operation
does not compile until both sides handle it.

Account operations are methods of `AccountService` (`src/account`), written with
their setting's module, such as `src/passkey`. Each takes the account and who acts
on it:

- an `Owner`, for what only the owner may do, such as adding a passkey or an
  address, or managing the account's clients. Only the session cookie builds one,
  so these cannot be called for an administrator. Verifying an address is
  authorized by its link's token instead, and takes an optional `Owner`: it refuses
  a browser signed in to another account, and records the owner as the actor when
  theirs confirms it. Signing a browser out is authorized by its session cookie
  alone: `AccountService::sign_out` takes the request's headers;
- a `Subject`, for changes an administrator may also make: the owner, or an
  `Operator` with the reason it must give;
- a `Viewer`, for reads, which need no reason. For an operator,
  `Viewer::authorize` calls `Operator::authorize_read`, as every admin read does,
  and records the read as a view; an owner's reads are not recorded.

Only the extractors and `AccountService::owner`, which pages call, build an owner's
`Owner`, from the session cookie; their `Subject` and `Viewer` come from it, or
from the extractors. Only `DashboardSignIn`, from the dashboard's session cookie,
builds an `Operator::Admin`. Routes whose operation needs a recent confirmation extract
`ConfirmedOwner` or `ConfirmedSubject` instead, which check it before the path and
body, so the browser is asked to confirm before any other error. Each operation says what it needs: it locks with `lock`, or
`lock_confirmed` when the owner must have confirmed with a passkey recently
(operators confirm their own before committing), records events with `context`,
and ends a `Subject`'s change with `Subject::commit`, which checks an
administrator again. The owner's router serves each shared `AccountOperation`, and
the `account` command has a command for each, under the same exhaustive matches and
test as `AdminOperation`. A new setting either joins `AccountOperation`, if it only
views, edits or removes, or takes an `Owner`.

`ClientRegistry` (`src/clients/mod.rs`) is the only code that changes OIDC clients: it
creates, updates, enables, disables, deletes and rotates the secrets of clients,
recording each change's event. It works in the caller's transaction, so an
operation can lock its actor's session and check its passkey confirmation in the
transaction that makes the change. It takes a `ClientRegistration` from
`piquel_common::clients`, whose field types validate themselves, so invalid input
never reaches the repository. `AdminService` (for the `client` command) and the
owner's `AccountService` operations (`src/clients/owned.rs`), which the developer
console calls, use it, and a registration API (RFC 7591) should too. The owner's input types there are the policy for
clients accounts own: they hold no ID, trust or back-channel logout URI, and only
standard scopes, and an invalid one names its field (`InvalidSetting`). Every
owner operation looks the client up as the owner's first, so any other client is
not found, and nothing checks ownership again. Clients are read from the database on each
request and nothing is cached, so changes apply at once on every replica.

Periodic work implements `ExclusiveJob` in `apps/auth-service/src/jobs.rs`, and
`Jobs::start` schedules it. A job receives only its locked `ExclusiveConnection`,
never the `Database`, so everything it does happens while it holds the lock.
Messages for other systems are never sent from handlers: the event's channels queue
them, and delivery workers send them. See [the delivery queue](delivery-queue.md).

## Errors

Return explicit `thiserror` errors. Preserve sources with `#[source]` or `#[from]`;
use `?` when a conversion already exists. Do not use `Result<_, ()>` or production
`expect`, `unwrap` or `panic!`. Drop a source only when it contains a secret, and
explain that exception in the code. Gate test helpers with `#[cfg(test)]`.

Helpers return the feature's domain error. Browser handlers return `ApiError`
through `From<DomainError>`; that exhaustive mapping owns public statuses and
messages. OAuth endpoints return `OAuthError`. Log internal failures once at the
HTTP boundary through `ApiError::log_error`, which includes the source chain.
OAuth rejections that carry a cause log it at debug level; clients trigger them.

Rejections tell the client what to fix: name the parameter or rule and its limit.
Every OAuth rejection goes through `OAuthCode::reject` or `reject_with`, which
sends an RFC 6749 `error_description`. Stay vague only where detail would reveal
a secret or whether an account exists. Internal failures keep a generic message.
Keep separate variants when they identify different failures; merge indistinguishable ones.

## Vocabulary and persistence

Use `str_enum!` for closed stored or wire strings and serde enums for JSON-only
choices. Give it an `else` variant, as `Browser` and `Platform` have, for labels a
newer release may extend that older ones can read coarsely. Match domain enums exhaustively; use their `ALL` list rather than repeating
variants. Limits and lifetimes are named constants. Preserve existing wire spellings.

Shared authentication vocabulary, JWT/JWK vocabulary and wire types live in
`piquel-common`. Build tokens and protocol documents from its structs, never with
`json!`, so auth and the SDKs share one definition. Use `open_str_enum!` for wire
values a newer peer may extend, such as `amr`. Domain events and `UserAgentFamily` live in
`piquel_common::events`; storage vocabulary (`CeremonyKind`, `OidcRedirectKind`)
lives in the repository.
Record each account or security change with `tx.record(&context, subject, event)`
in the transaction that makes it. Handlers extract `RequestContext`, which
`HttpSecurity::protect` attaches to rate-limited routes, and attribute it with
`context.user(&session)`, `context.client(id)` or `context.actor(actor)`. Record
failed sign-ins with `RequestContext::record_sign_in_failure`, which commits even
though the operation fails. Wrap values that identify a person in `Personal`; never
store challenges, cookies or tokens. Keep digests typed until
their persistence boundary. SQL, rows and connections stay inside the repository.
Write queries with SQLx's checked macros and refresh the cache with
`just db prepare`. `just db test` runs the database integration tests in a scratch
cluster; ordinary tests skip them.

## Documentation and tests

Give every item a concise, useful doc comment, private items included. Explain
security reasoning, protocol quirks, ordering and locking where they are not obvious.
Keep documentation current. Tests should cover meaningful logic and boundaries;
avoid repeated smoke tests. Run checks relevant to changed code while iterating,
then the required workspace checks before handing over an integration change.
