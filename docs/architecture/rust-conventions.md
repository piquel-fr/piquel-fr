# Rust conventions

Keep implementations simple. Follow neighbouring modules and share repeated logic.

## Crates

- `piquel-common` (`crates/common`): the one home for shared types, depending on
  no other workspace crate. IDs, account status, authentication methods,
  providers, `Personal<T>`, error-chain formatting, `str_enum!`, and under
  `protocol` the wire types shared with the SDKs: token claims, metadata, JWK sets,
  OAuth/OIDC vocabulary and errors, bearer challenges. Server-only parts are
  features: `config` (environment variables, validated URLs, secret references),
  `events` (domain events) and `sqlx` (column decoding).
- `piquel-crypto` (`crates/crypto`): random secrets, digests, HMAC, constant-time
  comparison, PKCE and RS256 signing.
- `piquel-auth` (`crates/auth-sdk`): the public Rust SDK, following
  [sdk.md](sdk.md). It depends only on `piquel-common`, without features, among
  the workspace crates, since it is published.
- `piquel-repository` (`crates/database`): the only SQLx consumer; typed
  repositories, transactions and storage vocabulary.
- `piquel-telemetry` (`crates/telemetry`): tracing setup.

Application code uses `Secret`, `Digest`, `Pkce` and `Rs256Key` instead of calling
`openssl`, `sha2` or `rand` directly. Environment reads go through `Variable`.
Keep cryptographic implementations in the crypto crate so they can be audited together.

## Configuration

There is no development mode. Use `just preview` for development over HTTPS through
piqueld. Every environment needs HTTPS URLs and a persistent signing key.

Declare each environment variable as a `Variable` constant beside its configuration
section. `ConfigurationError` names the variable, explains how to fix it and retains
safe underlying sources. Parse configuration into validated types such as `Origin`
and `PublicUrl` at startup; downstream code uses those values without revalidation.
Client callback URLs needed by HTTP policy are retained as parsed `Url` values.

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
or `Confirmed` extractors, with `FromRef<Application> for Database`. `Confirmed`
requires a recent passkey confirmation; handlers recheck it with `Confirmed::lock`
inside their transaction. Handlers that only need the session locked against logout
use `Session::lock`.
Protocol and conditional flows may use `Session` methods directly. Create sessions
inside the account transaction; set cookies after commit with `BrowserCookie::set_on`
and clear them with `clear_on`. Both preserve other Set-Cookie headers.

`AuthConfig::router` builds applications without writing to the database, so tests
build two on one database as replicas (`Replicas` in `src/tests.rs`). Startup then
runs `AuthConfig::provision_clients`, which replaces client registrations atomically.
The router installs origin/CSRF checks, rate limits, a deadline and browser
isolation headers.

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
choices. Match domain enums exhaustively; use their `ALL` list rather than repeating
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
