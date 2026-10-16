# Rust conventions

Keep implementations simple. Follow neighbouring modules and share repeated logic.

## Crates

- `piquel-common` (`crates/common`): environment variables, validated URLs,
  secret references, error-chain formatting and `str_enum!`.
- `piquel-crypto` (`crates/crypto`): random secrets, digests, HMAC, constant-time
  comparison, PKCE, RS256 signing and JWT/JWK vocabulary.
- `piquel-auth-protocol` (`crates/auth-protocol`): IDs, account status,
  authentication methods, providers and shared OAuth/OIDC vocabulary.
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
or `ManagementSession` extractors, with `FromRef<Application> for Database`.
Admin API reads take `Admin` and mutations `ConfirmedAdmin`; both delegate to
`AdminOperations`, which the CLI shares.
Protocol and conditional flows may use `Session` methods directly. Create sessions
inside the account transaction; set cookies after commit with `BrowserCookie::set_on`
and clear them with `clear_on`. Both preserve other Set-Cookie headers.

`AuthConfig::router` builds applications, provisions clients atomically and installs
origin/CSRF checks, rate limits, a deadline and browser isolation headers.

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

Shared authentication vocabulary lives in auth-protocol; JWT/JWK vocabulary lives
in crypto. Storage vocabulary (`AuditAction`, `AuditOutcome`, `CeremonyKind`,
`OidcRedirectKind`) lives in the repository. Record successful account operations
with `tx.audit_events().record(user_id, action, provider)`, and administrative ones
with `record_by(actor, user_id, action, reason)`. Record rejections that
implicate an account with `record_rejection(user_id, action)`, committed even though
the operation fails; never store challenges, cookies or tokens. Keep digests typed until
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
