# Piquel Database Crate Design

## 1. Purpose

The database crate is the single PostgreSQL access layer for the `piquel.fr` monorepo.
It is the only workspace crate permitted to depend directly on SQLx.
It provides typed repositories and transaction APIs to the platform applications while preventing SQLx-specific implementation details from leaking into the rest of the repository.

The crate exists to:
* Centralize database access
* Keep SQL consistent and reviewable
* Enforce data-access boundaries
* Provide typed repository APIs
* Translate database errors into stable application-facing errors
* Coordinate migrations
* Support safe multi-step transactions
* Make database behavior testable independently of applications

The crate can be found in `crates/database` & is named `piquel-repository`.

---

## 2. Architectural position

```text
auth-service ──────┐
admin-api ─────────┤
piquel-api ────────┤
other main apps ───┤
                   ▼
            piquel-database
                   │
                   ▼
                 SQLx
                   │
                   ▼
              PostgreSQL
```

No other application or shared crate may communicate directly with PostgreSQL.
The database crate may depend on shared primitive crates where necessary, but it must not depend on any application.

---

## 3. Goals

The database crate should:
* Be the only direct SQLx consumer
* Hide pools, connections, transactions, rows, and SQLx errors
* Expose domain-oriented repositories
* Support both non-transactional and transactional operations
* Keep query behavior explicit
* Use typed identifiers and input structures
* Make concurrency semantics visible
* Own database migrations
* Provide integration-test support
* Support distinct database roles for each application
* Preserve clear conceptual ownership of tables

---

## 4. Non-goals

The database crate is not:
* A generic ORM
* A business-service layer
* An authorization layer
* An authentication-policy engine
* A replacement for application domain logic
* A place for unrelated data transformations
* A way for every application to access every table
* A wrapper exposing arbitrary SQL execution
* A network service

The crate executes persistence operations.
Applications decide when and why those operations are performed.

---

## 5. Proposed directory structure

```text
crates/database/
├── Cargo.toml
├── README.md
├── AGENTS.md
├── migrations/
│   ├── 0001_initial.sql
│   ├── 0002_authentication.sql
│   ├── 0003_admin.sql
│   ├── 0004_internal_events.sql
│   └── ...
│
├── src/
│   ├── lib.rs
│   ├── config.rs
│   ├── connection.rs
│   ├── error.rs
│   ├── transaction.rs
│   ├── health.rs
│   │
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── email.rs
│   │   ├── passkey.rs
│   │   ├── session.rs
│   │   ├── refresh_token.rs
│   │   ├── oidc_client.rs
│   │   ├── service_identity.rs
│   │   ├── administrator.rs
│   │   └── internal_event.rs
│   │
│   ├── rows/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── session.rs
│   │   └── refresh_token.rs
│   │
│   ├── repositories/
│   │   ├── mod.rs
│   │   ├── users.rs
│   │   ├── emails.rs
│   │   ├── passkeys.rs
│   │   ├── sessions.rs
│   │   ├── refresh_tokens.rs
│   │   ├── oidc_clients.rs
│   │   ├── service_identities.rs
│   │   ├── administrators.rs
│   │   └── internal_events.rs
│   │
│   └── bin/
│       └── migrate.rs
│
└── tests/
    ├── common/
    ├── users.rs
    ├── sessions.rs
    ├── refresh_tokens.rs
    └── migrations.rs
```

Private modules may be reorganized as the crate evolves.

The public API should remain centered around:
* `Database`
* Repository handles
* `DatabaseTransaction`
* Public database model types
* Typed database errors

---

## 6. Dependency policy

`piquel-database` may depend on:
* SQLx
* Tokio
* Thiserror
* Shared Piquel identifier and primitive crates
* Serialization crates where required
* Time and UUID crates
* Tracing for sanitized instrumentation

Application crates depend on `piquel-database`.
No application may also depend directly on SQLx.

### 6.1 Tokio

All asynchronous database operations use Tokio.
The database crate must not create its own Tokio runtime.
It assumes it is called from an existing asynchronous runtime.

### 6.2 Error crates

Use `thiserror` for public and internal typed database errors.
Do not expose `anyhow::Error` from public repository methods.
Applications may wrap database errors with `anyhow::Context` at orchestration boundaries.

---

## 7. Public entry point

The main entry point is a `Database` type.

```rust
#[derive(Clone)]
pub struct Database {
    pool: sqlx::PgPool,
}
```

The pool remains private.
Construction should validate configuration and establish the pool.

```rust
impl Database {
    pub async fn connect(
        config: DatabaseConfig,
    ) -> Result<Self, DatabaseConnectionError>;

    pub async fn health_check(
        &self,
    ) -> Result<(), DatabaseError>;

    pub async fn begin(
        &self,
    ) -> Result<DatabaseTransaction<'_>, DatabaseError>;
}
```

Applications must not be able to retrieve the inner `PgPool`.

Do not implement:
```rust
pub fn pool(&self) -> &sqlx::PgPool;
```

Do not implement arbitrary query escape hatches.

---

## 8. Repository access

The `Database` type exposes focused repository handles.

```rust
impl Database {
    pub fn users(&self) -> UserRepository<'_>;
    pub fn emails(&self) -> EmailRepository<'_>;
    pub fn passkeys(&self) -> PasskeyRepository<'_>;
    pub fn sessions(&self) -> SessionRepository<'_>;
    pub fn refresh_tokens(&self) -> RefreshTokenRepository<'_>;
    pub fn oidc_clients(&self) -> OidcClientRepository<'_>;
    pub fn service_identities(&self) -> ServiceIdentityRepository<'_>;
    pub fn administrators(&self) -> AdministratorRepository<'_>;
    pub fn internal_events(&self) -> InternalEventRepository<'_>;
}
```

Example:
```rust
let user = database
    .users()
    .find_by_id(&user_id)
    .await?;
```

Repository objects are lightweight wrappers around a private executor abstraction.
They should not own separate pools.

---

## 9. Repository organization

Repositories are organized by domain rather than by SQL table count.
A repository may access multiple closely related tables when that matches the domain operation.

Examples:

### `UserRepository`

May access:
* `users`
* Token-visible profile fields
* Account status
* Profile version

### `EmailRepository`

May access:
* `user_emails`
* Verification state
* Primary-email state

### `RefreshTokenRepository`

May access:
* `refresh_token_families`
* `refresh_tokens`
* Replay-detection state

Repositories must not grow into application-service layers.
A repository method should describe a persistence operation.

Good:
```rust
find_by_id
find_by_verified_email
insert
update_display_name
increment_profile_version
consume_for_rotation
revoke_family
```

Avoid:
```rust
authenticate_user
decide_account_recovery_policy
authorize_admin_action
choose_social_login_provider
```

Those decisions belong to application domain logic.

---

## 10. Public model types

Public database models represent stored information in a database-independent form.

Example:
```rust
pub struct StoredUser {
    pub id: UserId,
    pub username: Username,
    pub display_name: DisplayName,
    pub profile_version: u64,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

These types must not expose:
* SQLx traits as part of their public contract
* PostgreSQL-specific enum representations
* Raw database column names where avoidable
* Database nullability quirks
* Internal surrogate keys when unnecessary

Input types should be explicit.
```rust
pub struct InsertUser {
    pub id: UserId,
    pub username: Username,
    pub display_name: DisplayName,
}
```

Avoid repository methods with long lists of primitive parameters.

---

## 11. Private row types

SQLx-specific row types remain private.

```rust
#[derive(sqlx::FromRow)]
struct UserRow {
    id: uuid::Uuid,
    username: String,
    display_name: String,
    profile_version: i64,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}
```

Private row types translate into public database models.

```rust
impl TryFrom<UserRow> for StoredUser {
    type Error = DatabaseDataError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        // Validate and convert database representation.
    }
}
```

This translation layer prevents malformed or legacy database values from silently entering application code.

---

## 12. Error design

The database crate exposes typed errors.

A possible top-level error:
```rust
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("the requested record was not found")]
    NotFound,

    #[error("the operation conflicts with existing data")]
    Conflict,

    #[error("the database operation timed out")]
    Timeout,

    #[error("the database is unavailable")]
    Unavailable,

    #[error("stored database data is invalid")]
    InvalidStoredData,

    #[error("the transaction could not be completed")]
    TransactionFailed,

    #[error("an unexpected database error occurred")]
    Internal,
}
```

More specific repository errors may be used where callers need to make decisions.

Example:

```rust
#[derive(Debug, thiserror::Error)]
pub enum InsertUserError {
    #[error("the username is already in use")]
    UsernameConflict,

    #[error("the user identifier already exists")]
    UserIdConflict,

    #[error(transparent)]
    Database(#[from] DatabaseError),
}
```

SQLx errors are translated internally.
Do not expose constraint names to application callers unless they are mapped to stable typed variants.
Do not include SQL statements, credentials, or sensitive values in error messages.

At application boundaries:
```rust
let user = database
    .users()
    .find_by_id(&user_id)
    .await
    .context("failed to load the authenticated user")?;
```

The application may use `anyhow` to add operational context while preserving the typed database source error.

---

## 13. Transactions

The crate must support multi-repository transactions.

Important transactional flows include:
* Creating a user and initial verified email
* Linking a social identity
* Rotating a refresh token
* Registering a passkey
* Updating a profile and appending an internal event
* Revoking a session and associated refresh-token families

### 13.1 Wrapped transaction

Expose a `DatabaseTransaction` wrapper.

```rust
pub struct DatabaseTransaction<'a> {
    inner: sqlx::Transaction<'a, sqlx::Postgres>,
}
```

The inner SQLx transaction remains private.

The transaction exposes the same repository families:
```rust
impl DatabaseTransaction<'_> {
    pub fn users(&mut self) -> UserRepository<'_>;
    pub fn emails(&mut self) -> EmailRepository<'_>;
    pub fn refresh_tokens(&mut self) -> RefreshTokenRepository<'_>;
    pub fn internal_events(&mut self) -> InternalEventRepository<'_>;

    pub async fn commit(self) -> Result<(), DatabaseError>;
    pub async fn rollback(self) -> Result<(), DatabaseError>;
}
```

Example:

```rust
let mut transaction = database.begin().await?;

let token = transaction
    .refresh_tokens()
    .consume_for_rotation(&presented_token)
    .await?;

transaction
    .refresh_tokens()
    .insert_replacement(&token.family_id, new_token)
    .await?;

transaction.commit().await?;
```

### 13.2 Transaction requirements

* Transactions must not be held across external network calls.
* Transactions should be as short as practical.
* Lock acquisition order should be consistent.
* Repository documentation must identify methods that lock rows.
* Commit failures must be handled as operation failures.
* Dropped uncommitted transactions must roll back.

### 13.3 Closure-based transactions

A closure-based helper may be introduced later, but it is not required initially.
Rust async closure lifetimes can make such APIs difficult to use correctly.
The explicit transaction wrapper is the preferred initial design.

---

## 14. Concurrency and locking

Repository methods must document concurrency behavior where it matters.

Examples include:
* Refresh-token rotation
* Username allocation
* Primary-email changes
* Passkey insertion
* Aggregate event sequence allocation
* Session revocation

### 14.1 Refresh-token rotation

Consuming a refresh token must be atomic.
The operation must ensure that two simultaneous refresh requests cannot both succeed.

Possible implementations include:
* `SELECT ... FOR UPDATE`
* Atomic `UPDATE ... WHERE consumed_at IS NULL RETURNING ...`
* Serializable transaction semantics where justified

Prefer explicit atomic statements over broad serializable transactions when possible.

### 14.2 Optimistic concurrency

Version columns may be used for mutable records.

Example:
```sql
UPDATE users
SET
    display_name = $1,
    profile_version = profile_version + 1,
    updated_at = now()
WHERE id = $2
  AND profile_version = $3
RETURNING profile_version;
```

The repository should return a typed conflict when the expected version does not match.

### 14.3 Advisory locks

PostgreSQL advisory locks should be used only when row-based locking cannot model the operation clearly.
Every advisory-lock use must be documented.

---

## 15. Query policy

Queries live in the database crate.
Applications must not construct SQL fragments.

Prefer:
* Explicit SQL
* Typed parameters
* Bounded result sets
* Stable ordering
* Keyset pagination for large collections
* Database constraints for persistent invariants

Avoid:
* `SELECT *`
* Unbounded list queries
* Dynamic SQL created from untrusted strings
* Offset pagination for very large or frequently changing tables
* Hidden N+1 query patterns

### 15.1 Checked SQLx queries

Prefer SQLx checked-query facilities where practical.
The repository should maintain SQLx offline metadata so that CI does not require a live database merely to compile checked queries.

A root command should update metadata:
```text
just prepare-sqlx
```

Generated SQLx metadata must be updated whenever checked queries or relevant schemas change.
Do not manually edit generated SQLx metadata.

### 15.2 Query files

Large or complex queries may live in `.sql` files near the relevant repository module.

Example:
```text
src/repositories/users/
├── mod.rs
├── find_by_id.sql
└── search.sql
```

Small queries may remain inline when readability is better.

---

## 16. Migrations

All shared database migrations live in:
```text
crates/database/migrations/
```

Migrations are owned by the monorepo, not by individual application directories.

### 16.1 Migration rules

* Every schema change requires a migration.
* Applied migrations are immutable.
* Fix mistakes through a new migration.
* Use descriptive migration names.
* Separate unrelated schema changes.
* Add constraints deliberately.
* Consider existing production data.
* Avoid long table locks where possible.
* Document destructive migrations.
* Review auth-related migrations as security-sensitive changes.

### 16.2 Migration execution

Provide a dedicated migration binary:
```text
crates/database/src/bin/migrate.rs
```

Example:
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = DatabaseConfig::from_environment()?;
    let database = Database::connect(config).await?;

    database
        .run_migrations()
        .await?;

    Ok(())
}
```

The migration binary may use `anyhow` because it is an application boundary.
Migration library methods should expose typed errors.

### 16.3 Application startup

Application replicas should not automatically race to run migrations during ordinary startup.
Migrations should be executed as an explicit release or operational step once the deployment strategy has been selected.

### 16.4 Backward compatibility

For changes deployed across multiple applications:
1. Add backward-compatible schema.
2. Deploy code that supports old and new representations.
3. Migrate or backfill data.
4. Deploy code that relies on the new representation.
5. Remove legacy schema in a later migration.

Avoid schema changes requiring every application to update atomically.

---

## 17. Database roles and permissions

All main services may use the same PostgreSQL database while authenticating with distinct database roles.

Example roles:
```text
piquel_auth_service
piquel_admin_api
piquel_main_api
piquel_migration
piquel_readonly_support
```

The migration role owns schema changes.
Runtime roles receive only the privileges they require.

Examples:

### Auth service

May require access to:

* Users
* Emails
* Passkeys
* Federated identities
* Sessions
* Refresh tokens
* OIDC clients
* Service identities
* Authentication audit records
* Internal events

### Admin API

May require:
* Read access to central user information
* Access to administrative tables
* Explicit stored procedures or repository operations for permitted account actions

### Main API

May require:
* Main product tables
* Limited user-profile reads
* No direct passkey or refresh-token access

Database permissions are a real security control.
Cargo feature flags are not a security boundary.

---

## 18. Feature-gated repository groups

The crate may use Cargo features to reduce accidental coupling and compilation surface.

Example:
```toml
[features]
default = []
auth = []
admin = []
platform = []
migrations = []
test-support = []
```

Application dependency:
```toml
piquel-repository = {
    workspace == true
    features = ["auth"]
}
```

Feature gates may control which repository modules are publicly exported.
They do not replace PostgreSQL permissions because a developer can change feature flags.

---

## 19. Conceptual table ownership

Even with one database crate and one PostgreSQL database, every table has a conceptual owner.

Example:
```text
auth-service:
    users
    user_emails
    passkey_credentials
    external_login_identities
    sessions
    refresh_token_families
    refresh_tokens
    oidc_clients
    service_identities
    authentication_audit_log

admin-api:
    administrators
    administrator_roles
    support_cases
    administrative_notes

piquel-api:
    main product tables
```

Cross-domain reads may be legitimate.
Cross-domain writes require deliberate design.
The database crate must not provide generic update methods that allow one application to bypass another domain’s invariants.

---

## 20. Internal events

The database crate owns persistence for the internal event log.
It does not decide when a domain event should occur.
The calling application decides which event to append.

The repository provides operations such as:
```rust
transaction
    .internal_events()
    .append(AppendInternalEvent {
        aggregate_type: AggregateType::User,
        aggregate_id: user_id.to_string(),
        event_type: "user.display_name.changed".into(),
        schema_version: 1,
        payload,
    })
    .await?;
```

Account changes and associated event insertion should occur in the same transaction.

The event repository must support:
* Unique event IDs
* Per-aggregate sequence numbers
* Schema versions
* Append-only behavior
* Future publication state
* Ordered retrieval for a future publisher

Event payloads must not contain credentials or tokens.

---

## 21. Sensitive data

The database crate may handle highly sensitive records.

Examples:
* Refresh-token digests
* Passkey public-key metadata
* Federated identity mappings
* Session records
* Audit records

Rules:
* Never log raw refresh tokens.
* Never store raw refresh tokens.
* Never log authorization codes.
* Never place secrets in error messages.
* Redact sensitive query parameters from tracing.
* Use constant-time secret comparison where applicable outside SQL.
* Encrypt sensitive stored values where required by the security design.
* Keep token digests distinct from general-purpose password hashing where lookup behavior differs.

The database crate should expose methods that operate on digests or structured secret inputs rather than returning sensitive internal values unnecessarily.

---

## 22. Pagination

All list and search repository methods must be bounded.
Prefer keyset pagination.

Example public request:
```rust
pub struct UserSearchPage {
    pub limit: PageSize,
    pub after: Option<UserSearchCursor>,
}
```

Example result:
```rust
pub struct Page<T, C> {
    pub items: Vec<T>,
    pub next_cursor: Option<C>,
}
```

Limits must have server-enforced maximums.
Do not allow a caller to request an unbounded result set.

---

## 23. Health checks

The database crate exposes a small health-check operation.

It should:
* Verify a connection can be acquired
* Execute a lightweight query
* Respect a short timeout
* Avoid running migrations
* Avoid checking every table

Example:
```rust
pub async fn health_check(
    &self,
) -> Result<(), DatabaseHealthError>;
```

Applications decide how database health affects readiness.

---

## 24. Observability

Repository operations may emit sanitized tracing spans and metrics.

Useful attributes include:
* Repository name
* Operation name
* Outcome category
* Duration
* Number of returned rows
* Whether a transaction was used

Do not include:
* SQL query parameters
* Tokens
* Email addresses
* User-provided search text
* Unbounded user IDs as metric labels

SQL text may be available in controlled development logs, but production logging must avoid exposing sensitive values.

---

## 25. Testing strategy

The database crate requires integration tests against PostgreSQL.
Mocking SQLx is not a substitute for testing actual constraints and transaction behavior.

### 25.1 Unit tests

Use unit tests for:
* Row conversion
* Cursor encoding
* Input validation
* Error mapping
* Identifier conversion

### 25.2 Integration tests

Use PostgreSQL integration tests for:
* Repository queries
* Constraints
* Transactions
* Locking
* Concurrent refresh-token consumption
* Migration correctness
* Pagination
* Role permissions where practical

### 25.3 Test isolation

Each test should use one of:
* A dedicated temporary database
* A dedicated temporary schema
* A transaction rolled back after the test, where concurrency behavior does not require committed state

Tests must not depend on execution order.

### 25.4 Migration tests

CI should verify:
* A fresh database can apply every migration
* The resulting schema supports repository tests
* SQLx metadata matches the current schema and queries
* Important upgrade paths remain valid where supported

### 25.5 Concurrency tests

Security-sensitive concurrency requires explicit tests.

Examples:
* Only one of two simultaneous refresh rotations succeeds.
* Duplicate verified emails cannot be inserted.
* Aggregate event sequence numbers remain unique.
* Passkey credentials remain unique.
* Session revocation is idempotent.

---

## 26. Repository API examples

### 26.1 User lookup

```rust
let user = database
    .users()
    .find_by_id(&user_id)
    .await?
    .ok_or(UserLookupError::NotFound)?;
```

The repository may return `Option` when absence is expected.
Use a typed `NotFound` error when absence represents operation failure.
Choose consistently per method.

### 26.2 Social identity linking

```rust
let mut transaction = database.begin().await?;

if let Some(identity) = transaction
    .federated_identities()
    .find_by_issuer_and_subject(&issuer, &subject)
    .await?
{
    transaction.commit().await?;
    return Ok(identity.user_id);
}

let user = transaction
    .users()
    .find_by_verified_email(&normalized_email)
    .await?;

let user_id = match user {
    Some(user) => user.id,
    None => {
        transaction
            .users()
            .insert(new_user)
            .await?
            .id
    }
};

transaction
    .federated_identities()
    .insert(LinkFederatedIdentity {
        user_id,
        issuer,
        subject,
        linked_email,
    })
    .await?;

transaction.commit().await?;
```

The application decides the linking policy.
The database crate guarantees atomic persistence.

### 26.3 Profile update with event

```rust
let mut transaction = database.begin().await?;

let updated = transaction
    .users()
    .update_display_name(UpdateDisplayName {
        user_id,
        expected_profile_version,
        display_name,
    })
    .await?;

transaction
    .internal_events()
    .append(AppendInternalEvent {
        aggregate_type: AggregateType::User,
        aggregate_id: user_id.to_string(),
        event_type: "user.display_name.changed".into(),
        schema_version: 1,
        payload: serde_json::json!({
            "profile_version": updated.profile_version,
        }),
    })
    .await?;

transaction.commit().await?;
```

---

## 27. Prohibited database patterns

The following are not allowed:

```rust
// Exposing SQLx:
pub fn pool(&self) -> &sqlx::PgPool;

// Accepting arbitrary SQL:
pub async fn execute(&self, query: &str);

// Returning SQLx errors:
pub async fn find_user(...) -> Result<User, sqlx::Error>;

// Letting applications supply raw executors:
pub async fn find_user(
    executor: impl sqlx::Executor<'_>,
    ...
);

// Application-owned raw SQL:
sqlx::query!("DELETE FROM refresh_tokens ...");
```

Also prohibited:
* Business policy hidden inside repository code
* Unbounded list methods
* Logging query parameters containing personal or secret data
* Updating auth-critical tables through generic map-based APIs
* Automatic migrations from every application replica
* Schema changes without migrations
* Modifying an applied migration
* Returning private row types publicly
* Database feature flags treated as security controls

---

## 28. Adding a repository method

Before adding a repository method, determine:
1. Which domain owns the operation?
2. Is this persistence behavior or business policy?
3. Does an existing method already support it?
4. Must it participate in a transaction?
5. What happens under concurrent calls?
6. What database constraints enforce the invariant?
7. What typed errors must the caller handle?
8. Does the result need pagination?
9. Does it expose sensitive data?
10. Which database roles should be permitted to execute it?

The method should be named after the persistence action, not the HTTP endpoint that currently needs it.

---

## 29. Adding a table

Every new table must have:
* A conceptual owner
* A migration
* Appropriate primary and foreign keys
* Required uniqueness constraints
* Timestamp policy
* Deletion or retention policy
* Repository ownership
* Permission grants
* Test coverage
* Documentation when security-sensitive

Do not add tables as general-purpose dumping grounds for JSON.
JSON columns are acceptable when the data is genuinely flexible or event-shaped, but core searchable invariants should use typed columns.

---

## 30. Crate evolution

The database crate should begin as one crate.
Do not split it into multiple database crates merely because it contains several repositories.

Consider splitting only when:
* Compile times become materially problematic
* Domains require genuinely different databases
* Release boundaries diverge
* Security boundaries require separate packages
* The public API becomes difficult to navigate despite clear modules

A single well-structured crate is preferable to many thin crates that all expose SQLx-adjacent details.

---

## 31. Guiding principles

The database crate follows these principles:
1. SQLx stays private.
2. PostgreSQL behavior is explicit.
3. Repositories model persistence operations.
4. Applications own business policy.
5. Transactions span repository operations safely.
6. Database constraints protect persistent invariants.
7. Typed errors replace leaked driver errors.
8. Migrations are deliberate and immutable.
9. Shared storage does not erase domain ownership.
10. Security-sensitive data receives security-sensitive APIs.

The central rule is:
> Applications describe the persistence operation they need; the database crate decides how that operation is performed safely in PostgreSQL.
