# Piquel Monorepo Structure and Contribution Guidelines

## 1. Purpose

This document explains how the `piquel.fr` monorepo is organized and establishes rules for modifying it safely.

It is intended for:

* Human contributors
* Coding agents
* Code-review agents
* Repository automation
* Future maintainers

Before making structural changes, adding dependencies, creating a new service, or moving code between packages, contributors should read this document.
The main objective is to keep the repository understandable and prevent accidental coupling between applications.

This document contains the global vision. Only add parts described here when
they are actually needed. Adding a bunch of empty crates is unnecessary.

---

## 2. Repository scope

The monorepo contains the services and interfaces that make up the main `piquel.fr` platform.

This includes:

* The central authentication service at `auth.piquel.fr`
* The authentication frontend
* Administrative APIs
* Administrative frontends
* The main `piquel.fr` backend
* The main `piquel.fr` frontend
* Shared Rust libraries
* Shared frontend packages
* Shared database access
* Internal protocol definitions
* Monitoring configuration
* Architecture and operational documentation

Independent downstream products are not part of this monorepo.

Those products live in separate repositories and integrate with the platform through the published Piquel authentication SDK and public authentication protocols.

---

## 3. Architectural model

The monorepo contains multiple deployable applications that share:

* A repository
* A PostgreSQL database
* Common Rust crates
* Common protocol definitions
* Common frontend packages where useful
* Common monitoring conventions

Sharing a repository and database does not mean every application may modify every part of the system.

Each application still has clear responsibilities.

In particular:

* `auth-service` owns authentication and identity invariants.
* Administrative applications perform explicit administrative operations.
* Frontends communicate through APIs rather than accessing data directly.
* Shared crates provide reusable infrastructure and protocol code.
* The database crate is the only crate that communicates directly with PostgreSQL through SQLx.

---

## 4. Repository overview

```text
piquel/
├── apps/
│   ├── auth-service/
│   ├── auth-web/
│   ├── admin-api/
│   ├── admin-web/
│   ├── piquel-api/
│   └── piquel-web/
│
├── crates/
│   ├── database/
│   ├── auth-sdk/
│   ├── auth-middleware/
│   ├── auth-client/
│   ├── auth-protocol/
│   ├── service-auth/
│   ├── configuration/
│   ├── telemetry/
│   └── test-support/
│
├── packages/
│   ├── auth-client-js/
│   ├── ui/
│   ├── design-tokens/
│   ├── eslint-config/
│   └── typescript-config/
│
├── proto/
│   └── piquel/
│       └── auth/
│           └── v1/
│
├── infra/
│   └── monitoring/
│
├── docs/
│   ├── architecture/
│   ├── security/
│   ├── decisions/
│   └── operations/
│
├── scripts/
├── plans/
├── Cargo.toml
├── Cargo.lock
├── package.json
├── pnpm-workspace.yaml
└── justfile
```

Not every directory must exist immediately. Add a directory only when it has a concrete use.

Do not create placeholder packages or speculative abstraction layers.

---

## 5. Root-level responsibilities

### `Cargo.toml`

The root Cargo workspace defines all Rust applications and libraries.

All dependencies & versions should be declared in `[workspace.dependencies]`.

Applications and crates must still list the dependencies they use explicitly.

Example:

```toml
[workspace]
resolver = "2"
members = [
    "apps/auth-service",
    "apps/admin-api",
    "apps/piquel-api",
    "crates/*",
]

[workspace.dependencies]
anyhow = "1"
thiserror = "2"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
serde = { version = "1", features = ["derive"] }
```

### `package.json` and `pnpm-workspace.yaml`

The root JavaScript workspace manages frontend applications and shared packages.
Use `pnpm` for workspace dependency management.
A package must not depend on another application under `apps/`.
Shared frontend code belongs under `packages/`.

### `justfile`

The root `justfile` provides consistent development commands.

Typical commands include:

```text
just test
just lint
just format
just check
just dev-auth
just dev-admin
just migrate
just generate-proto
just prepare-sqlx
```

Commands should delegate to Cargo, pnpm, Protobuf tools, and other underlying tooling rather than hiding important behavior in large shell scripts.

---

## 6. Applications

Everything under `apps/` is a deployable application.
Applications may depend on shared crates and packages.
Applications must not depend directly on another application.
Invalid dependency:

```text
apps/admin-api
    └── imports apps/auth-service
```

Valid dependency:

```text
apps/admin-api
    ├── depends on crates/database
    ├── depends on crates/auth-client
    └── depends on crates/auth-protocol
```

### 6.1 `apps/auth-service`

The central authentication authority served at `auth.piquel.fr`.

It owns:

* Piquel accounts
* Passkey authentication
* Social authentication
* OIDC and OAuth endpoints
* Login sessions
* Access-token issuance
* Refresh-token rotation
* Service authentication
* Internal authentication RPC
* Authentication audit events
* Authentication-related internal events

Its internal modules may include:

```text
apps/auth-service/src/
├── account/
├── email/
├── federation/
├── oidc/
├── passkey/
├── session/
├── token/
├── service_identity/
├── rpc/
├── audit/
├── event_log/
├── lib.rs
└── main.rs
```

These modules are internal implementation details.
Do not extract an internal module into a shared crate unless another application has a real, justified need for the same behavior.
Authentication policy and authentication invariants must remain owned by `auth-service`.

### 6.2 `apps/auth-web`

The user-facing frontend for `auth.piquel.fr`.
It may contain:

* Login pages
* Passkey registration
* Social login
* OAuth consent
* Session management
* Account security settings
* Authentication error pages

It communicates through supported HTTP APIs.
It must not receive internal service credentials.
It must not access PostgreSQL directly.

### 6.3 `apps/admin-api`

The trusted administrative backend.

It may provide operations such as:
* Searching users
* Viewing account state
* Reviewing security events
* Disabling accounts
* Revoking sessions
* Managing administrative roles

It may use the shared database crate for explicitly supported administrative data access.
It must not duplicate authenticaton policy.
Security-sensitive account mutations should be implemented through well-defined database operations or auth-service RPC methods, depending on which component owns the invariant.
Do not modify authentication tables with ad hoc queries.

### 6.4 `apps/admin-web`

The administrative frontend.
It calls `admin-api`.

It must not:
* Access the database
* Hold database credentials
* Hold internal service private keys
* Call privileged internal RPC endpoints directly from browser code

### 6.5 `apps/piquel-api`

The backend for the main `piquel.fr` product.
It may use:

* `crates/database`
* `crates/auth-middleware`
* `crates/auth-client`
* `crates/auth-protocol`
* Shared configuration and telemetry crates

It validates Piquel access tokens through the authentication SDK.
It owns its product-specific authorization and business rules.

### 6.6 `apps/piquel-web`

The frontend for the main `piquel.fr` product.
It uses the public authentication flow and communicates with `piquel-api`.
It must not contain server credentials in browser bundles.

---

## 7. Shared Rust crates

Everything under `crates/` is reusable Rust code.
Shared crates must have clear responsibilities and stable public interfaces.
They must not become containers for unrelated utilities.

### 7.1 `crates/database`

The only crate permitted to depend directly on SQLx.

It owns:
* PostgreSQL connection management
* SQL queries
* Database row mappings
* Repository implementations
* Wrapped database transactions
* Migrations
* Database error translation

Other applications and crates use its repository API.
They must not receive raw SQLx pools, rows, transactions, or errors.

A more detailed design is maintained in:

```text
docs/architecture/database-crate.md
```

### 7.2 `crates/auth-protocol`

Contains authentication protocol types shared between trusted Rust components.

Examples:
* `UserId`
* `SessionId`
* `ClientId`
* `ServiceId`
* Access-token claims
* Service-token claims
* Authentication method enums
* Stable internal error codes

It must not contain:
* SQLx row types
* Database schema details
* Auth-service business logic
* Web-framework-specific middleware

### 7.3 `crates/auth-middleware`

Contains framework-neutral JWT authentication logic and optional web-framework adapters.
It owns the `AuthMiddleware` builder.

Responsibilities include:
* JWT extraction
* Signature validation
* Issuer validation
* Audience validation
* Expiry validation
* JWKS caching
* Construction of a validated principal

Audience validation must remain mandatory for production use.

### 7.4 `crates/auth-client`

Contains the client for the private authentication RPC API.

It may wrap generated gRPC clients with:
* Service-token injection
* Deadlines
* Retry policy
* Error translation
* Tracing
* Safe configuration defaults

### 7.5 `crates/auth-sdk`

Provides the main ergonomic SDK facade.

It may re-export selected functionality from:
* `auth-protocol`
* `auth-middleware`
* `auth-client`
* `service-auth`

Downstream repositories should normally depend on this crate rather than understanding the monorepo’s internal crate layout.
Avoid placing all implementation code directly into this facade crate.

### 7.6 `crates/service-auth`

Contains service-level authentication support.

Responsibilities may include:
* Signed service assertions
* Short-lived service-token retrieval
* Token caching
* Token renewal
* RPC metadata injection

### 7.7 `crates/configuration`

Contains shared configuration loading and validation.

It may define:
* Environment configuration helpers
* Typed duration parsing
* URL parsing
* Secret references
* Common environment names

It must not contain application-specific business configuration.

### 7.8 `crates/telemetry`

Contains shared logging, tracing, and metrics initialization.

It may define:
* Standard tracing configuration
* Request IDs
* OpenTelemetry integration
* Metric naming conventions
* Sensitive-data redaction helpers

### 7.9 `crates/test-support`

Contains test-only helpers shared by multiple Rust packages.

Examples:
* Test database setup
* Fixture builders
* Token factories
* Mock OIDC providers
* Test service identities

Production crates must not depend on `test-support` outside development or test configurations.

---

## 8. Shared frontend packages

Shared JavaScript and TypeScript packages live under `packages/`.

### 8.1 `packages/auth-client-js`

Provides browser-safe authentication helpers.

It may include:
* Authorization URL construction
* PKCE helpers
* Callback processing
* Session-aware frontend utilities

It must not contain:
* Internal service authentication
* Private keys
* Database access
* Privileged RPC clients

### 8.2 `packages/ui`

Contains reusable UI components.
Keep it framework-specific or framework-neutral according to actual use.
Do not create React and Svelte wrappers until both are needed.

### 8.3 `packages/design-tokens`

Contains shared visual constants such as:
* CSS variables
* Typography definitions
* Spacing scales
* Border radii
* Semantic colors

### 8.4 Configuration packages

Shared ESLint and TypeScript settings belong in dedicated packages rather than being copied across applications.

---

## 9. Protocol definitions

Internal Protobuf definitions live under:
```text
proto/piquel/auth/v1/
```

Protocol files are not owned by a specific application because both the server and clients consume them.

Rules:
* Use versioned packages.
* Never reuse deleted field numbers.
* Reserve removed field names and numbers.
* Prefer additive changes.
* Avoid exposing database row structure.
* Keep browser clients away from private RPC protocols.
* Regenerate clients through repository commands rather than editing generated code.

Generated code should either be checked in consistently according to a documented repository policy.

---

## 10. Database ownership

The main Piquel services share one PostgreSQL database because their core information is closely related.
All PostgreSQL access goes through `crates/database`.

This rule applies even when a query appears trivial.

Do not:
* Add SQLx directly to an application
* Create an application-specific database pool
* Run raw SQL from an application
* Expose a `PgPool` from the database crate
* Expose a SQLx transaction from the database crate
* Return `sqlx::Error` from a public repository API

The shared database does not remove domain ownership.

Examples:
* Auth tables are owned conceptually by `auth-service`.
* Administrative tables are owned conceptually by `admin-api`.
* Main product tables are owned conceptually by `piquel-api`.

Repository methods should make ownership clear.
Applications must not modify another domain’s sensitive data through generic repository escape hatches.

---

## 11. Infrastructure directory

The monorepo does not currently prescribe a deployment platform or delivery pipeline.
Do not add speculative Kubernetes, Terraform, Docker Compose, or provider-specific deployment structures until a deployment strategy is selected.

For now, `infra/` contains monitoring configuration only:
```text
infra/
└── monitoring/
    ├── dashboards/
    ├── alerts/
    ├── recording-rules/
    └── README.md
```

### 11.1 Dashboards

Contains version-controlled monitoring dashboards for:
* Authentication
* API traffic
* Database health
* Redis health
* RPC traffic
* Frontend errors
* Platform-level availability

### 11.2 Alerts

Contains alert definitions for conditions such as:
* Elevated login failure rates
* Refresh-token replay detection
* Token-signing failures
* Database connection exhaustion
* High request latency
* Elevated server error rates
* RPC authentication failures
* Redis outages
* Background task failures

### 11.3 Recording rules

Contains precomputed metric expressions where the selected monitoring system supports them.

### 11.4 Monitoring rules

Monitoring configuration must not contain:
* Secrets
* Raw user identifiers
* Email addresses
* Tokens
* Authorization headers
* High-cardinality unbounded labels

Application instrumentation belongs in the relevant application or telemetry crate.
The `infra/monitoring` directory contains the configuration that consumes that instrumentation.

---

## 12. Documentation

Repository documentation lives under `docs/`.
```text
docs/
├── architecture/
├── security/
├── decisions/
└── operations/
```

### `docs/architecture`

Contains durable system and component designs.

Examples:
* Authentication architecture
* Monorepo structure
* Database crate design
* RPC architecture

### `docs/security`

Contains threat models, accepted risks, security requirements, and incident-related procedures.

### `docs/decisions`

Contains architectural decision records.

Use an ADR when changing a major boundary, including:
* Database ownership
* Authentication-token structure
* Frontend framework policy
* RPC protocol choice
* Deployment platform
* Migration strategy

### `docs/operations`

Contains operational procedures such as:
* Database migration
* Signing-key rotation
* Service-key rotation
* Backup restoration
* Incident response

Keep documentation updated when changing the architecture it describes.

---

## 13. Rust stack guidelines

These guidelines are repository defaults and may be updated through an architectural decision.

### 13.1 Asynchronous runtime

Use Tokio for asynchronous Rust.

Rules:
* Application binaries own runtime startup through `#[tokio::main]`.
* Shared libraries expose asynchronous functions without creating their own runtime.
* Do not call `Runtime::new()` inside reusable libraries.
* Avoid blocking operations on Tokio worker threads.
* Use `spawn_blocking` for unavoidable blocking work.
* Make cancellation behavior explicit for long-running tasks.
* Use timeouts on network and RPC operations.

### 13.2 Error handling

Use `thiserror` for typed library and domain errors.

Example:
```rust
#[derive(Debug, thiserror::Error)]
pub enum AuthenticationError {
    #[error("the access token has expired")]
    TokenExpired,

    #[error("the token audience is invalid")]
    InvalidAudience,

    #[error("the signing key is unavailable")]
    SigningKeyUnavailable,
}
```

Use `anyhow` at application boundaries for:
* Application startup
* CLI commands
* Top-level task orchestration
* Error context in binaries
* Operations where callers do not need to match error variants

Example:
```rust
async fn main_inner() -> anyhow::Result<()> {
    let config = load_config()
        .context("failed to load auth-service configuration")?;

    run(config).await
}
```

Do not expose `anyhow::Error` from reusable public crate APIs when callers need structured handling.

General rule:

```text
Libraries and domains: thiserror
Application boundaries and orchestration: anyhow
```

### 13.3 Dependency discipline

Before adding a dependency:
* Confirm an existing workspace dependency does not already solve the problem.
* Prefer well-maintained crates with narrow responsibilities.
* Avoid adding two libraries for the same purpose.
* Add versions through `[workspace.dependencies]`.
* Avoid large default feature sets when only a subset is needed.
* Consider security and maintenance history.

---

## 14. Frontend stack guidelines

Frontends may use SvelteKit or React-based frameworks.
Do not force all frontends onto one framework unless a project-wide decision has been made.
Shared browser packages should avoid framework coupling where practical.

Rules:
* Do not place secrets in browser environment variables.
* Do not expose internal RPC endpoints to browser clients.
* Do not store refresh tokens in `localStorage`.
* Prefer generated or typed API clients.
* Validate external data at runtime where necessary.
* Keep authentication protocol logic in shared auth packages rather than duplicating it across frontends.

---

## 15. Dependency direction

The intended dependency direction is:

```text
applications
    │
    ├── domain-focused shared crates
    ├── auth SDK crates
    ├── database crate
    ├── configuration
    └── telemetry

database crate
    │
    ├── SQLx
    └── shared primitive types

auth middleware
    │
    └── auth protocol

auth client
    │
    ├── generated RPC protocol
    ├── service auth
    └── auth protocol
```

Dependencies must not form cycles.
Applications are leaves of the dependency graph. No reusable crate may depend on an application.

---

## 16. Agent modification rules

Coding agents must follow these rules unless the task explicitly overrides them.

### Before modifying code

1. Identify the owning application or crate.
2. Read the closest architecture document.
3. Inspect existing patterns before creating a new abstraction.
4. Check workspace dependencies before adding a crate.
5. Determine whether a protocol or migration change is required.

### While modifying code

1. Do not import code from another application.
2. Do not add SQLx outside `crates/database`.
3. Do not expose raw database handles.
4. Do not bypass audience validation.
5. Do not log credentials or tokens.
6. Do not add deployment-specific infrastructure without an explicit decision.
7. Do not modify generated code manually.
8. Do not place business logic in generic utility crates.
9. Do not create a shared crate for code used by only one application.
10. Keep public APIs smaller than internal APIs.

### After modifying code

1. Run formatting.
2. Run linting.
3. Run affected tests.
4. Run workspace checks when practical.
5. Update protocol fixtures after protocol changes.
6. Update SQLx metadata after checked-query changes.
7. Add or update migrations for schema changes.
8. Update documentation when an architectural rule changes.

### The `plans` directory

This directory contains active plans that agents are working on (writing or
implementing). It should not contain any deployed code or configuration.

---

## 17. Prohibited patterns

The following patterns are not allowed without an explicit architectural decision:

```text
apps/admin-api importing apps/auth-service
apps/piquel-api importing apps/admin-api
SQLx as an application dependency
Returning PgPool from crates/database
Returning sqlx::Error from crates/database
Raw SQL embedded in application code
Frontends calling internal gRPC APIs
Browser bundles containing service credentials
Universal JWT audiences
Disabling JWT expiry validation
Disabling JWT audience validation
Using display names or usernames as foreign keys
Adding speculative deployment infrastructure
Creating a miscellaneous shared-utils crate
```

---

## 18. Adding a new application

Before adding a new application under `apps/`, document:
* Its user-facing or internal purpose
* Its deployment boundary
* Its data ownership
* Its authentication model
* Which shared crates it requires
* Whether it requires new database repositories
* Whether it requires new public or internal protocols

A new application should be independently buildable and testable.
Do not create a separate application merely to split code that belongs in one process.

---

## 19. Adding a new shared crate

Create a new shared crate only when:
* At least two consumers require the functionality, or
* It represents a critical boundary worth isolating, such as database access or authentication middleware

The crate must have:
* A single clear purpose
* A documented public API
* No dependency on applications
* Typed errors
* Tests for public behavior

Avoid generic names such as:
```text
common
shared
utils
helpers
```

Prefer names that describe responsibility.

---

## 20. Guiding principle

The repository is a monorepo for coordinated development, not permission to ignore architectural boundaries.

The central rule is:
> Share infrastructure and stable interfaces deliberately, while keeping domain ownership explicit.

Contributors should prefer clear dependencies, typed APIs, and explicit ownership over shortcuts that create hidden coupling.
