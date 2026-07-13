# Piquel Authentication Service
## Architecture and Technical Design Specification
**Status:** Draft  
**Version:** 0.1  
**Scope:** First production iteration
## 1. Executive summary
Piquel Auth is a centralized identity and authentication platform shared by multiple independent Piquel products.
A person has one global Piquel account. That account can be used to authenticate with any Piquel product, while each product remains operationally and logically independent.

Piquel Auth provides:
- Passkey authentication
- Federated authentication through approved external identity providers
- OpenID Connect and OAuth-compatible public endpoints
- Short-lived, audience-restricted access tokens
- Rotating, centrally revocable refresh tokens
- Central account and session management
- A private RPC API for trusted downstream services
- Service-to-auth-service authentication
- Rust SDKs for token validation and protocol integration
- An internal event log for future event broadcasting

Piquel Auth is deployed as one stateless application process that can run as multiple replicas. PostgreSQL is the authoritative state store. Redis may be used for disposable coordination, rate limiting, and short-lived state.

Downstream products:
- Store only the global Piquel user ID as their identity reference
- Validate access tokens locally
- Own their product-specific permissions and data
- Own credentials for product-specific external integrations
- Use the Piquel SDK for authentication integration

The first iteration intentionally excludes cross-product service delegation, a distributed user-event system, deletion orchestration, TOTP, and centrally stored external API credentials.
## 2. Goals
### 2.1 Global identity
Every person has one Piquel account with one immutable user ID.
The same account can be used across all Piquel products.
A user may authenticate through any supported authentication method linked to the account.
### 2.2 Independent products
Each product remains independent.
Products do not call one another and do not exchange user tokens with one another.
Each product:
- Has its own client registration
- Has its own API audience
- Receives its own access tokens
- Receives its own refresh-token families
- Owns its own application data
- Owns its own product authorization model
### 2.3 Centralized authentication
Piquel Auth owns:
- Accounts
- Verified email addresses
- Usernames and display names
- Passkeys
- Federated login identities
- Login sessions
- Refresh tokens
- OIDC client registrations
- Service identities
- Signing keys
- Authentication audit information

Downstream products must not store:
- Passkey credentials
- Piquel refresh tokens
- Social-login credentials used to authenticate a Piquel account
- Piquel session cookies
- Authentication secrets belonging to another product
### 2.4 Low-latency request authentication
Ordinary product API requests must not require a network call to Piquel Auth.
Products validate short-lived access JWTs locally using cached public signing keys.
### 2.5 Strong product isolation
An access token issued for one product API must not be accepted by another product API.
Audience validation is mandatory.
### 2.6 Easy integration
A first-party Rust SDK provides:
- Login-flow helpers
- Callback validation
- Token refresh handling
- JWT validation
- Web-framework middleware
- Internal RPC clients
- Service-token management
- Helpers for product-owned OAuth integrations
## 3. Non-goals for the first iteration
The following capabilities are explicitly outside the initial scope:
- TOTP or authenticator-app codes
- Cross-product service-to-service delegation
- OAuth Token Exchange between products
- A centralized vault for product-specific GitHub, Google, or similar credentials
- A production event broker
- Guaranteed user-event delivery to downstream products
- Distributed account-deletion orchestration
- Pairwise or product-specific Piquel identities
- Third-party developer registration
- Dynamic client registration
- Risk-based authentication
- Automatic fraud detection
- Enterprise identity federation
- Organization-level identity administration
The initial internal event log must be designed so that reliable event broadcasting can be added later.
## 4. System context
```text
                         Public clients
                  Web, native, desktop, CLI
                              │
                              │ OIDC / OAuth / account APIs
                              ▼
                  ┌─────────────────────────┐
                  │      Piquel Auth        │
                  │                         │
                  │ Passkeys                │
                  │ Social login            │
                  │ OIDC authorization      │
                  │ Token issuance          │
                  │ Session management      │
                  │ Internal RPC API        │
                  │ Internal event log      │
                  └────────────┬────────────┘
                               │
              ┌────────────────┼─────────────────┐
              ▼                ▼                 ▼
         PostgreSQL          Redis        Key-management system
       authoritative data   disposable      signing and encryption
                              state
                              
                              ▲
                              │ authenticated internal RPC
            ┌─────────────────┼──────────────────┐
            │                 │                  │
      Product A API     Product B API      Product C API
            │                 │                  │
            └──── independently validate JWTs ──┘
```
Piquel Auth is one deployable executable.
Its internal modules are code boundaries rather than independently deployed services.
## 5. Internal module structure
The Piquel Auth process should be organized into modules with explicit ownership boundaries.
```text
account
email
passkey
federation
session
oidc
token
service_identity
internal_rpc
event_log
audit
administration
storage
crypto
```
### 5.1 Account module
Owns:
- Global users
- Username
- Display name
- Account status
- Account creation and disabling
- Profile versions
### 5.2 Email module
Owns:
- Email normalization
- Verification status
- Primary email selection
- Unique verified-email constraints
### 5.3 Passkey module
Owns:
- WebAuthn registration ceremonies
- WebAuthn authentication ceremonies
- Stored public-key credentials
- Credential metadata
- Passkey addition and removal
### 5.4 Federation module
Owns:
- Social-login initiation
- Provider callback validation
- External issuer and subject mappings
- Email-based automatic account linking
- Provider metadata
### 5.5 Session module
Owns:
- Central Piquel login sessions
- Product-specific authorization sessions
- Session revocation
- Authentication timestamps
- Authentication methods
### 5.6 OIDC module
Owns:
- Authorization endpoint
- Token endpoint
- UserInfo endpoint
- Discovery metadata
- OIDC client validation
- Redirect URI validation
- Authorization Code flow
- PKCE
- State and nonce processing
### 5.7 Token module
Owns:
- Access-token issuance
- ID-token issuance
- Refresh-token issuance
- Refresh-token rotation
- Refresh-token replay detection
- Signing-key selection
- Token revocation
### 5.8 Service identity module
Owns:
- Downstream service registrations
- Service public keys
- Service assertion verification
- Short-lived internal service tokens
- Internal RPC permissions
### 5.9 Internal RPC module
Owns:
- Private service-facing APIs
- Service authentication middleware
- Method-level authorization
- Request deadlines and limits
### 5.10 Event-log module
Owns:
- Append-only internal domain events
- Aggregate sequence numbers
- Event schema versions
- Future publication metadata
### 5.11 Audit module
Owns:
- Authentication security events
- Administrative actions
- Session changes
- Credential changes
- Social identity linking
The security audit log is separate from the future integration event stream.
## 6. Identity model
### 6.1 Global user ID
Every account has one immutable identifier.
UUIDv7 is recommended.

The precise representation may differ, but it must be:
- Globally unique
- Immutable
- Never reassigned
- Unrelated to email, username, or provider identity
- Suitable for storage by downstream services
The global user ID is exposed as the OIDC `sub` claim.
### 6.2 Mutable profile fields
The central profile initially contains:
- User ID
- Username
- Display name
- Verified email addresses
- Primary email address
- Profile version
- Account status
- Created timestamp
- Updated timestamp
A downstream product must never use username, display name, or email as a database identity key.
Only the global user ID is authoritative for identity references.
### 6.3 Profile version
Each user has a monotonically increasing `profile_version`.
It is incremented whenever token-visible profile data changes, including:
- Username
- Display name
- Primary email, if later included in tokens
- Other future token-visible fields
The access token includes the current profile version.
Products may use it to detect that locally cached presentation data is stale.
## 7. Authentication methods
Piquel Auth supports two authentication categories:
1. Piquel passkeys
2. Approved social identity providers
TOTP is not supported.
### 7.1 Passkeys
Passkeys are implemented using WebAuthn.
The Piquel authentication domain is the WebAuthn relying party.
```text
auth.piquel.fr
```

Stored passkey information includes:
```text
credential_id
user_id
public_key
signature_counter
transports
backup_eligible
backup_state
friendly_name
created_at
last_used_at
```
Private keys never reach Piquel Auth.
Passkey operations include:
- Register passkey
- Authenticate with passkey
- List registered passkeys
- Rename passkey
- Remove passkey
### 7.2 Social login
Approved providers may be used as complete authentication methods.
Examples may include:
- Google
- GitHub
- Apple
- Microsoft
The provider configuration is controlled by Piquel Auth.
Each provider identity is stored using:
```text
issuer
subject
user_id
provider_name
linked_email
created_at
last_used_at
```

The permanent identity key is:
```text
(issuer, subject)
```
Email is used only during initial account matching.
### 7.3 Automatic email-based linking
For the first iteration, a new social identity is automatically linked to an existing Piquel account when the provider supplies an email matching an existing account.
The flow is:
1. Validate the external provider response.
2. Obtain the stable provider issuer and subject.
3. Obtain an email that the provider declares verified.
4. Look up an existing identity by `(issuer, subject)`.
5. If found, authenticate the linked Piquel account.
6. Otherwise, normalize the verified email.
7. Look up an existing Piquel account with that verified normalized email.
8. If found, link the new provider identity to that account.
9. Otherwise, create a new Piquel account.
10. Record a security audit event.
After linking, future authentication uses `(issuer, subject)`, not email.
Automatic linking must not occur when:
- The provider does not assert that the email is verified
- No usable email is returned
- Multiple accounts match because of inconsistent legacy data
- The provider is not explicitly approved for automatic linking
Email normalization must be conservative.

It may include:
- Unicode normalization where appropriate
- Domain-name case normalization
- Local-part handling consistent with the system’s documented email policy

It must not:
- Remove plus-address suffixes
- Remove dots from Gmail addresses
- Apply provider-specific mailbox transformations
- Guess that two different addresses are equivalent
### 7.4 Social login and passkey recovery
For the first iteration, a fresh social login is considered sufficient to regain full account access, including passkey management.
This means a social login may be used to:
- View passkey metadata
- Register a passkey
- Remove a passkey
- Recover an account without an existing passkey
After social authentication, the interface should recommend registering a passkey.
Passkey registration is not mandatory.
This is an explicitly accepted first-iteration security trade-off. The architecture must make it possible to introduce stronger assurance requirements later without changing account identifiers or provider mappings.
## 8. Public protocol surface
The public API remains standards-oriented and HTTP-based.
### 8.1 Required endpoints
```text
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json

GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke
GET  /oidc/userinfo
GET  /oidc/logout

POST /webauthn/register/start
POST /webauthn/register/finish
POST /webauthn/authenticate/start
POST /webauthn/authenticate/finish

GET  /login/{provider}
GET  /login/{provider}/callback
```
Exact paths may change, but discovery metadata must remain authoritative.
### 8.2 Supported authorization flow
The primary flow is:
```text
Authorization Code with PKCE
```
PKCE is required for all clients.
The authorization request must validate:
- Registered client ID
- Exact redirect URI
- Response type
- Requested scopes
- Requested audience or resource
- PKCE challenge
- State
- Nonce when required
- Prompt and login requirements
- Maximum authentication age when requested
### 8.3 Client registration
Each product client has a static administrative registration.
A registration includes:
```text
client_id
display_name
application_type
allowed_redirect_uris
allowed_post_logout_redirect_uris
allowed_scopes
allowed_audiences
token_endpoint_auth_method
access_token_lifetime
refresh_token_policy
enabled
```
Dynamic client registration is not supported in the first iteration.
## 9. Token architecture
Piquel Auth issues three user-related token types:
1. ID token
2. Access token
3. Refresh token
A fourth short-lived token may be issued for purpose-bound sensitive operations.
## 10. ID token
The ID token is an OIDC token intended for the application client.
It describes:
- The authenticated account
- The authentication event
- The intended client
- The authentication time
- The methods used

It must not be used as an API access token.
Representative claims:
```json
{
  "iss": "https://auth.piquel.example",
  "sub": "0198a346-1e13-7d91-bf85-15d90f7e2885",
  "aud": "product-a-web",
  "nonce": "client-generated-nonce",
  "name": "Piquel Chips",
  "preferred_username": "piquel",
  "amr": ["passkey"],
  "auth_time": 1783771200,
  "iat": 1783771200,
  "exp": 1783771500
}
```
## 11. Access token
### 11.1 Purpose
The access token authenticates a user to one specific product API.
It is:
- A signed JWT
- Short-lived
- Validated locally
- Restricted to an audience
- Not centrally introspected during ordinary requests
### 11.2 Lifetime
The default lifetime is: `5 minutes`
Individual clients may receive a stricter lifetime, but products must not configure a longer lifetime without an explicit security decision.
### 11.3 Representative claims
```json
{
  "iss": "https://auth.piquel.example",
  "sub": "0198a346-1e13-7d91-bf85-15d90f7e2885",
  "aud": "product-a-api",
  "client_id": "product-a-web",
  "sid": "ses_0198a34d",
  "jti": "at_0198a351",

  "username": "piquel",
  "name": "Piquel Chips",
  "profile_version": 12,

  "amr": ["passkey"],
  "auth_time": 1783771200,

  "iat": 1783771200,
  "nbf": 1783771200,
  "exp": 1783771500
}
```
### 11.4 JWT header
```json
{
  "typ": "at+jwt",
  "alg": "ES256",
  "kid": "signing-key-2026-07"
}
```
Only explicitly approved asymmetric algorithms are accepted.
Symmetric JWT signing must not be used between Piquel Auth and downstream products.
### 11.5 Embedded profile information
The access token includes:
- User ID
- Username
- Display name
- Profile version
This allows products to render common user-interface elements without querying Piquel Auth on every page load.
These claims are snapshots.
They may remain stale for the remainder of the token lifetime.
Products must not use username or display name for:
- Authorization decisions
- Database ownership
- Unique identity constraints
- Permanent references
Only `sub` is the stable user identity.
### 11.6 Audience isolation
Every product API has a unique audience.
Examples:
```text
product-a-api
product-b-api
product-c-api
```
A Product A API token must be rejected by Product B regardless of whether its signature and expiry are valid.
Audience validation is mandatory and cannot be disabled in production SDK middleware.
### 11.7 Required validation
A resource server must validate:
- Token presence
- Token structure
- `typ`
- Allowed signing algorithm
- Signature
- Known signing key
- Exact issuer
- Expected audience
- Subject format
- Issued-at time
- Not-before time
- Expiry
- Required claims
- Configured clock tolerance
A valid signature alone is never sufficient.
## 12. Refresh token
### 12.1 Purpose
A refresh token continues a product-specific user session.
It is used to obtain:
- A new access token
- A new ID token when appropriate
- A replacement refresh token
It may also be used to identify the session that is requesting the beginning of a sensitive-operation flow.
It must not directly authorize a sensitive account mutation.
### 12.2 Representation
The refresh token is an opaque, high-entropy random credential.
It is not a JWT.
It contains no client-readable user information.
Conceptually, the server-side record identifies the user, client, session, and token family.
Example wire representation:
```text
prt_v1_<token-id>.<random-secret>
```
The database stores:
- An indexed token identifier
- A cryptographic hash or keyed digest of the secret
- Server-side metadata
The raw refresh token is never stored.
### 12.3 Server-side record
```text
refresh_tokens
--------------
id
token_id
secret_digest
token_family_id
user_id
client_id
session_id
allowed_audience
granted_scopes
created_at
expires_at
last_used_at
rotated_from_id
consumed_at
revoked_at
revocation_reason
```
### 12.4 Product and device isolation
Refresh-token families are specific to:
- User
- Product client
- Device or installation
- Login session

Example:
```text
User
├── Product A / laptop / family A1
├── Product A / phone  / family A2
├── Product B / laptop / family B1
└── Product C / CLI    / family C1
```
Revoking one family does not revoke unrelated product sessions.
### 12.5 Rotation
Every successful refresh rotates the token.
The transaction must:
1. Lock or atomically consume the current token.
2. Verify that it is active.
3. Mark it consumed.
4. Create a replacement token in the same family.
5. Issue a new access token.
6. Commit all changes atomically.
7. Return the replacement refresh token.
### 12.6 Replay detection
If an already consumed refresh token is presented again:
1. Treat the event as possible credential theft.
2. Revoke the complete refresh-token family.
3. Record a security event.
4. Reject the request.
5. Optionally notify the user.
### 12.7 Revocation
Refresh tokens may be revoked by:
- Explicit product logout
- Global logout
- User session management
- Account disabling
- Passwordless credential changes where policy requires it
- Replay detection
- Administrative action
- Security incident response
Revocation is immediate at Piquel Auth.
A previously issued access JWT may remain valid until its expiry, subject to its five-minute maximum lifetime.
### 12.8 Refresh-token security classification
A refresh token is a high-value credential.
Immediate revocability does not make theft harmless. An attacker may use a stolen token before its theft is detected.
Refresh tokens must therefore receive stronger storage protection than access tokens.

For browser applications:
- Prefer a backend-for-frontend architecture.
- Store refresh tokens server-side where possible.
- Otherwise use a Secure, HttpOnly, SameSite cookie.
- Never expose refresh tokens to JavaScript.
- Never store refresh tokens in `localStorage`.

For native applications:
- Use operating-system secure credential storage.
- Bind sessions to the application client.
- Use PKCE.
## 13. Sensitive operations
Sensitive operations include:
- Adding or removing passkeys
- Changing the primary email
- Linking or unlinking a social login
- Revoking all sessions
- Deleting an account
- Exporting sensitive account information
- Changing security-critical profile settings
A refresh token may establish which session is requesting the operation, but it does not directly approve the mutation.
### 13.1 Flow
1. The client requests a sensitive operation.
2. Piquel Auth checks the current product session.
3. Piquel Auth requires fresh authentication.
4. The user authenticates with a passkey or approved social provider.
5. Piquel Auth issues a short-lived purpose-bound authorization token.
6. The client submits the mutation with that token.
7. Piquel Auth validates the token’s audience, purpose, expiry, and user.
8. The mutation is performed.
9. The token may be marked used where single-use behavior is required.
### 13.2 Purpose token
Example:
```json
{
  "iss": "https://auth.piquel.example",
  "sub": "0198a346-1e13-7d91-bf85-15d90f7e2885",
  "aud": "piquel-account-management",
  "purpose": "manage-passkeys",
  "sid": "ses_0198a34d",
  "auth_time": 1783771400,
  "iat": 1783771400,
  "exp": 1783771520,
  "jti": "step_0198a360"
}
```
Recommended lifetime:
```text
2 minutes
```
Under the first-iteration policy, either a fresh passkey authentication or a fresh approved social login satisfies the operation.
## 14. Sessions and single sign-on
Piquel Auth maintains a central login session.
When a user visits a second Piquel product:
1. The product redirects the user to Piquel Auth.
2. Piquel Auth detects the existing central session.
3. Piquel Auth evaluates the new client request.
4. Piquel Auth issues a new authorization code.
5. The new product exchanges it for its own tokens.
6. The user does not need to authenticate again unless policy requires it.
The products do not share refresh tokens.
The products do not accept one another’s access tokens.
Single sign-on is achieved through the central Piquel browser session, not through universal bearer credentials.
## 15. Downstream product model
Each product stores the Piquel user ID on domain records.
Example:
```text
projects
--------
id
owner_user_id
name
created_at
```
The product owns:
- Product roles
- Product permissions
- Product resources
- Product settings
- Product billing
- Product onboarding
- Product-specific OAuth credentials
- Product-specific audit records
Piquel Auth does not decide whether a user may edit a particular product resource.
Piquel Auth proves who the user is. The product decides what that user may do.
## 16. Internal API architecture
### 16.1 Protocol choice
The private service API should use RPC.
The recommended first implementation is:
```text
gRPC over HTTP/2
Protocol Buffers
Rust Tonic client and server
```
RPC is suitable because the private API:
- Is consumed by controlled first-party services
- Benefits from generated typed clients
- Has a relatively small number of explicit operations
- Requires strict request and response schemas
- Needs deadlines and structured errors
- Does not need browser compatibility
- Can evolve through versioned Protobuf packages
Public OIDC and OAuth endpoints remain HTTP-based.
### 16.2 Network boundary
The internal RPC server must:
- Listen on a separate port or listener
- Be inaccessible from the public internet
- Require TLS
- Require an authenticated service identity
- Enforce method-specific permissions
- Enforce request deadlines
- Enforce message-size limits
- Avoid exposing gRPC reflection publicly in production
Private networking is an additional control, not a substitute for authentication.
### 16.3 Initial RPC surface
```protobuf
syntax = "proto3";

package piquel.auth.v1;

service AuthService {
  rpc GetUser(GetUserRequest)
      returns (GetUserResponse);

  rpc BatchGetUsers(BatchGetUsersRequest)
      returns (BatchGetUsersResponse);

  rpc GetSessionStatus(GetSessionStatusRequest)
      returns (GetSessionStatusResponse);

  rpc RevokeSession(RevokeSessionRequest)
      returns (RevokeSessionResponse);

  rpc RevokeAllUserSessions(RevokeAllUserSessionsRequest)
      returns (RevokeAllUserSessionsResponse);

  rpc GetServiceConfiguration(GetServiceConfigurationRequest)
      returns (GetServiceConfigurationResponse);
}
```

Potential later methods:
```protobuf
rpc DisableUser(DisableUserRequest)
    returns (DisableUserResponse);

rpc GetProfileVersion(GetProfileVersionRequest)
    returns (GetProfileVersionResponse);

rpc ConfirmSensitiveOperation(ConfirmSensitiveOperationRequest)
    returns (ConfirmSensitiveOperationResponse);
```
### 16.4 RPC non-goals
The RPC service should not be called for every product request.
It should not provide a general `ValidateAccessToken` method for normal JWT validation.
Local JWT validation remains the ordinary request path.
RPC is used for operations requiring authoritative current state, such as:
- Reading the latest central profile
- Batch-resolving users
- Checking session status
- Revoking sessions
- Administrative account changes
## 17. Service-level authentication
The user’s access token authenticates the user.
A separate service credential authenticates the downstream product backend.
These identities must not be conflated.
### 17.1 Service registration
Each backend has a service identity:
```text
service_id
display_name
public_keys
allowed_rpc_methods
allowed_user_data_fields
enabled
created_at
```

Example:
```text
svc_product_a_backend
```
### 17.2 Service credential
The service owns an asymmetric private key.
Piquel Auth stores only the corresponding public key.
At runtime:
1. The service creates a short-lived signed client assertion.
2. It sends the assertion to the internal service-token endpoint.
3. Piquel Auth verifies the signature and service registration.
4. Piquel Auth issues a short-lived service JWT.
5. The SDK caches the service token.
6. The SDK renews it before expiry.
7. The service token is attached to internal RPC metadata.
### 17.3 Service token
Representative claims:
```json
{
  "iss": "https://auth.piquel.example",
  "sub": "svc_product_a_backend",
  "aud": "piquel-internal-api",
  "scope": "users:read sessions:revoke",
  "iat": 1783771200,
  "nbf": 1783771200,
  "exp": 1783771500,
  "jti": "st_0198a36e"
}
```
Recommended lifetime:
```text
5 minutes
```
### 17.4 Service-token management
The SDK is responsible for:
- Creating signed service assertions
- Obtaining service tokens
- Caching active tokens
- Refreshing before expiry
- Avoiding duplicate simultaneous refreshes
- Adding the token to RPC metadata
- Retrying once after an authentication failure when safe
- Redacting tokens from logs and errors
The service-token manager must be concurrency-safe.
### 17.5 Administrative service management
Service registration and key rotation are separate administrative operations.
They are not ordinary runtime SDK calls.
Administrative capabilities include:
- Create service identity
- Add public key
- Remove public key
- Rotate key
- Disable service
- Configure RPC permissions
- Review service audit history
## 18. Rust SDK architecture
The SDK should be divided into focused crates or modules.
Recommended structure:
```text
piquel-auth-core
piquel-auth-client
piquel-auth-middleware
piquel-auth-rpc
piquel-auth-oauth
piquel-auth-axum
```
The exact crate split may initially be simplified, but the public API should preserve these conceptual boundaries.
### 18.1 Core crate
Provides:
- User ID type
- Client ID type
- Audience type
- Token claim types
- Validated principal type
- Error types
- Shared configuration types
### 18.2 Application client
Provides:
- OIDC discovery loading
- Authorization URL construction
- State generation
- Nonce generation
- PKCE generation
- Callback processing
- Code exchange
- Refresh
- Logout
- Current-user extraction
### 18.3 RPC client
Provides generated or wrapped gRPC clients.
It automatically integrates with the service-token manager.
### 18.4 OAuth helper module
Provides reusable primitives for product-owned external integrations:
- OAuth state creation and verification
- PKCE generation and validation
- Authorization URL construction
- Callback parsing
- Token response parsing
- Provider error normalization
- Secret redaction
- Webhook-signature primitives where appropriate

The downstream product remains responsible for:
- Registering its external provider application
- Selecting scopes
- Persisting provider credentials
- Refreshing provider credentials
- Revoking provider access
- Product-specific consent
- Provider-specific API calls

Piquel Auth does not store these product integration credentials.
## 19. AuthMiddleware builder
The SDK exposes an `AuthMiddleware` builder.
The builder creates a reusable request-authentication component for a specific product API.
### 19.1 Example
```rust
use std::time::Duration;

use piquel_auth::{
    AuthMiddleware,
    AuthMiddlewareError,
};

let auth_middleware = AuthMiddleware::builder()
    .issuer("https://auth.piquel.example")
    .audience("product-a-api")
    .jwks_uri("https://auth.piquel.example/.well-known/jwks.json")
    .allowed_algorithm("ES256")
    .clock_tolerance(Duration::from_secs(30))
    .require_claim("sub")
    .require_claim("sid")
    .require_claim("username")
    .require_claim("name")
    .require_claim("profile_version")
    .build()
    .await?;
```

Framework integrations may then expose it as a layer:
```rust
use axum::{
    routing::get,
    Router,
};

let app = Router::new()
    .route("/me", get(get_current_user))
    .layer(auth_middleware.into_axum_layer());
```

Alternatively, the framework-neutral authenticator may be called directly:
```rust
let principal = auth_middleware
    .authenticate_request(&request)
    .await?;
```
### 19.2 Mandatory production settings
The following settings are mandatory:
- Issuer
- Audience
- Allowed signing algorithm
- JWKS source
Production construction must fail when any are missing.
Audience verification cannot be disabled.
Signature verification cannot be disabled.
Expiry verification cannot be disabled.
### 19.3 Builder options
Potential builder methods include:
```rust
AuthMiddleware::builder()
    .issuer(...)
    .audience(...)
    .jwks_uri(...)
    .allowed_algorithm(...)
    .clock_tolerance(...)
    .required_scope(...)
    .require_claim(...)
    .bearer_header(...)
    .jwks_cache_ttl(...)
    .http_client(...)
    .on_authentication_failure(...)
    .build()
    .await
```
Options intended only for tests must be gated behind explicit testing APIs or feature flags.
### 19.4 Validation sequence
The middleware performs validation in a strict sequence:
1. Read the `Authorization` header.
2. Require the `Bearer` scheme.
3. Reject multiple or malformed credentials.
4. Parse the JWT header.
5. Require `typ = at+jwt`.
6. Require an explicitly allowed algorithm.
7. Read `kid`.
8. Resolve the corresponding public key.
9. Verify the signature.
10. Parse the claims.
11. Verify the exact issuer.
12. Verify the configured audience.
13. Verify expiry.
14. Verify not-before.
15. Verify issued-at sanity.
16. Validate required claim types.
17. Validate the Piquel user ID format.
18. Construct an immutable validated principal.
### 19.5 JWKS handling
The middleware maintains an in-memory JWKS cache.
Behavior:
- Fetch keys during startup or first use.
- Respect a bounded cache lifetime.
- Refresh keys when the cache expires.
- On an unknown `kid`, perform at most one controlled refresh.
- Rate-limit unknown-key refresh attempts.
- Preserve currently valid old keys during server-side rotation.
- Fail closed when a key cannot be resolved.
- Never accept a key supplied by the JWT itself.
A malicious stream of random `kid` values must not cause unbounded calls to Piquel Auth.
### 19.6 Validated principal
The middleware returns a validated application-facing type:
```rust
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub client_id: ClientId,
    pub username: String,
    pub display_name: String,
    pub profile_version: u64,
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub authenticated_at: chrono::DateTime<chrono::Utc>,
}
```
The raw JWT should not be required by ordinary handlers.
When advanced use requires it, access to raw claims should be explicit rather than the default API.
### 19.7 Error model
Internal SDK errors may include:
```rust
pub enum AuthenticationError {
    MissingAuthorizationHeader,
    InvalidAuthorizationHeader,
    UnsupportedAuthorizationScheme,
    MalformedToken,
    InvalidTokenType,
    UnsupportedAlgorithm,
    MissingKeyId,
    UnknownSigningKey,
    InvalidSignature,
    InvalidIssuer,
    InvalidAudience,
    TokenExpired,
    TokenNotYetValid,
    InvalidIssuedAt,
    MissingClaim(&'static str),
    InvalidClaim(&'static str),
    JwksUnavailable,
}
```

HTTP framework adapters should map:
- Missing or invalid authentication to `401 Unauthorized`
- Valid authentication with insufficient product permission to `403 Forbidden`
Detailed cryptographic errors must not be returned to untrusted clients.
### 19.8 Scope handling
Piquel access tokens may later include scopes.
The middleware may optionally enforce required scopes:
```rust
let middleware = AuthMiddleware::builder()
    .issuer(...)
    .audience("product-a-api")
    .required_scope("profile:read")
    .build()
    .await?;
```
Product-specific resource authorization remains outside the authentication middleware.
## 20. Product integration flow
A typical web product integration is:
```text
1. User opens Product A.
2. Product A finds no valid local access token.
3. Product A starts OIDC Authorization Code with PKCE.
4. Browser is redirected to Piquel Auth.
5. User authenticates, or an existing Piquel session is reused.
6. Piquel Auth returns an authorization code.
7. Product A exchanges the code.
8. Product A receives:
   - ID token
   - Product A access JWT
   - Product A refresh token
1. Product A calls Product A API with the access JWT.
2. Product A API validates the JWT locally through AuthMiddleware.
3. Product A API uses `sub` as the global user ID.
4. When the JWT expires, Product A rotates the refresh token.
```
## 21. Login user experience
### 21.1 Available methods
The Piquel login interface offers:
- Sign in with a passkey
- Sign in with approved external providers
### 21.2 Social-first accounts
When a user authenticates socially and has no passkey, the account interface should display a recommendation such as:

> Add a passkey for faster, phishing-resistant access to your Piquel account.

The recommendation is non-blocking.
### 21.3 Terminology
The interface must distinguish:
- **Sign in with GitHub**: use GitHub to authenticate the Piquel account
- **Connect GitHub**: allow one product to call GitHub APIs
These are separate flows and separate credentials.
## 22. Product-owned external OAuth integrations
Each product owns its external API integrations.
For example, Product A may own a GitHub App and store the resulting GitHub user or installation tokens.
Piquel Auth does not become the universal storage system for these tokens.
This provides:
- Independent provider permission boundaries
- Separate provider registrations
- Reduced compromise blast radius
- Product-specific consent
- Product-specific revocation
- Easier use of GitHub Apps and similar provider-native models

The Piquel SDK may simplify implementation but does not take ownership of credentials.
## 23. Data model
Representative tables follow.
### 23.1 Users
```text
users
-----
id
username
display_name
profile_version
status
created_at
updated_at
```
### 23.2 Emails
```text
user_emails
-----------
id
user_id
original_email
normalized_email
is_primary
verified_at
created_at
updated_at
```
Constraint:
```text
UNIQUE (normalized_email)
```
for active verified identities under the chosen account model.
### 23.3 Passkeys
```text
passkey_credentials
-------------------
id
user_id
credential_id
public_key
signature_counter
transports
backup_eligible
backup_state
friendly_name
created_at
last_used_at
revoked_at
```
Constraint:
```text
UNIQUE (credential_id)
```
### 23.4 Federated identities
```text
external_login_identities
-------------------------
id
user_id
issuer
subject
provider_name
linked_email
created_at
last_used_at
revoked_at
```
Constraint:
```text
UNIQUE (issuer, subject)
```
### 23.5 Sessions
```text
sessions
--------
id
user_id
created_at
last_authenticated_at
last_seen_at
expires_at
revoked_at
authentication_methods
client_metadata
```
### 23.6 Refresh-token families
```text
refresh_token_families
----------------------
id
user_id
client_id
session_id
created_at
expires_at
revoked_at
revocation_reason
```
### 23.7 Refresh tokens
```text
refresh_tokens
--------------
id
token_id
secret_digest
family_id
rotated_from_id
created_at
expires_at
consumed_at
last_used_at
revoked_at
```
### 23.8 OIDC clients
```text
oidc_clients
------------
id
client_id
display_name
application_type
enabled
created_at
updated_at
```
Supporting tables may contain redirect URIs, audiences, scopes, and keys.
### 23.9 Service identities
```text
service_identities
------------------
id
service_id
display_name
enabled
created_at
updated_at
```
### 23.10 Service keys
```text
service_public_keys
-------------------
id
service_identity_id
key_id
algorithm
public_key
created_at
expires_at
revoked_at
```
### 23.11 Internal events
```text
internal_events
---------------
event_id
aggregate_type
aggregate_id
aggregate_sequence
event_type
schema_version
payload
created_at
published_at
```

Constraint:
```text
UNIQUE (aggregate_type, aggregate_id, aggregate_sequence)
```
### 23.12 Security audit log
```text
security_audit_log
------------------
event_id
user_id
service_id
session_id
action
outcome
source_ip
user_agent
request_id
occurred_at
metadata
```
## 24. Internal event log
The first iteration does not publish events to a broker.
It records internal domain events so that publication may be introduced later.
Account mutations and their event records should be committed in the same database transaction.

Example event:
```json
{
  "event_id": "evt_0198a37d",
  "aggregate_type": "user",
  "aggregate_id": "0198a346-1e13-7d91-bf85-15d90f7e2885",
  "aggregate_sequence": 12,
  "event_type": "user.display_name.changed",
  "schema_version": 1,
  "payload": {
    "profile_version": 12
  },
  "created_at": "2026-07-11T14:32:00Z"
}
```

The initial event log must:
- Be append-only
- Use unique event IDs
- Use per-aggregate sequence numbers
- Version payload schemas
- Avoid storing tokens or secrets
- Avoid unnecessary personal data
- Support a future publisher cursor
- Support future at-least-once delivery
Reliable broadcasting and deletion coordination remain out of scope.
## 25. Redis usage
Redis is disposable infrastructure.
Redis should be kept in mind when designing the architecture but does not need to be implemented in this first prototype.
Appropriate uses include:
- Rate limiting
- WebAuthn ceremony state
- OAuth state and nonce state
- Short-lived PKCE transaction state
- Replay protection
- Distributed locks where strictly necessary
- JWKS or metadata caching
- Service-token refresh coordination
- Temporary session-status caching

Redis must not be the only storage location for:
- Users
- Passkeys
- Refresh-token records
- OIDC clients
- Service identities
- Revocations
- Audit logs
- Internal events
- Signing-key metadata

The system must preserve account integrity if Redis is flushed.
## 26. Cryptographic key management
Piquel Auth uses asymmetric signing keys for access tokens, ID tokens, purpose tokens, and internal service tokens.
Requirements:
- Private signing keys are not stored unencrypted in PostgreSQL.
- Private keys are not included directly in application configuration.
- A KMS or HSM-backed design is preferred.
- Public keys are exposed through JWKS where appropriate.
- Keys have stable `kid` identifiers.
- Key rotation supports an overlap period.
- Old public keys remain available until all issued tokens have expired.
- New tokens use only the active signing key.
- Key-use permissions are restricted to Piquel Auth.
- Development and production keys are separate.

No token verifier may accept an algorithm selected solely from an untrusted token header.
## 27. Security requirements
### 27.1 Transport
- TLS is required for every public and internal connection.
- Internal traffic must not rely on network location alone.
- Cookies containing security state must use `Secure`.
- Session cookies must use `HttpOnly`.
- SameSite policy must be explicitly selected per flow.
### 27.2 OAuth and OIDC
- Redirect URIs use exact matching.
- PKCE is mandatory.
- State is mandatory for browser authorization flows.
- Nonces are validated when ID tokens are issued to relevant clients.
- Authorization codes are single-use.
- Authorization codes have a very short lifetime.
- Authorization codes are bound to the client and redirect URI.
- Token endpoint errors do not expose sensitive details.
### 27.3 WebAuthn
- Challenges are cryptographically random.
- Challenges are single-use.
- Challenges have short expiration.
- Expected origin is validated.
- Expected relying-party ID is validated.
- User verification requirements are explicitly configured.
- Credential IDs are unique.
### 27.4 Tokens
- Access tokens last approximately five minutes.
- Refresh tokens rotate on every use.
- Refresh-token replay revokes the family.
- Tokens are never logged.
- Authorization headers are removed from error telemetry.
- Token-bearing URLs are not supported.
- JWT verification fails closed.
- Audience validation is mandatory.
### 27.5 Logging
Logs must not contain:
- Access tokens
- Refresh tokens
- Authorization codes
- OAuth state secrets
- PKCE verifiers
- WebAuthn challenges
- Social-provider access tokens
- Private keys
- Session cookies

Structured logs should contain:
- Request ID
- Service identity
- Client ID
- User ID when appropriate
- Operation
- Result category
- Latency
- Sanitized error code
### 27.6 Database
- Connections require TLS where supported.
- Authentication uses dedicated credentials.
- Application privileges follow least privilege.
- Sensitive columns use application-layer encryption where appropriate.
- Migrations are reviewed as security-sensitive changes.
## 28. Deployment model
Piquel Auth runs as multiple interchangeable replicas.
Each replica may handle:
- Public OIDC requests
- Passkey requests
- Social callbacks
- Token issuance
- Internal RPC requests
- Internal event-log writes
Replicas do not store authoritative state locally.
### 28.1 Required infrastructure
```text
Piquel Auth replicas
PostgreSQL
Load balancer or ingress
KMS or equivalent key protection
```
A message broker is not required in the first iteration.
### 28.2 Replica behavior
Replicas must:
- Use shared PostgreSQL state
- Use shared signing-key configuration
- Be safe under concurrent refresh requests
- Be safe under concurrent social-login callbacks
- Avoid process-local session authority
- Support graceful shutdown
- Stop accepting new requests before termination
- Complete or cancel in-flight transactions safely
### 28.3 Health endpoints
Recommended endpoints:
```text
GET /health/live
GET /health/ready
```
Liveness indicates that the process is running.
Readiness indicates that the replica can safely serve traffic, including required database and key-management dependencies.
## 29. Availability behavior
### 29.1 Piquel Auth unavailable
Existing five-minute access tokens continue to work until expiry because products validate them locally.
During an outage:
- Existing API requests with valid tokens continue.
- New logins fail.
- Token refresh fails.
- New service tokens may fail after cached service tokens expire.
- Account-management operations fail.
- Internal RPC calls fail.
The SDK must use deadlines and must not retry indefinitely.
### 29.3 PostgreSQL unavailable
Piquel Auth becomes unready for operations requiring authoritative state.
Downstream services may continue accepting already issued access JWTs until expiry.
## 30. Observability
Metrics should include:
- Login attempts by method
- Login successes and failures
- Passkey registration outcomes
- Social-provider callback failures
- Authorization-code exchanges
- Refresh success rate
- Refresh-token replay detections
- Token issuance latency
- RPC request latency
- RPC authorization failures
- JWKS refresh failures
- Active sessions
- Service-token issuance failures
- Database transaction failures
- Redis failures
- Rate-limit actions
No metric labels may contain raw tokens, email addresses, or unbounded user identifiers.
Tracing must redact authorization metadata.
## 31. Accepted first-iteration risks
The following risks are knowingly accepted:
### 31.1 Social-provider trust
A supported social provider is trusted as an authentication method equivalent to Piquel’s own login for first-iteration account access.
Compromise of that provider account may therefore compromise the Piquel account.
### 31.2 Automatic email linking
A newly observed provider identity may be linked automatically to an existing Piquel account based on a provider-verified matching email.
This creates account-linking risk if a provider’s email assurance is weaker than expected.
Mitigations retained in the first iteration are:
- Explicit provider allowlist
- Verified-email requirement
- Permanent issuer-and-subject mapping after linking
- Conservative email normalization
- Security audit entry
- User notification
### 31.3 Social recovery of passkeys
A fresh social login may manage passkeys.
This weakens the security boundary of passkey recovery.
The data model and purpose-token flow should allow this policy to be tightened later.
### 31.4 Access-token revocation delay
A revoked session’s existing access token may remain usable for up to approximately five minutes.
This is accepted to avoid an authentication-service call on every request.
### 31.5 No event broadcasting
Products do not receive reliable real-time profile, deletion, or account-status events in the first iteration.
Products must treat access-token profile fields as short-lived snapshots.
## 32. Future extensions
The architecture should support later addition of:
- Durable event publication
- Consumer subscriptions
- Account-deletion orchestration
- User-event acknowledgements
- Stricter social-account linking
- Passkey-required high-assurance operations
- Explicit authentication assurance levels
- Suspicious-login detection
- Device-bound sessions
- Sender-constrained refresh tokens
- Product-specific consent screens
- Administrative organization accounts
- External provider connector framework
- User-facing session and device management
- Pairwise subject identifiers for third-party clients
- Selective token introspection for exceptional operations
- Redis caching
## 33. Initial implementation sequence
### Phase 1: Core identity
Implement:
- User model
- Email model
- Passkey registration
- Passkey login
- Central session
- Basic account interface
### Phase 2: OIDC and tokens
Implement:
- Discovery
- Authorization Code with PKCE
- Client registration
- ID tokens
- Audience-specific access JWTs
- Opaque rotating refresh tokens
- JWKS
- Revocation
### Phase 3: SDK and first product
Implement:
- Rust core SDK
- `AuthMiddleware` builder
- Axum integration
- Token refresh client
- First product integration
- JWKS rotation tests
### Phase 4: Social login
Implement:
- First approved provider
- Verified-email extraction
- Automatic email matching
- Issuer-and-subject linking
- Passkey recommendation
- Social recovery
### Phase 5: Internal RPC
Implement:
- Service identities
- Signed service assertions
- Service-token manager
- gRPC server
- Generated Rust client
- User and session methods
### Phase 6: Hardening
Implement:
- Rate limiting
- Audit log
- Internal event log
- Key rotation
- Refresh-token replay response
- Backup and restore testing
- Security testing
- Incident-response procedures
## 34. Final architecture summary
Piquel Auth provides one global identity across multiple independent products.
The core model is:
```text
One global Piquel user ID
One central authentication authority
One replicated stateless auth process
One central single-sign-on session

Per product:
    One or more OIDC clients
    One API audience
    Separate access tokens
    Separate refresh-token families
    Separate application data
    Separate authorization rules
```
Ordinary product requests use five-minute audience-specific JWTs validated locally through the Piquel SDK.
Refresh tokens are opaque, rotating, product-specific, revocable, and stored only by the appropriate client environment.
Sensitive operations require fresh authentication and receive purpose-bound authorization rather than relying directly on a refresh token.
The private API uses authenticated gRPC. Each downstream backend has a distinct service identity and obtains short-lived service tokens through SDK-managed asymmetric authentication.
The SDK’s `AuthMiddleware` builder makes secure token verification the default by requiring an issuer, audience, trusted JWKS source, approved algorithm, time validation, and required claims.
Passkeys and approved social providers are both supported login methods. Provider-verified matching emails are automatically associated with existing accounts in the first iteration. Social login may recover and manage passkeys, with the associated risk explicitly documented.
The event system begins as an internal transactional event log. Reliable broadcasting and deletion workflows are deferred without preventing their later implementation.
