// Generated from piquel_common::protocol by `just sdk-types`. Do not edit.
// The wire types auth and every SDK share; docs/architecture/sdk.md describes them.

/**
 * Claims of an access token (RFC 9068), signed with `typ: at+jwt`. `X` holds
 * application claims; auth issues none, so it uses `()`.
 */
export type AccessTokenClaims = {
/**
 * Issuer, exactly as in discovery.
 */
iss: string,
/**
 * The user's account ID, or the client ID when no user is involved.
 */
sub: string,
/**
 * The resource the token is for.
 */
aud: Audience,
/**
 * Client that requested the token.
 */
client_id: string,
/**
 * Unique token ID.
 */
jti: string,
/**
 * Granted scopes.
 */
scope: string,
/**
 * Issue time.
 */
iat: number,
/**
 * Expiry time.
 */
exp: number,
/**
 * Time before which the token must not be accepted.
 */
nbf?: number,
/**
 * Delegation chain, for exchanged tokens.
 */
act?: Actor,
/**
 * Proof-of-possession binding, for sender-constrained tokens.
 */
cnf?: Confirmation,
/**
 * Browser session that authorized the grant.
 */
sid?: string,
/**
 * When the session signed in.
 */
auth_time?: number,
/**
 * How the session signed in. Values this version does not know are dropped.
 */
amr?: Array<Amr>,
/**
 * Authentication context class the session reached. A class this version does
 * not know reads as none, so it meets no requirement.
 */
acr?: Acr,
/**
 * Username, with the profile scope.
 */
preferred_username?: string,
/**
 * Display name, with the profile scope.
 */
name?: string,
/**
 * Bumped when profile claims change, so clients can tell cached data is stale.
 */
profile_version?: number,
/**
 * Primary email, with the email scope.
 */
email?: string,
/**
 * Always true when present: only verified emails are released.
 */
email_verified?: boolean, };

/**
 * Claims of an ID token (OIDC Core §2), signed with `typ: JWT`.
 */
export type IdTokenClaims = {
/**
 * Issuer, exactly as in discovery.
 */
iss: string,
/**
 * The user's account ID.
 */
sub: string,
/**
 * The client the token is for.
 */
aud: Audience,
/**
 * The client the token was issued to, when `aud` names several.
 */
azp?: string,
/**
 * Issue time.
 */
iat: number,
/**
 * Expiry time.
 */
exp: number,
/**
 * Time before which the token must not be accepted.
 */
nbf?: number,
/**
 * The client's nonce from the authorization request.
 */
nonce?: string,
/**
 * Browser session that authorized the grant.
 */
sid?: string,
/**
 * When the session signed in.
 */
auth_time?: number,
/**
 * How the session signed in. Values this version does not know are dropped.
 */
amr?: Array<Amr>,
/**
 * Authentication context class the session reached. A class this version does
 * not know reads as none, so it meets no requirement.
 */
acr?: Acr,
/**
 * Username, with the profile scope.
 */
preferred_username?: string,
/**
 * Display name, with the profile scope.
 */
name?: string,
/**
 * Bumped when profile claims change, so clients can tell cached data is stale.
 */
profile_version?: number,
/**
 * Primary email, with the email scope.
 */
email?: string,
/**
 * Always true when present: only verified emails are released.
 */
email_verified?: boolean, };

/**
 * Claims of a back-channel logout token (OIDC Back-Channel Logout 1.0 §2.4), signed
 * with `typ: logout+jwt` and posted to a client's back-channel logout URI. It ends
 * one session (`sid`), or with `sub` alone every session of that user at the client.
 * Auth always sends `sub`, and sends `sid` for a session logout.
 */
export type LogoutTokenClaims = {
/**
 * Issuer, exactly as in discovery.
 */
iss: string,
/**
 * The client being told.
 */
aud: Audience,
/**
 * When this attempt to deliver the token was made.
 */
iat: number,
/**
 * Expiry time.
 */
exp: number,
/**
 * The delivery's ID, the same on every attempt, so receivers can drop repeats.
 */
jti: string,
/**
 * The user whose sessions end.
 */
sub?: string,
/**
 * The auth session that ended, as the ID token's `sid` named it.
 */
sid?: string,
/**
 * Marks the token as a back-channel logout.
 */
events: LogoutEvents,
/**
 * Never present.
 */
nonce?: never, };

export type LogoutEvents = { "http://schemas.openid.net/event/backchannel-logout": Record<string, unknown> };

/**
 * The `UserInfo` response (OIDC Core §5.3.2).
 */
export type UserInfo = {
/**
 * The user's account ID.
 */
sub: string,
/**
 * Username, with the profile scope.
 */
preferred_username?: string,
/**
 * Display name, with the profile scope.
 */
name?: string,
/**
 * Bumped when profile claims change, so clients can tell cached data is stale.
 */
profile_version?: number,
/**
 * Primary email, with the email scope.
 */
email?: string,
/**
 * Always true when present: only verified emails are released.
 */
email_verified?: boolean, };

/**
 * How and when the browser session behind a token authenticated. Shared by access
 * and ID tokens, and what step-up checks read.
 */
export type AuthenticationClaims = {
/**
 * Browser session that authorized the grant.
 */
sid?: string,
/**
 * When the session signed in.
 */
auth_time?: number,
/**
 * How the session signed in. Values this version does not know are dropped.
 */
amr?: Array<Amr>,
/**
 * Authentication context class the session reached. A class this version does
 * not know reads as none, so it meets no requirement.
 */
acr?: Acr, };

/**
 * Profile and email claims, present only when the matching scope was granted.
 */
export type ProfileClaims = {
/**
 * Username, with the profile scope.
 */
preferred_username?: string,
/**
 * Display name, with the profile scope.
 */
name?: string,
/**
 * Bumped when profile claims change, so clients can tell cached data is stale.
 */
profile_version?: number,
/**
 * Primary email, with the email scope.
 */
email?: string,
/**
 * Always true when present: only verified emails are released.
 */
email_verified?: boolean, };

/**
 * `aud`: one string or an array (RFC 7519 §4.1.3). Auth always sends one string.
 */
export type Audience = string | Array<string>;

/**
 * `act` (RFC 8693 §4.1): who is acting for the subject. Nested for delegation chains,
 * the outermost actor being the most recent.
 */
export type Actor = {
/**
 * The acting party.
 */
sub: string,
/**
 * The actor before this one, if the token was exchanged more than once.
 */
act?: Actor, };

/**
 * `cnf` (RFC 7800): the key a sender-constrained token is bound to.
 */
export type Confirmation = {
/**
 * SHA-256 JWK thumbprint of the `DPoP` key (RFC 9449 §6.1).
 */
jkt?: string, };

export type Amr = "pop" | "mfa" | "user" | "fed";

export type Acr = "phr" | "urn:piquel:acr:social";

/**
 * The metadata Piquel auth publishes. Every field it sends is required, except the
 * PKCE methods, so a client parsing it learns of a missing capability at once. Lists
 * keep only the values this version knows, so a newer auth advertising more does not
 * break older clients. Later capabilities add fields
 * here, optional ones skipped when `None`.
 */
export type ServerMetadata = {
/**
 * Issuer, matching the `iss` claim. A string because it is an origin without the
 * trailing slash a `Url` would add.
 */
issuer: string,
/**
 * Where clients send authorization requests.
 */
authorization_endpoint: string,
/**
 * Where clients redeem codes and refresh tokens.
 */
token_endpoint: string,
/**
 * Where clients revoke refresh tokens (RFC 7009).
 */
revocation_endpoint: string,
/**
 * Where clients read claims with an access token.
 */
userinfo_endpoint: string,
/**
 * Where clients push authorization requests (RFC 9126 §5). Absent from issuers
 * that predate pushed authorization requests.
 */
pushed_authorization_request_endpoint?: string,
/**
 * Whether every client must push its authorization requests (RFC 9126 §5).
 * Individual clients may still be required to.
 */
require_pushed_authorization_requests: boolean,
/**
 * Where clients send RP-initiated logout.
 */
end_session_endpoint: string,
/**
 * Where clients fetch the public signing keys.
 */
jwks_uri: string,
/**
 * Human-readable documentation for client developers.
 */
service_documentation: string,
/**
 * Standard scopes clients may request.
 */
scopes_supported: Array<Scope>,
/**
 * Accepted `response_type` values.
 */
response_types_supported: Array<ResponseType>,
/**
 * Accepted `response_mode` values.
 */
response_modes_supported: Array<ResponseMode>,
/**
 * Accepted `grant_type` values.
 */
grant_types_supported: Array<GrantType>,
/**
 * Client authentication methods at the token endpoint.
 */
token_endpoint_auth_methods_supported: Array<ClientAuthMethod>,
/**
 * Client authentication methods at the revocation endpoint.
 */
revocation_endpoint_auth_methods_supported: Array<ClientAuthMethod>,
/**
 * Accepted PKCE methods. Defaults to empty when absent, which RFC 8414 §2 says
 * means no PKCE support, so clients can refuse the issuer with a precise reason.
 */
code_challenge_methods_supported: Array<CodeChallengeMethod>,
/**
 * Subject identifier types.
 */
subject_types_supported: Array<SubjectType>,
/**
 * ID token signing algorithms.
 */
id_token_signing_alg_values_supported: Array<Algorithm>,
/**
 * Claims tokens may contain.
 */
claims_supported: Array<Claim>,
/**
 * Authentication context classes `acr_values` may request and `acr` reports.
 */
acr_values_supported: Array<Acr>,
/**
 * Whether the `claims` request parameter is honoured.
 */
claims_parameter_supported: boolean,
/**
 * Whether the `request` parameter is accepted.
 */
request_parameter_supported: boolean,
/**
 * Whether client-hosted request objects (`request_uri`, RFC 9101) are
 * accepted. Pushed `request_uri` values are advertised by
 * `Self::pushed_authorization_request_endpoint` instead.
 */
request_uri_parameter_supported: boolean,
/**
 * Whether authorization responses carry `iss` (RFC 9207).
 */
authorization_response_iss_parameter_supported: boolean,
/**
 * Whether clients may register a back-channel logout URI (OIDC Back-Channel
 * Logout 1.0 §2.1). False when absent.
 */
backchannel_logout_supported: boolean,
/**
 * Whether logout tokens name the ended session with `sid`. False when absent.
 */
backchannel_logout_session_supported: boolean, };

/**
 * What a protected operation needs from the user's authentication: an `acr` to
 * meet, a maximum age of `auth_time`, or both. The default needs nothing.
 *
 * It serializes as the parameters that ask for it, `acr_values` and `max_age`, as in
 * a step-up challenge (RFC 9470 §3).
 */
export type StepUpRequirement = {
/**
 * The class the authentication must meet (`Acr::satisfies`).
 */
acr_values?: Acr,
/**
 * The longest time since `auth_time`, in seconds.
 */
max_age?: number, };

export type TokenType = "at+jwt" | "JWT" | "logout+jwt";

export type Claim = "iss" | "sub" | "aud" | "iat" | "exp" | "nbf" | "sid" | "auth_time" | "amr" | "acr" | "act" | "cnf" | "azp" | "name" | "preferred_username" | "email" | "email_verified" | "profile_version" | "client_id" | "jti" | "scope" | "nonce";

export type Algorithm = "RS256";

/**
 * A JSON Web Key Set (RFC 7517 §5). Auth publishes `JwkSet<Jwk>`. Verifiers read the
 * keys as raw JSON and parse each one alone, because RFC 7517 §5 says a key of an
 * unknown `kty` is skipped rather than failing the whole set.
 */
export type JwkSet = {
/**
 * Published keys.
 */
keys: Array<Jwk>, };

/**
 * One public RSA signing key. Fields are in sorted order, so auth's JWKS keeps the
 * byte layout it had when it was built with `json!`.
 */
export type Jwk = {
/**
 * Algorithm the key signs with. Auth always sends it; other issuers may not.
 */
alg?: Algorithm,
/**
 * Base64url RSA public exponent.
 */
e: string,
/**
 * Key identifier, matching the token header's `kid`.
 */
kid: string,
/**
 * Key family; any value but `RSA` fails parsing.
 */
kty: KeyType,
/**
 * Base64url RSA modulus.
 */
n: string,
/**
 * Key purpose. Auth always sends it; other issuers may not.
 */
use?: KeyUse, };

export type KeyType = "RSA";

export type KeyUse = "sig";

export type GrantType = "authorization_code" | "refresh_token";

export type ResponseType = "code";

export type ResponseMode = "query";

export type ClientAuthMethod = "none" | "client_secret_basic";

export type SubjectType = "public";

export type CodeChallengeMethod = "S256";

export type Prompt = "none" | "login" | "consent" | "select_account";

export type Scope = "openid" | "profile" | "email" | "offline_access";

export type ErrorCode = "invalid_request" | "invalid_client" | "invalid_grant" | "invalid_scope" | "invalid_target" | "invalid_token" | "unsupported_grant_type" | "login_required" | "consent_required" | "unmet_authentication_requirements" | "request_not_supported" | "invalid_request_uri" | "access_denied" | "server_error" | (string & Record<never, never>);

/**
 * JSON error body of auth's OAuth endpoints (RFC 6749 §5.2).
 */
export type ErrorResponse = {
/**
 * What went wrong.
 */
error: ErrorCode,
/**
 * What the client should fix.
 */
error_description?: string, };

/**
 * One `Bearer` challenge. Without `error` it means no token was sent (RFC 6750 §3.1).
 */
export type BearerChallenge = {
/**
 * What went wrong; `None` when the request carried no token.
 */
error?: BearerError,
/**
 * Human-readable detail.
 */
error_description?: string,
/**
 * Every scope the request needs.
 */
scope?: string,
/**
 * Where the resource's protected resource metadata is served (RFC 9728 §5.1).
 */
resource_metadata?: string,
/**
 * The class the authentication must meet (`Acr::satisfies`).
 */
acr_values?: Acr,
/**
 * The longest time since `auth_time`, in seconds.
 */
max_age?: number, };

export type BearerError = "invalid_request" | "invalid_token" | "insufficient_scope" | "insufficient_user_authentication" | (string & Record<never, never>);

/**
 * The shared code of an SDK error: a category, and for most categories the check
 * that failed. It serializes as the vectors' expected errors do.
 */
export type SdkError = {
/**
 * What kind of operation failed.
 */
code: ErrorCategory,
/**
 * Which check failed, when the category has several.
 */
reason?: ErrorReason, };

export type ErrorCategory = "discovery" | "keys" | "invalid_token" | "insufficient_scope" | "insufficient_user_authentication" | "callback" | "oauth" | "network";

export type ErrorReason = "issuer_mismatch" | "invalid_document" | "pkce_unsupported" | "duplicate_key_id" | "malformed" | "unsupported_critical_header" | "wrong_type" | "unsupported_algorithm" | "unknown_key" | "bad_signature" | "wrong_audience" | "expired" | "not_yet_valid" | "issued_in_future" | "lifetime_too_long" | "invalid_claims" | "nonce_mismatch" | "wrong_authorized_party" | "authentication_too_old" | "state_mismatch" | "missing_issuer" | "missing_code";
