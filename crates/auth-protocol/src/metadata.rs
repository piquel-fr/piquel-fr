//! Authorization server metadata (RFC 8414), which also carries the `OpenID` Provider
//! fields (OIDC Discovery 1.0 §3). RFC 8414 §2 allows OIDC fields in OAuth metadata,
//! so one document serves both well-known paths.

use crate::{
    claims::Acr,
    jwt::{Algorithm, Claim},
    oauth::{
        ClientAuthMethod, CodeChallengeMethod, GrantType, ResponseMode, ResponseType, Scope,
        SubjectType,
    },
};
use serde::{Deserialize, Serialize};
use url::Url;

/// Path of the RFC 8414 document. The issuer is an origin, so no path is inserted.
pub const OAUTH_AUTHORIZATION_SERVER_PATH: &str = "/.well-known/oauth-authorization-server";
/// Path of the OIDC Discovery document.
pub const OPENID_CONFIGURATION_PATH: &str = "/.well-known/openid-configuration";

/// The metadata Piquel auth publishes. Every field it sends is required, so a client
/// parsing it learns of a missing capability at once. Later capabilities add fields
/// here, optional ones skipped when `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "RFC 8414 and OIDC Discovery define these capability flags as JSON booleans"
)]
pub struct ServerMetadata {
    /// Issuer, matching the `iss` claim. A string because it is an origin without the
    /// trailing slash a [`Url`] would add.
    pub issuer: String,
    /// Where clients send authorization requests.
    pub authorization_endpoint: Url,
    /// Where clients redeem codes and refresh tokens.
    pub token_endpoint: Url,
    /// Where clients revoke refresh tokens (RFC 7009).
    pub revocation_endpoint: Url,
    /// Where clients read claims with an access token.
    pub userinfo_endpoint: Url,
    /// Where clients send RP-initiated logout.
    pub end_session_endpoint: Url,
    /// Where clients fetch the public signing keys.
    pub jwks_uri: Url,
    /// Human-readable documentation for client developers.
    pub service_documentation: Url,
    /// Standard scopes clients may request.
    pub scopes_supported: Vec<Scope>,
    /// Accepted `response_type` values.
    pub response_types_supported: Vec<ResponseType>,
    /// Accepted `response_mode` values.
    pub response_modes_supported: Vec<ResponseMode>,
    /// Accepted `grant_type` values.
    pub grant_types_supported: Vec<GrantType>,
    /// Client authentication methods at the token endpoint.
    pub token_endpoint_auth_methods_supported: Vec<ClientAuthMethod>,
    /// Client authentication methods at the revocation endpoint.
    pub revocation_endpoint_auth_methods_supported: Vec<ClientAuthMethod>,
    /// Accepted PKCE methods.
    pub code_challenge_methods_supported: Vec<CodeChallengeMethod>,
    /// Subject identifier types.
    pub subject_types_supported: Vec<SubjectType>,
    /// ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<Algorithm>,
    /// Claims tokens may contain.
    pub claims_supported: Vec<Claim>,
    /// Authentication context classes `acr_values` may request and `acr` reports.
    pub acr_values_supported: Vec<Acr>,
    /// Whether the `claims` request parameter is honoured.
    pub claims_parameter_supported: bool,
    /// Whether the `request` parameter is accepted.
    pub request_parameter_supported: bool,
    /// Whether the `request_uri` parameter is accepted.
    pub request_uri_parameter_supported: bool,
    /// Whether authorization responses carry `iss` (RFC 9207).
    pub authorization_response_iss_parameter_supported: bool,
}
