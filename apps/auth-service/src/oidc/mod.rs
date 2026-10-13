//! Authorization Code + PKCE, signed tokens, and rotating opaque refresh tokens.

/// Authorization, login continuation and consent.
mod authorize;
/// Protocol errors and their HTTP responses.
mod error;
/// RP-initiated logout and confirmation.
mod logout;
/// Code exchanges, refresh rotation and identity claims.
mod token;

use crate::config::OidcConfig;
use crate::routes;
use crate::security::CSRF_HEADER;
use error::{OAuthCode, OAuthError};
use piquel_crypto::{
    Digest, Rs256Key, Secret,
    jwt::{Algorithm, Claim, TokenType},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    routing::{get, post},
};
use base64::Engine;
use piquel_auth_protocol::{
    TokenId,
    oauth::{CodeChallengeMethod, GrantType, Prompt, ResponseType, Scope},
};
use piquel_repository::{Database, StoredOidcClient};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};

/// Value the auth frontend sends in the CSRF header.
const CSRF_HEADER_VALUE: &str = "1";
/// Fetch metadata header naming the request's site relationship.
const FETCH_SITE_HEADER: &str = "sec-fetch-site";
/// `Sec-Fetch-Site` value proving the request came from the issuer's own pages.
const FETCH_SITE_SAME_ORIGIN: &str = "same-origin";
/// Lifetime of signed access tokens; kept short because they cannot be revoked.
const ACCESS_TOKEN_SECONDS: i64 = 300;
/// Maximum byte length of `state` and `nonce`.
const MAX_STATE_BYTES: usize = 512;
/// Maximum length of the base64 part of an HTTP Basic header.
const MAX_BASIC_CREDENTIAL_BYTES: usize = 1024;
/// Maximum length of an opaque token, checked before parsing it.
const MAX_OPAQUE_TOKEN_BYTES: usize = 160;
/// Maximum number of distinct scopes in a request.
const MAX_SCOPES: usize = 16;
/// How long a pending authorization waits for login and consent.
const AUTHORIZATION_REQUEST_MINUTES: i64 = 10;
/// How long an authorization code stays redeemable.
const AUTHORIZATION_CODE_MINUTES: i64 = 2;
/// Subject identifier type: every client sees the same account ID.
const SUBJECT_TYPE: &str = "public";

/// The OAuth 2.0 and `OpenID` Connect provider.
#[derive(Clone)]
pub struct OidcApplication {
    /// Shared database pool.
    database: Database,
    /// HTTPS issuer origin, without a trailing slash.
    issuer: String,
    /// HMAC key under which opaque token secrets are stored.
    refresh_key: Arc<Secret>,
    /// Persistent key that signs and verifies tokens.
    keys: Arc<Rs256Key>,
}

piquel_common::str_enum! {
    /// HTTP authentication schemes accepted by the protocol endpoints.
    enum AuthScheme {
        /// Client ID and secret, used by confidential clients at the token endpoint.
        Basic = "Basic",
        /// An access token, used at `UserInfo`.
        Bearer = "Bearer",
    }
}

impl AuthScheme {
    /// Returns the credentials of an `Authorization` value using this scheme.
    /// Scheme names are case-insensitive (RFC 9110); credentials are untouched.
    fn credentials(self, value: &str) -> Option<&str> {
        let (scheme, credentials) = value.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case(self.as_str())
            .then_some(credentials)
    }
}

piquel_common::str_enum! {
    /// Opaque token prefixes; each binds a token to one purpose so it cannot be used for another.
    enum TokenPrefix {
        /// Pending login and consent transaction.
        AuthorizationRequest = "par_v1",
        /// One-use authorization code.
        AuthorizationCode = "pac_v1",
        /// Rotating refresh token.
        RefreshToken = "prt_v1",
    }
}

impl TokenPrefix {
    /// Request parameter carrying this kind of token, named in error descriptions.
    const fn parameter(self) -> &'static str {
        match self {
            Self::AuthorizationRequest => "transaction",
            Self::AuthorizationCode => "code",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// An opaque token, encoded as `<prefix>_<id>.<secret>`. Only the secret's HMAC is stored.
struct OpaqueToken {
    /// Database record the token points to.
    id: TokenId,
    /// Random secret proving possession of the token.
    secret: Secret,
    /// Purpose of the token.
    prefix: TokenPrefix,
}

impl OpaqueToken {
    /// Creates a token with a fresh ID and random secret.
    fn new(prefix: TokenPrefix) -> Result<Self, OAuthError> {
        Ok(Self {
            id: TokenId::new(),
            secret: Secret::generate()?,
            prefix,
        })
    }

    /// Parses a token sent by a client, rejecting it as `invalid_grant` if malformed
    /// or meant for another purpose.
    fn parse(prefix: TokenPrefix, value: &str) -> Result<Self, OAuthError> {
        let malformed = || format!("{} is malformed", prefix.parameter());
        if value.len() > MAX_OPAQUE_TOKEN_BYTES {
            return Err(OAuthCode::InvalidGrant.reject(format!(
                "{} must be at most {MAX_OPAQUE_TOKEN_BYTES} bytes",
                prefix.parameter()
            )));
        }
        let (id, secret) = value
            .strip_prefix(prefix.as_str())
            .and_then(|rest| rest.strip_prefix('_'))
            .and_then(|rest| rest.split_once('.'))
            .ok_or_else(|| OAuthCode::InvalidGrant.reject(malformed()))?;
        Ok(Self {
            id: id
                .parse()
                .map_err(|error| OAuthCode::InvalidGrant.reject_with(malformed(), error))?,
            secret: Secret::parse(secret)
                .map_err(|error| OAuthCode::InvalidGrant.reject_with(malformed(), error))?,
            prefix,
        })
    }

    /// Encodes the token for the client.
    fn encoded(&self) -> String {
        format!("{}_{}.{}", self.prefix, self.id, self.secret.encoded())
    }
}

/// A deduplicated scope set, sorted so its wire form is stable. Holds plain strings
/// because clients may be granted registered extension scopes besides [`Scope`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Scopes(BTreeSet<String>);

impl Scopes {
    /// Parses a space-separated scope list, which must be non-empty and bounded.
    fn parse(value: &str) -> Result<Self, OAuthError> {
        let scopes: BTreeSet<_> = value.split_ascii_whitespace().map(str::to_owned).collect();
        if scopes.is_empty() {
            return Err(OAuthCode::InvalidScope.reject("scope is required"));
        }
        if scopes.len() > MAX_SCOPES {
            return Err(OAuthCode::InvalidScope
                .reject(format!("scope may list at most {MAX_SCOPES} values")));
        }
        Ok(Self(scopes))
    }

    /// Rebuilds a scope set read from the database.
    fn from_stored(scopes: &[String]) -> Self {
        Self(scopes.iter().cloned().collect())
    }

    /// Whether every scope is in `allowed`.
    fn allowed_by(&self, allowed: &[String]) -> bool {
        self.0.iter().all(|scope| allowed.contains(scope))
    }

    /// Whether the set contains a standard scope.
    fn contains(&self, scope: Scope) -> bool {
        self.0.contains(scope.as_str())
    }

    /// Converts to the list stored in the database.
    fn into_stored(self) -> Vec<String> {
        self.0.into_iter().collect()
    }

    /// Space-separated form used in responses and the access token's `scope` claim.
    fn wire(&self) -> String {
        self.0
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

piquel_common::str_enum! {
    /// Supported authorization response modes.
    enum ResponseMode {
        /// Code and state go in the redirect's query string.
        Query = "query",
    }
}

piquel_common::str_enum! {
    /// Token endpoint client authentication methods, listed in discovery.
    enum ClientAuthentication {
        /// Public client, identified by its ID alone.
        None = "none",
        /// Confidential client, authenticated by HTTP Basic.
        Basic = "client_secret_basic",
    }
}

/// Claims listed in discovery, in their published order.
const SUPPORTED_CLAIMS: [Claim; 9] = [
    Claim::Subject,
    Claim::Name,
    Claim::Username,
    Claim::Email,
    Claim::EmailVerified,
    Claim::ProfileVersion,
    Claim::AuthTime,
    Claim::Methods,
    Claim::Session,
];

/// `OpenID` Provider metadata. Supported value lists come from the same enums the
/// endpoints validate against. Fields are sorted, matching the earlier `json!` output.
#[derive(Serialize)]
struct Discovery {
    /// Where clients send authorization requests.
    authorization_endpoint: String,
    /// Claims tokens may contain.
    claims_supported: &'static [Claim],
    /// Accepted PKCE methods.
    code_challenge_methods_supported: &'static [CodeChallengeMethod],
    /// Where clients send RP-initiated logout.
    end_session_endpoint: String,
    /// Accepted `grant_type` values.
    grant_types_supported: &'static [GrantType],
    /// ID token signing algorithms.
    id_token_signing_alg_values_supported: &'static [Algorithm],
    /// Issuer, matching the `iss` claim.
    issuer: String,
    /// Where clients fetch the public signing keys.
    jwks_uri: String,
    /// Always false: `request` is rejected.
    request_parameter_supported: bool,
    /// Always false: `request_uri` is rejected.
    request_uri_parameter_supported: bool,
    /// Accepted `response_mode` values.
    response_modes_supported: &'static [ResponseMode],
    /// Accepted `response_type` values.
    response_types_supported: &'static [ResponseType],
    /// Where clients revoke refresh tokens.
    revocation_endpoint: String,
    /// Standard scopes clients may request.
    scopes_supported: &'static [Scope],
    /// Subject identifier types.
    subject_types_supported: &'static [&'static str],
    /// Where clients redeem codes and refresh tokens.
    token_endpoint: String,
    /// Accepted client authentication methods.
    token_endpoint_auth_methods_supported: &'static [ClientAuthentication],
    /// Where clients read claims with an access token.
    userinfo_endpoint: String,
}

#[cfg(test)]
mod tests;

/// Lets the shared browser-session extractors reach the database.
impl axum::extract::FromRef<OidcApplication> for Database {
    /// Clones the application's database handle.
    fn from_ref(application: &OidcApplication) -> Self {
        application.database.clone()
    }
}

impl OidcApplication {
    /// Builds the provider from its validated configuration.
    pub(crate) fn new(database: Database, config: &OidcConfig) -> Self {
        Self {
            database,
            issuer: config.origin.serialized(),
            refresh_key: config.refresh_key.clone(),
            keys: config.keys.clone(),
        }
    }

    /// Every discovery, OAuth and OIDC route, with `self` as their state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::oidc::DISCOVERY, get(Self::discovery))
            .route(routes::oidc::JWKS, get(Self::jwks))
            .route(
                routes::oidc::AUTHORIZE,
                get(Self::authorize).post(Self::authorize),
            )
            .route(routes::oidc::AUTHORIZE_RESUME, get(Self::resume))
            .route(
                routes::oidc::AUTHORIZE_TRANSACTION,
                get(Self::authorization_transaction),
            )
            .route(
                routes::oidc::AUTHORIZE_DECISION,
                post(Self::authorization_decision),
            )
            .route(routes::oidc::TOKEN, post(Self::token))
            .route(routes::oidc::REVOKE, post(Self::revoke))
            .route(
                routes::oidc::USERINFO,
                get(Self::userinfo).post(Self::userinfo),
            )
            .route(
                routes::oidc::LOGOUT,
                get(Self::start_logout).post(Self::logout),
            )
            .with_state(self)
    }

    /// Serves the `OpenID` Provider metadata.
    fn discovery(State(app): State<Self>) -> std::future::Ready<Json<Discovery>> {
        let base = &app.issuer;
        std::future::ready(Json(Discovery {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}{}", routes::oidc::AUTHORIZE),
            token_endpoint: format!("{base}{}", routes::oidc::TOKEN),
            revocation_endpoint: format!("{base}{}", routes::oidc::REVOKE),
            userinfo_endpoint: format!("{base}{}", routes::oidc::USERINFO),
            jwks_uri: format!("{base}{}", routes::oidc::JWKS),
            end_session_endpoint: format!("{base}{}", routes::oidc::LOGOUT),
            response_types_supported: &ResponseType::ALL,
            grant_types_supported: &GrantType::ALL,
            code_challenge_methods_supported: &CodeChallengeMethod::ALL,
            token_endpoint_auth_methods_supported: &ClientAuthentication::ALL,
            subject_types_supported: &[SUBJECT_TYPE],
            response_modes_supported: &ResponseMode::ALL,
            claims_supported: &SUPPORTED_CLAIMS,
            id_token_signing_alg_values_supported: &Algorithm::ALL,
            request_uri_parameter_supported: false,
            request_parameter_supported: false,
            scopes_supported: &Scope::ALL,
        }))
    }

    /// Serves the public signing keys.
    fn jwks(State(app): State<Self>) -> std::future::Ready<Json<Value>> {
        std::future::ready(Json(app.keys.jwks()))
    }

    /// Authenticates the client: public clients by ID alone, confidential clients with
    /// HTTP Basic. A `client_id` form field, when sent, must name the same client.
    async fn authenticate_client(
        &self,
        headers: &HeaderMap,
        supplied_id: Option<&str>,
    ) -> Result<StoredOidcClient, OAuthError> {
        let basic = headers
            .get(header::AUTHORIZATION)
            .map(Self::basic_credentials)
            .transpose()?;
        let id = basic
            .as_ref()
            .map(|(id, _)| id.as_str())
            .or(supplied_id)
            .ok_or_else(|| {
                OAuthCode::InvalidClient.reject("send client_id, or HTTP Basic client credentials")
            })?;
        if supplied_id.is_some_and(|supplied| supplied != id) {
            return Err(OAuthCode::InvalidClient
                .reject("client_id does not match the HTTP Basic client credentials"));
        }
        // Client IDs are public, so naming an unknown one reveals nothing secret.
        let client = self
            .database
            .oidc()
            .find_client(id)
            .await?
            .filter(|client| client.enabled)
            .ok_or_else(|| {
                OAuthCode::InvalidClient.reject("client_id is not a registered, enabled client")
            })?;
        match (&client.client_secret_hash, &basic) {
            (None, None) => Ok(client),
            (Some(expected), Some((_, secret))) => {
                if Digest::constant_time_eq(expected, Digest::sha256(secret.as_bytes()).as_bytes())
                {
                    Ok(client)
                } else {
                    Err(OAuthCode::InvalidClient.reject("the client secret is incorrect"))
                }
            }
            // Public clients have no secret and must not send one.
            (None, Some(_)) => Err(OAuthCode::InvalidClient
                .reject("this public client must not send HTTP Basic credentials")),
            (Some(_), None) => Err(OAuthCode::InvalidClient
                .reject("this client must authenticate with HTTP Basic credentials")),
        }
    }

    /// Decodes HTTP Basic client credentials into an ID and secret.
    fn basic_credentials(value: &HeaderValue) -> Result<(String, String), OAuthError> {
        let value = value.to_str().map_err(|error| {
            OAuthCode::InvalidClient
                .reject_with("the Authorization header is not valid text", error)
        })?;
        let encoded = AuthScheme::Basic.credentials(value).ok_or_else(|| {
            OAuthCode::InvalidClient.reject(format!(
                "the Authorization header must use {}",
                AuthScheme::Basic
            ))
        })?;
        if encoded.len() > MAX_BASIC_CREDENTIAL_BYTES {
            return Err(OAuthCode::InvalidClient.reject(format!(
                "{} credentials must be at most {MAX_BASIC_CREDENTIAL_BYTES} bytes",
                AuthScheme::Basic
            )));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| {
                OAuthCode::InvalidClient.reject_with(
                    format!("{} credentials are not valid base64", AuthScheme::Basic),
                    error,
                )
            })?;
        let decoded = String::from_utf8(bytes).map_err(|error| {
            OAuthCode::InvalidClient.reject_with(
                format!("{} credentials are not UTF-8", AuthScheme::Basic),
                error,
            )
        })?;
        let (id, secret) = decoded.split_once(':').ok_or_else(|| {
            OAuthCode::InvalidClient.reject(format!(
                "{} credentials must be client_id:client_secret",
                AuthScheme::Basic
            ))
        })?;
        // RFC 6749 §2.3.1 form-encodes the ID and secret before base64. Decoding a
        // single `v=<value>` pair always yields that pair.
        let decode = |value: &str| {
            url::form_urlencoded::parse(format!("v={value}").as_bytes())
                .next()
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default()
        };
        Ok((decode(id), decode(secret)))
    }

    /// Requires a browser mutation to come from the issuer's own pages: a matching
    /// `Origin` plus either the CSRF header or `Sec-Fetch-Site: same-origin`.
    fn require_same_origin(&self, headers: &HeaderMap) -> Result<(), OAuthError> {
        // Non-text header values cannot match, so they fail like absent ones.
        let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
        if text(header::ORIGIN.as_str()) != Some(self.issuer.as_str()) {
            return Err(OAuthCode::InvalidRequest.reject("Origin must be this issuer"));
        }
        let csrf_header = text(CSRF_HEADER) == Some(CSRF_HEADER_VALUE);
        let same_origin_fetch = text(FETCH_SITE_HEADER) == Some(FETCH_SITE_SAME_ORIGIN);
        if csrf_header || same_origin_fetch {
            Ok(())
        } else {
            Err(OAuthCode::InvalidRequest.reject(format!(
                "send {CSRF_HEADER}: {CSRF_HEADER_VALUE}, or make a same-origin request"
            )))
        }
    }
    /// HMAC of an opaque token's secret, the only form in which it is stored.
    fn token_digest(&self, token: &OpaqueToken) -> Result<Digest, OAuthError> {
        Ok(Digest::hmac(
            self.refresh_key.as_bytes(),
            token.secret.as_bytes(),
        )?)
    }
}
