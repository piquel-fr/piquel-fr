//! Authorization Code + PKCE, signed tokens, and rotating opaque refresh tokens.

/// Authorization, login continuation and consent.
mod authorize;
/// Protocol errors and their HTTP responses.
mod error;
/// RP-initiated logout and confirmation.
mod logout;
/// Code exchanges, refresh rotation and identity claims.
mod token;

use crate::config::{OidcConfig, TokenDigestKeys};
use crate::keys::SigningKeys;
use crate::routes;
use crate::security::{CacheClass, Cached};
pub(crate) use authorize::{AuthorizationDecision, TransactionQuery};
pub use error::OidcConfigError;
pub(crate) use error::{OAuthCode, OAuthError, Reject};
pub(crate) use logout::LogoutQuery;
use piquel_crypto::{ClientSecret, CryptoError, Digest, Secret};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use piquel_common::{
    TokenId,
    clients::ClientKind,
    protocol::{
        claims::{Acr, ProfileClaims},
        jwt::{Algorithm, Claim, TokenType},
        metadata::ServerMetadata,
        oauth::{
            self, ClientAuthMethod, CodeChallengeMethod, GrantType, Prompt, ResponseMode,
            ResponseType, Scope, SubjectType,
        },
    },
};
use piquel_repository::{Database, StoredOidcClient};
use piquel_ui::Query;
use serde::Serialize;
use std::sync::Arc;
use url::Url;

/// Lifetime of signed access and ID tokens; kept short because they cannot be revoked.
pub(crate) const ACCESS_TOKEN_SECONDS: i64 = 300;
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
/// How long a pushed request waits for the browser to bring its `request_uri`.
const PUSHED_REQUEST_SECONDS: i64 = 60;
/// How long an authorization code stays redeemable.
const AUTHORIZATION_CODE_MINUTES: i64 = 2;
/// Developer documentation advertised in the metadata.
const SERVICE_DOCUMENTATION: &str = "https://github.com/piquel-fr/piquel-fr#oidc-clients";

/// The OAuth 2.0 and `OpenID` Connect provider.
#[derive(Clone)]
pub struct OidcApplication {
    /// Shared database pool.
    database: Database,
    /// HTTPS issuer origin, without a trailing slash.
    issuer: String,
    /// Keys under which opaque token secrets are stored.
    digest_keys: Arc<TokenDigestKeys>,
    /// Keys that sign and verify tokens, reloaded from the database.
    keys: SigningKeys,
    /// Server metadata, served at both well-known discovery paths.
    metadata: PublicDocument,
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
        /// Pending login and consent transaction, or a pushed request not yet claimed.
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

    /// A token for the same record with a fresh secret. Once the record stores the
    /// new secret's digest, the previous token stops matching.
    fn renewed(&self) -> Result<Self, OAuthError> {
        Ok(Self {
            id: self.id,
            secret: Secret::generate()?,
            prefix: self.prefix,
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

/// A requested or granted scope set: the shared wire type, plus auth's request limits.
/// Holds plain strings because clients may be granted registered extension scopes
/// besides [`Scope`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Scopes(oauth::Scopes);

impl Scopes {
    /// Parses a space-separated scope list, which must be non-empty and bounded.
    fn parse(value: &str) -> Result<Self, OAuthError> {
        let scopes: oauth::Scopes = value.parse().map_err(|error| {
            OAuthCode::InvalidScope.reject_with("scope has an invalid scope token", error)
        })?;
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

    /// Wraps the scopes of a token auth signed, which were limited when it was issued.
    const fn from_wire(scopes: oauth::Scopes) -> Self {
        Self(scopes)
    }

    /// Keeps only the claims these scopes release: profile claims with `profile`, and
    /// email claims with `email`.
    fn release(&self, mut claims: ProfileClaims) -> ProfileClaims {
        let mut released = ProfileClaims::default();
        for scope in Scope::ALL {
            if !self.contains(scope) {
                continue;
            }
            match scope {
                Scope::Profile => {
                    released.preferred_username = claims.preferred_username.take();
                    released.name = claims.name.take();
                    released.profile_version = claims.profile_version.take();
                }
                Scope::Email => {
                    released.email = claims.email.take();
                    released.email_verified = claims.email_verified.take();
                }
                // These scopes release no claims.
                Scope::OpenId | Scope::OfflineAccess => {}
            }
        }
        released
    }

    /// Whether every scope is in `allowed`.
    fn allowed_by(&self, allowed: &[String]) -> bool {
        self.0
            .iter()
            .all(|scope| allowed.iter().any(|value| value == scope))
    }

    /// Whether the set contains a standard scope.
    fn contains(&self, scope: Scope) -> bool {
        self.0.contains(scope.as_str())
    }

    /// Converts to the list stored in the database.
    fn into_stored(self) -> Vec<String> {
        self.0.into_iter().collect()
    }

    /// The shared wire type, as sent in responses and the access token's `scope` claim.
    fn wire(&self) -> &oauth::Scopes {
        &self.0
    }
}

/// Claims listed in the metadata, in their published order.
const SUPPORTED_CLAIMS: [Claim; 10] = [
    Claim::Subject,
    Claim::Name,
    Claim::Username,
    Claim::Email,
    Claim::EmailVerified,
    Claim::ProfileVersion,
    Claim::AuthTime,
    Claim::Methods,
    Claim::AuthenticationClass,
    Claim::Session,
];

/// A public JSON document, such as the metadata, serialized once at startup, or
/// JWKS, serialized from the current key set. Responses let any cache keep them
/// for an hour.
#[derive(Clone)]
pub(crate) struct PublicDocument(Bytes);

impl PublicDocument {
    /// How long caches may reuse the document, in seconds. Signing key rotation
    /// publishes keys for longer than this before and after they sign.
    pub(crate) const MAX_AGE_SECONDS: i64 = 3600;
    /// The caching [`Self::MAX_AGE_SECONDS`] allows.
    pub(crate) const CACHE: CacheClass = CacheClass::Public {
        max_age: std::time::Duration::from_secs(Self::MAX_AGE_SECONDS.unsigned_abs()),
    };

    /// Serializes `value`.
    fn new(value: &impl Serialize) -> Result<Self, serde_json::Error> {
        Ok(Self(serde_json::to_vec(value)?.into()))
    }
}

impl IntoResponse for PublicDocument {
    /// Sends the stored bytes as cacheable JSON.
    fn into_response(self) -> Response {
        Cached(
            Self::CACHE,
            ([(header::CONTENT_TYPE, "application/json")], self.0),
        )
        .into_response()
    }
}

/// Where an authorization response goes: a verified client redirect URI, the request's
/// `state` and this issuer. Every success and error redirect to the client is built
/// here, so none can miss `state` or the RFC 9207 `iss`. Only this module builds one.
pub(crate) struct ClientRedirect<'a> {
    /// Redirect URI, already matched against the client's registration.
    uri: &'a Url,
    /// Client value returned unchanged.
    state: &'a str,
    /// Issuer identifier, exactly as in discovery.
    issuer: &'a str,
}

impl ClientRedirect<'_> {
    /// The redirect URI with `parameters`, `state` and `iss` appended.
    fn url(&self, parameters: &[(&str, &str)]) -> Url {
        let mut url = self.uri.clone();
        url.query_pairs_mut()
            .extend_pairs(parameters)
            .append_pair("state", self.state)
            .append_pair("iss", self.issuer);
        url
    }
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
    /// Builds the provider from its validated configuration and the shared
    /// signing keys, serializing its metadata once.
    pub(crate) fn new(
        database: Database,
        config: &OidcConfig,
        keys: SigningKeys,
    ) -> Result<Self, OidcConfigError> {
        Ok(Self {
            database,
            issuer: config.origin.serialized(),
            digest_keys: config.digest_keys.clone(),
            keys,
            metadata: PublicDocument::new(&Self::metadata(config)?)?,
        })
    }

    /// The server metadata. Supported value lists are the `ALL` of the enums the
    /// endpoints parse into, so nothing is advertised that is not handled.
    fn metadata(config: &OidcConfig) -> Result<ServerMetadata, OidcConfigError> {
        let origin = &config.origin;
        Ok(ServerMetadata {
            issuer: origin.serialized(),
            authorization_endpoint: origin.url(routes::oidc::AUTHORIZE),
            token_endpoint: origin.url(routes::oidc::TOKEN),
            revocation_endpoint: origin.url(routes::oidc::REVOKE),
            userinfo_endpoint: origin.url(routes::oidc::USERINFO),
            pushed_authorization_request_endpoint: Some(origin.url(routes::oidc::PAR)),
            // Individual clients may be required to push.
            require_pushed_authorization_requests: false,
            end_session_endpoint: origin.url(routes::oidc::LOGOUT),
            jwks_uri: origin.url(routes::oidc::JWKS),
            service_documentation: SERVICE_DOCUMENTATION
                .parse()
                .map_err(OidcConfigError::Documentation)?,
            scopes_supported: Scope::ALL.into(),
            response_types_supported: ResponseType::ALL.into(),
            response_modes_supported: ResponseMode::ALL.into(),
            grant_types_supported: GrantType::ALL.into(),
            // The token, revocation and pushed authorization endpoints all
            // authenticate clients with `authenticate_client`.
            token_endpoint_auth_methods_supported: ClientAuthMethod::ALL.into(),
            revocation_endpoint_auth_methods_supported: ClientAuthMethod::ALL.into(),
            code_challenge_methods_supported: CodeChallengeMethod::ALL.into(),
            subject_types_supported: SubjectType::ALL.into(),
            id_token_signing_alg_values_supported: Algorithm::ALL.into(),
            claims_supported: SUPPORTED_CLAIMS.into(),
            acr_values_supported: Acr::ALL.into(),
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            authorization_response_iss_parameter_supported: true,
            // Every logout token names the ended session with `sid`.
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
        })
    }

    /// Every discovery, OAuth and OIDC route, with `self` as their state.
    pub(crate) fn routes(self) -> Router {
        Router::new()
            .route(routes::oidc::DISCOVERY, get(Self::discovery))
            .route(routes::oidc::OAUTH_METADATA, get(Self::discovery))
            .route(routes::oidc::JWKS, get(Self::jwks))
            .route(
                routes::oidc::AUTHORIZE,
                get(Self::authorize).post(Self::authorize),
            )
            .route(routes::oidc::PAR, post(Self::push_authorization))
            .route(routes::oidc::AUTHORIZE_RESUME, get(Self::resume))
            .route(routes::oidc::TOKEN, post(Self::token))
            .route(routes::oidc::REVOKE, post(Self::revoke))
            .route(
                routes::oidc::USERINFO,
                get(Self::userinfo).post(Self::userinfo),
            )
            .route(
                routes::oidc::LOGOUT,
                get(Self::start_logout).post(Self::start_logout),
            )
            .with_state(self)
    }

    /// Serves the server metadata, identical at both well-known paths.
    fn discovery(State(app): State<Self>) -> std::future::Ready<PublicDocument> {
        std::future::ready(app.metadata)
    }

    /// Serves the published signing keys: the active key, the `next` one and
    /// those still retiring.
    fn jwks(State(app): State<Self>) -> std::future::Ready<Result<PublicDocument, OAuthError>> {
        std::future::ready(
            PublicDocument::new(app.keys.current().jwks())
                .map_err(|error| CryptoError::Json(error).into()),
        )
    }

    /// Authenticates the client at the token, revocation and pushed authorization
    /// endpoints: public clients by ID alone, confidential clients with HTTP Basic.
    /// A `client_id` form field, when sent, must name the same client.
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
        let method = match basic {
            Some(_) => ClientAuthMethod::ClientSecretBasic,
            None => ClientAuthMethod::None,
        };
        // Exhaustive over the methods the metadata advertises, so a new one cannot be
        // advertised without being checked here.
        match method {
            ClientAuthMethod::None if client.kind == ClientKind::Confidential => {
                Err(OAuthCode::InvalidClient
                    .reject("this client must authenticate with HTTP Basic credentials"))
            }
            ClientAuthMethod::None => Ok(client),
            ClientAuthMethod::ClientSecretBasic => {
                // `basic` is always present here, so only a public client fails.
                let (ClientKind::Confidential, Some((_, secret))) = (client.kind, &basic) else {
                    // Public clients have no secret and must not send one.
                    return Err(OAuthCode::InvalidClient
                        .reject("this public client must not send HTTP Basic credentials"));
                };
                // During a rotation's grace period, the previous secrets match too.
                // Every digest is compared, so timing does not reveal which one matched.
                let presented = ClientSecret::digest_presented(secret);
                let matched = self
                    .database
                    .oidc()
                    .active_secret_digests(client.id.as_str())
                    .await?
                    .iter()
                    .fold(false, |matched, digest| {
                        Digest::constant_time_eq(digest, presented.as_bytes()) | matched
                    });
                if matched {
                    Ok(client)
                } else {
                    Err(OAuthCode::InvalidClient
                        .reject("the client secret is incorrect or expired"))
                }
            }
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

    /// Auth's page at `page`, with `query`, where an OAuth flow sends the browser.
    fn page(&self, page: &str, query: &impl Query) -> Result<Url, OAuthError> {
        Ok(Url::parse(&format!("{}{}", self.issuer, query.on(page)?))?)
    }

    /// Responses to an authorization request with `state`, sent to its verified `uri`.
    fn client_redirect<'a>(&'a self, uri: &'a Url, state: &'a str) -> ClientRedirect<'a> {
        ClientRedirect {
            uri,
            state,
            issuer: &self.issuer,
        }
    }

    /// HMAC of a new opaque token's secret, the only form in which it is
    /// stored, and the fingerprint of the key that made it.
    fn token_digest(&self, token: &OpaqueToken) -> Result<(Vec<u8>, String), OAuthError> {
        let (digest, key) = self.digest_keys.issue(&token.secret)?;
        Ok((digest.as_bytes().to_vec(), key.to_owned()))
    }

    /// Every form in which a presented opaque token's secret may be stored: one
    /// digest per accepted digest key.
    fn accepted_digests(&self, token: &OpaqueToken) -> Result<Vec<Vec<u8>>, OAuthError> {
        Ok(self.digest_keys.accepted(&token.secret)?)
    }
}
