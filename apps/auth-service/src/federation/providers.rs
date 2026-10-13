//! Provider protocol facts, code exchange and verified identity extraction.

use super::{FederationApplication, Provider};
use crate::email::NormalizedEmail;
use axum::http::{StatusCode, header};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use piquel_auth_protocol::oauth::{GrantType, Prompt, Scope};
use piquel_common::ConfigurationError;
use piquel_crypto::jwt::{Algorithm as JwtAlgorithm, Claim, KeyType, KeyUse};
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

/// Maximum stored byte length of a provider subject.
const MAX_SUBJECT_BYTES: usize = 255;
/// Maximum length of provider bearer credentials and ID tokens.
const MAX_TOKEN_BYTES: usize = 8192;
/// Maximum number of characters kept from a provider profile name.
const MAX_DISPLAY_NAME_CHARS: usize = 80;
/// Maximum provider response size, enforced while streaming chunked bodies too.
const MAX_RESPONSE_BYTES: usize = 65536;
/// Allowed provider clock skew when checking ID-token issuance and expiry.
const JWT_CLOCK_SKEW_SECONDS: i64 = 30;
/// Claims an ID token must carry, on top of a valid signature.
const REQUIRED_ID_TOKEN_CLAIMS: [&str; 4] = [
    Claim::Issuer.as_str(),
    Claim::Audience.as_str(),
    Claim::ExpiresAt.as_str(),
    Claim::Subject.as_str(),
];
/// GitHub scopes: the public profile plus the account's email addresses.
const GITHUB_SCOPES: &[&str] = &["read:user", "user:email"];
/// Google scopes: a signed ID token carrying email and profile claims.
const GOOGLE_SCOPES: &[&str] = &[
    Scope::OpenId.as_str(),
    Scope::Email.as_str(),
    Scope::Profile.as_str(),
];

/// Why a provider callback produced no verified identity. These failures are only
/// logged: the browser goes back to the login page with a generic error.
#[derive(Debug, Error)]
pub(super) enum ProviderError {
    /// The flow's provider was disabled since the flow started, e.g. by a restart.
    #[error("sign-in provider is not configured")]
    NotConfigured,
    /// The client secret is not UTF-8 text (startup checks this, so it should not happen).
    #[error(transparent)]
    Secret(#[from] ConfigurationError),
    /// A provider request failed or answered with a non-success status.
    #[error("provider HTTP exchange failed")]
    Http(#[from] reqwest::Error),
    /// A provider response is not the JSON we expect.
    #[error("provider returned invalid JSON")]
    Json(#[from] serde_json::Error),
    /// An ID token or its signing key could not be decoded or verified.
    #[error("provider token verification failed")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// The verified subject is empty or longer than we store.
    #[error("provider subject is empty or too long")]
    InvalidSubject,
    /// The access token is empty or longer than we accept.
    #[error("provider access token is empty or too long")]
    InvalidAccessToken,
    /// GitHub returned the reserved user ID 0.
    #[error("GitHub user ID is zero")]
    ZeroUserId,
    /// The ID token is longer than we accept.
    #[error("ID token is too long")]
    IdTokenTooLong,
    /// The ID token is not signed with RS256.
    #[error("ID token is not RS256")]
    IdTokenAlgorithm,
    /// The ID token header names no signing key.
    #[error("ID token has no key ID")]
    IdTokenKeyId,
    /// The provider's key set has no RSA signing key with the ID token's `kid`.
    #[error("no matching RSA signing key")]
    UnknownSigningKey,
    /// A provider response is larger than we buffer.
    #[error("provider response is too large")]
    ResponseTooLarge,
    /// The ID token was issued for another client, flow or time.
    #[error("ID token audience, nonce, timing or authorized party mismatch")]
    IdTokenClaims,
}

/// Every protocol fact about a provider. Back-channel URLs are `String`s so tests can
/// point them at a local fixture.
#[derive(Clone)]
pub(super) struct ProviderEndpoints {
    /// Issuer stored beside each subject, so subjects never collide across providers.
    pub(super) issuer: &'static str,
    /// Page the browser is sent to for authorization.
    pub(super) authorization: &'static str,
    /// Back-channel endpoint exchanging the authorization code.
    pub(super) token: String,
    /// Requested scopes, in the order sent to the provider.
    pub(super) scopes: &'static [&'static str],
    /// How the verified subject is read once the code is exchanged.
    pub(super) identity: IdentityStrategy,
}

impl ProviderEndpoints {
    /// The single place holding provider facts: a new `Provider` fails to compile here.
    pub(super) fn new(provider: Provider) -> Self {
        match provider {
            Provider::GitHub => Self {
                issuer: "https://github.com",
                authorization: "https://github.com/login/oauth/authorize",
                token: "https://github.com/login/oauth/access_token".into(),
                scopes: GITHUB_SCOPES,
                identity: IdentityStrategy::GitHub {
                    user: "https://api.github.com/user".into(),
                    emails: "https://api.github.com/user/emails?per_page=100".into(),
                },
            },
            Provider::Google => Self {
                issuer: "https://accounts.google.com",
                authorization: "https://accounts.google.com/o/oauth2/v2/auth",
                token: "https://oauth2.googleapis.com/token".into(),
                scopes: GOOGLE_SCOPES,
                identity: IdentityStrategy::Google(GoogleProtocol {
                    keys: "https://www.googleapis.com/oauth2/v3/certs".into(),
                    issuers: &["https://accounts.google.com", "accounts.google.com"],
                    prompt: Prompt::SelectAccount,
                    fallback_name: "Google user",
                }),
            },
        }
    }
}

/// How a provider proves who the user is after the shared code exchange.
#[derive(Clone)]
pub(super) enum IdentityStrategy {
    /// OAuth only: fetch the profile, then the verified primary email.
    GitHub {
        /// Profile endpoint returning the numeric subject and names.
        user: String,
        /// Email endpoint; when GitHub denies access the identity simply has no email.
        emails: String,
    },
    /// `OpenID` Connect: identity comes only from a verified, nonce-bound ID token.
    Google(GoogleProtocol),
}

/// Facts needed to request and verify Google ID tokens.
#[derive(Clone)]
pub(super) struct GoogleProtocol {
    /// Public signing-key (JWKS) endpoint.
    pub(super) keys: String,
    /// Accepted `iss` values: Google uses both the HTTPS and the legacy scheme-less form.
    pub(super) issuers: &'static [&'static str],
    /// Sent as `prompt` so the user picks an account instead of silently reusing one.
    pub(super) prompt: Prompt,
    /// Display name proposed when the token carries no usable name.
    fallback_name: &'static str,
}

/// Provider evidence that passed every check; usable for login or explicit linking.
pub(super) struct VerifiedIdentity {
    /// Stable provider account ID, independent of the email address.
    pub(super) subject: String,
    /// Normalized verified email, if the provider gave a valid one.
    pub(super) email: Option<String>,
    /// Profile name proposed for onboarding, at most `MAX_DISPLAY_NAME_CHARS` long.
    pub(super) display_name: String,
}

impl VerifiedIdentity {
    /// Rejects unstorable subjects, drops invalid emails and bounds the display name.
    fn new(
        subject: String,
        email: Option<String>,
        name: Option<String>,
        fallback_name: String,
    ) -> Result<Self, ProviderError> {
        if subject.is_empty() || subject.len() > MAX_SUBJECT_BYTES {
            return Err(ProviderError::InvalidSubject);
        }
        Ok(Self {
            subject,
            // An invalid optional email is dropped; email never proves account ownership.
            email: email
                .and_then(|email| NormalizedEmail::parse(&email).ok())
                .map(|email| email.as_str().to_owned()),
            display_name: name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(fallback_name)
                .chars()
                .take(MAX_DISPLAY_NAME_CHARS)
                .collect(),
        })
    }
}

impl FederationApplication {
    /// Exchanges a PKCE-bound code, then reads the identity the provider's way.
    pub(super) async fn exchange(
        &self,
        provider: Provider,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let config = self
            .providers
            .get(&provider)
            .ok_or(ProviderError::NotConfigured)?;
        let endpoints = &self.endpoints[&provider];
        let response = self
            .client
            .post(&endpoints.token)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("client_id", config.client_id.as_str()),
                ("client_secret", config.client_secret.utf8()?),
                ("code", code),
                ("redirect_uri", &self.callback_url(provider)),
                ("code_verifier", verifier),
                ("grant_type", GrantType::AuthorizationCode.as_str()),
            ])
            .send()
            .await?;
        match &endpoints.identity {
            IdentityStrategy::GitHub { user, emails } => {
                self.github_identity(response, user, emails).await
            }
            IdentityStrategy::Google(protocol) => {
                self.google_identity(response, &config.client_id, nonce, protocol)
                    .await
            }
        }
    }

    /// Reads GitHub's numeric subject and, if shared, its verified primary email.
    async fn github_identity(
        &self,
        response: reqwest::Response,
        user_endpoint: &str,
        emails_endpoint: &str,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let token: GithubToken = Self::json(response).await?;
        if token.access_token.is_empty() || token.access_token.len() > MAX_TOKEN_BYTES {
            return Err(ProviderError::InvalidAccessToken);
        }
        let user: GithubUser = Self::json(
            self.client
                .get(user_endpoint)
                .bearer_auth(&token.access_token)
                .send()
                .await?,
        )
        .await?;
        if user.id == 0 {
            return Err(ProviderError::ZeroUserId);
        }
        let response = self
            .client
            .get(emails_endpoint)
            .bearer_auth(&token.access_token)
            .send()
            .await?;
        // GitHub can withhold email access without invalidating its authenticated subject.
        let emails: Vec<GithubEmail> = if response.status() == StatusCode::FORBIDDEN {
            Vec::new()
        } else {
            Self::json(response).await?
        };
        let email = emails
            .into_iter()
            .find(|email| email.verified && email.primary)
            .map(|email| email.email);
        VerifiedIdentity::new(user.id.to_string(), email, user.name, user.login)
    }

    /// Takes Google's identity only from an `RS256` ID token signed by a published key.
    pub(super) async fn google_identity(
        &self,
        response: reqwest::Response,
        client_id: &str,
        nonce: &str,
        protocol: &GoogleProtocol,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let token: GoogleToken = Self::json(response).await?;
        if token.id_token.len() > MAX_TOKEN_BYTES {
            return Err(ProviderError::IdTokenTooLong);
        }
        let header = decode_header(&token.id_token)?;
        if header.alg != Algorithm::RS256 {
            return Err(ProviderError::IdTokenAlgorithm);
        }
        let kid = header.kid.ok_or(ProviderError::IdTokenKeyId)?;
        let jwks: GoogleJwks = Self::json(self.client.get(&protocol.keys).send().await?).await?;
        let jwk = jwks
            .keys
            .into_iter()
            .find(|key| {
                key.kid == kid
                    && key.kty == KeyType::Rsa.as_str()
                    && key
                        .alg
                        .as_deref()
                        .is_none_or(|alg| alg == JwtAlgorithm::Rs256.as_str())
                    && key
                        .key_use
                        .as_deref()
                        .is_none_or(|usage| usage == KeyUse::Signature.as_str())
            })
            .ok_or(ProviderError::UnknownSigningKey)?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
        let claims =
            GoogleClaims::verify(&token.id_token, &key, client_id, nonce, protocol.issuers)?;
        VerifiedIdentity::new(
            claims.sub,
            claims.email.filter(|_| claims.email_verified),
            claims.name,
            protocol.fallback_name.into(),
        )
    }

    /// Reads a success response as JSON, refusing bodies over `MAX_RESPONSE_BYTES`.
    async fn json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, ProviderError> {
        let mut response = response.error_for_status()?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(ProviderError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&body)?)
    }
}

/// GitHub's code-exchange response.
#[derive(Deserialize)]
struct GithubToken {
    /// Bearer token, used only for GitHub API requests.
    access_token: String,
}

/// GitHub's authenticated user profile.
#[derive(Deserialize)]
struct GithubUser {
    /// Stable numeric account ID; zero is invalid.
    id: u64,
    /// Profile name, often unset.
    name: Option<String>,
    /// Username, used as the display name when `name` is unset.
    login: String,
}

/// One address from GitHub's email list.
#[derive(Deserialize)]
struct GithubEmail {
    /// Address as GitHub returns it, not yet normalized.
    email: String,
    /// Whether GitHub verified ownership of the address.
    verified: bool,
    /// Whether this is the account's primary address.
    primary: bool,
}

/// Google's code-exchange response.
#[derive(Deserialize)]
struct GoogleToken {
    /// Signed ID token, never trusted before `GoogleClaims::verify`.
    id_token: String,
}

/// Claims read from a Google ID token.
#[derive(Deserialize)]
pub(super) struct GoogleClaims {
    /// Intended client or clients.
    aud: GoogleAudience,
    /// Stable Google account ID.
    sub: String,
    /// Expiry, as a Unix timestamp.
    exp: i64,
    /// Issuance time, as a Unix timestamp.
    iat: i64,
    /// Nonce stored with the federation flow when it started.
    nonce: String,
    /// Authorized party; must be this client when present.
    azp: Option<String>,
    /// Contact address, if the `email` scope returned one.
    email: Option<String>,
    /// Whether Google verified `email`.
    #[serde(default)]
    email_verified: bool,
    /// Profile name proposed for onboarding.
    name: Option<String>,
}

impl GoogleClaims {
    /// Verifies the signature, issuer, exclusive audience, nonce and expiry.
    pub(super) fn verify(
        token: &str,
        key: &DecodingKey,
        client_id: &str,
        nonce: &str,
        issuers: &[&str],
    ) -> Result<Self, ProviderError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&REQUIRED_ID_TOKEN_CLAIMS);
        validation.set_audience(&[client_id]);
        validation.set_issuer(issuers);
        validation.leeway = JWT_CLOCK_SKEW_SECONDS.unsigned_abs();
        // `decode` checks the signature, required claims, issuer and that the audience
        // includes this client. The checks below are stricter than the library's.
        let claims = decode::<Self>(token, key, &validation)?.claims;
        let now = Utc::now().timestamp();
        if !claims.aud.only_contains(client_id)
            || claims.nonce != nonce
            // The library allows `leeway` past expiry; we do not.
            || claims.exp <= now
            || claims.iat > now + JWT_CLOCK_SKEW_SECONDS
            || claims.azp.as_deref().is_some_and(|azp| azp != client_id)
        {
            return Err(ProviderError::IdTokenClaims);
        }
        Ok(claims)
    }
}

/// The two legal `OpenID` Connect `aud` encodings.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoogleAudience {
    /// A token for one client.
    Single(String),
    /// A token naming a list of clients.
    Multiple(Vec<String>),
}

impl GoogleAudience {
    /// True when the audience is nonempty and names only this client, never another one.
    fn only_contains(&self, client_id: &str) -> bool {
        match self {
            Self::Single(value) => value == client_id,
            Self::Multiple(values) => {
                !values.is_empty() && values.iter().all(|value| value == client_id)
            }
        }
    }
}
/// Google's published signing keys.
#[derive(Deserialize)]
struct GoogleJwks {
    /// Candidate keys, matched against the ID token's `kid`.
    keys: Vec<GoogleJwk>,
}
/// One published RSA key and its optional metadata.
#[derive(Deserialize)]
struct GoogleJwk {
    /// Key ID matched against the ID token header.
    kid: String,
    /// Key type; must be RSA.
    kty: String,
    /// Signature algorithm; must be RS256 when present.
    alg: Option<String>,
    /// Key usage; must be signing when present.
    #[serde(rename = "use")]
    key_use: Option<String>,
    /// Base64url RSA modulus.
    n: String,
    /// Base64url RSA public exponent.
    e: String,
}
