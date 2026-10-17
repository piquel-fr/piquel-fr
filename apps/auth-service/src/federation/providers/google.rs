//! Google sign-in: `OpenID` Connect, so the identity comes only from a signed ID token.

use super::{
    FederationApplication, FederationConfigError, IdentityStrategy, MAX_TOKEN_BYTES,
    ProviderEndpoints, ProviderError, VerifiedIdentity,
};
use chrono::Utc;
use piquel_auth::{Jws, KeyCache, TokenError};
use piquel_auth_protocol::claims::Audience;
use piquel_auth_protocol::jwt::Algorithm;
use piquel_auth_protocol::oauth::{Prompt, Scope};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Google scopes: a signed ID token carrying email and profile claims.
const SCOPES: &[&str] = &[
    Scope::OpenId.as_str(),
    Scope::Email.as_str(),
    Scope::Profile.as_str(),
];
/// Allowed clock skew when checking ID-token issuance.
const CLOCK_SKEW_SECONDS: i64 = 30;
/// Display name proposed when the token carries no usable name.
const FALLBACK_NAME: &str = "Google user";
/// Google's published signing keys.
const KEYS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Reasons a Google ID token is not accepted.
#[derive(Debug, Error)]
pub(in crate::federation) enum GoogleError {
    /// The ID token is longer than we accept.
    #[error("Google ID token is {0} bytes; at most {MAX_TOKEN_BYTES} are accepted")]
    TokenTooLong(usize),
    /// The ID token is malformed, not RS256, signed by an unpublished key, or its
    /// signature does not verify.
    #[error("Google ID token failed verification")]
    Signature(#[from] TokenError),
    /// The ID token's claims are missing or have the wrong type.
    #[error("Google ID token claims are invalid")]
    Claims(#[source] serde_json::Error),
    /// The ID token was issued by someone other than Google.
    #[error("Google ID token issuer {0:?} is not Google")]
    UntrustedIssuer(String),
    /// The ID token is for another client.
    #[error("Google ID token is not for this client")]
    WrongAudience,
    /// The ID token also names clients other than this one.
    #[error("Google ID token audience includes other clients")]
    SharedAudience,
    /// The ID token was issued for another sign-in attempt.
    #[error("Google ID token nonce does not match this sign-in attempt")]
    NonceMismatch,
    /// The ID token has expired.
    #[error("Google ID token has expired")]
    Expired,
    /// The ID token's issuance time is in the future.
    #[error("Google ID token is issued in the future")]
    IssuedInFuture,
    /// The ID token was authorized for another client.
    #[error("Google ID token authorized party is another client")]
    AuthorizedPartyMismatch,
}

/// Facts needed to request and verify Google ID tokens.
#[derive(Clone)]
pub(in crate::federation) struct GoogleProtocol {
    /// Google's signing keys, cached across sign-ins: kept for the response's
    /// `max-age`, refetched once for an unknown key ID, and fetched at most every 30
    /// seconds. Tests point it at a local fixture.
    pub(in crate::federation) keys: KeyCache,
    /// Accepted `iss` values: Google uses both the HTTPS and the legacy scheme-less form.
    pub(in crate::federation) issuers: &'static [&'static str],
}

impl ProviderEndpoints {
    /// Google's protocol facts; `client` fetches its signing keys.
    pub(super) fn google(client: &reqwest::Client) -> Result<Self, FederationConfigError> {
        Ok(Self {
            issuer: "https://accounts.google.com",
            authorization: "https://accounts.google.com/o/oauth2/v2/auth",
            token: "https://oauth2.googleapis.com/token".into(),
            scopes: SCOPES,
            identity: IdentityStrategy::Google(GoogleProtocol {
                keys: KeyCache::new(
                    Url::parse(KEYS_URL).map_err(FederationConfigError::ProviderEndpoint)?,
                    client.clone(),
                ),
                issuers: &["https://accounts.google.com", "accounts.google.com"],
            }),
        })
    }
}

impl GoogleProtocol {
    /// Binds the ID token to this flow's nonce, and makes the user pick an account
    /// instead of silently reusing one.
    pub(super) fn extend_authorization(url: &mut Url, nonce: &str) {
        url.query_pairs_mut()
            .append_pair("nonce", nonce)
            .append_pair("prompt", Prompt::SelectAccount.as_str());
    }
}

impl FederationApplication {
    /// Takes Google's identity only from an `RS256` ID token signed by a published key,
    /// looked up in the protocol's key cache.
    pub(in crate::federation) async fn google_identity(
        &self,
        response: reqwest::Response,
        client_id: &str,
        nonce: &str,
        protocol: &GoogleProtocol,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let token: GoogleToken = Self::json(response).await?;
        let claims = GoogleClaims::verify(&token.id_token, protocol, client_id, nonce).await?;
        VerifiedIdentity::new(
            claims.sub,
            claims.email.filter(|_| claims.email_verified),
            claims.name,
            FALLBACK_NAME.into(),
        )
    }
}

/// Google's code-exchange response.
#[derive(Deserialize)]
struct GoogleToken {
    /// Signed ID token, never trusted before `GoogleClaims::verify`.
    id_token: String,
}

/// Claims read from a Google ID token.
#[derive(Deserialize)]
pub(in crate::federation) struct GoogleClaims {
    /// Who issued the token; must be one of Google's issuers.
    iss: String,
    /// Intended client or clients.
    aud: Audience,
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
    /// Verifies the signature against Google's published keys, then the issuer,
    /// exclusive audience, nonce and times. Unlike the SDK's own ID tokens, expiry has
    /// no leeway: the token came straight from Google's token endpoint.
    pub(in crate::federation) async fn verify(
        token: &str,
        protocol: &GoogleProtocol,
        client_id: &str,
        nonce: &str,
    ) -> Result<Self, GoogleError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(GoogleError::TokenTooLong(token.len()));
        }
        let jws = Jws::parse(token)?;
        let algorithm = jws.require_algorithm(&[Algorithm::Rs256])?;
        protocol.keys.verify(&jws, algorithm).await?;
        let claims: Self = serde_json::from_slice(jws.payload()).map_err(GoogleError::Claims)?;
        if !protocol.issuers.contains(&claims.iss.as_str()) {
            return Err(GoogleError::UntrustedIssuer(claims.iss));
        }
        if !claims.aud.contains(client_id) {
            return Err(GoogleError::WrongAudience);
        }
        if claims.aud.iter().any(|audience| audience != client_id) {
            return Err(GoogleError::SharedAudience);
        }
        if claims.nonce != nonce {
            return Err(GoogleError::NonceMismatch);
        }
        let now = Utc::now().timestamp();
        if claims.exp <= now {
            return Err(GoogleError::Expired);
        }
        if claims.iat > now + CLOCK_SKEW_SECONDS {
            return Err(GoogleError::IssuedInFuture);
        }
        if claims.azp.as_deref().is_some_and(|azp| azp != client_id) {
            return Err(GoogleError::AuthorizedPartyMismatch);
        }
        Ok(claims)
    }
}
