//! GitHub and Google code exchange and identity verification.

use super::{FederationApplication, Provider};
use crate::{email::normalize, security::ApiError};
use axum::http::{StatusCode, header};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, de::DeserializeOwned};

pub(super) struct VerifiedIdentity {
    pub(super) subject: String,
    pub(super) email: Option<String>,
    pub(super) display_name: String,
}
impl FederationApplication {
    pub(super) async fn exchange(
        &self,
        provider: Provider,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ApiError> {
        let config = self
            .providers
            .get(provider.name())
            .ok_or_else(|| ApiError::bad_request("This sign-in provider is not configured."))?;
        let secret = std::str::from_utf8(config.client_secret.expose_secret())
            .map_err(ApiError::internal)?;
        let callback = self.callback_url(provider);
        let endpoint = match provider {
            Provider::GitHub => &self.endpoints.github_token,
            Provider::Google => &self.endpoints.google_token,
        };
        let response = self
            .client
            .post(endpoint)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("client_id", config.client_id.as_str()),
                ("client_secret", secret),
                ("code", code),
                ("redirect_uri", &callback),
                ("code_verifier", verifier),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(ApiError::internal)?;
        let identity = match provider {
            Provider::GitHub => self.github_identity(response).await?,
            Provider::Google => {
                self.google_identity(response, &config.client_id, nonce)
                    .await?
            }
        };
        if identity.subject.is_empty() || identity.subject.len() > 255 {
            return Err(ApiError::bad_request(
                "The provider returned an invalid account identifier.",
            ));
        }
        Ok(identity)
    }
    async fn github_identity(
        &self,
        response: reqwest::Response,
    ) -> Result<VerifiedIdentity, ApiError> {
        let token: GithubToken = Self::json(response).await?;
        if token.access_token.is_empty() || token.access_token.len() > 8192 {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        let user: GithubUser = Self::json(
            self.client
                .get(&self.endpoints.github_user)
                .bearer_auth(&token.access_token)
                .send()
                .await
                .map_err(ApiError::internal)?,
        )
        .await?;
        let response = self
            .client
            .get(&self.endpoints.github_emails)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(ApiError::internal)?;
        let emails: Vec<GithubEmail> = if response.status() == StatusCode::FORBIDDEN {
            Vec::new()
        } else {
            Self::json(response).await?
        };
        let email = emails
            .iter()
            .find(|email| email.verified && email.primary)
            .and_then(|email| normalize(&email.email).ok())
            .map(|email| email.as_str().to_owned());
        if user.id == 0 {
            return Err(ApiError::bad_request(
                "The provider returned an invalid account identifier.",
            ));
        }
        Ok(VerifiedIdentity {
            subject: user.id.to_string(),
            email,
            display_name: user
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(user.login)
                .chars()
                .take(80)
                .collect(),
        })
    }
    pub(super) async fn google_identity(
        &self,
        response: reqwest::Response,
        client_id: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ApiError> {
        let token: GoogleToken = Self::json(response).await?;
        if token.id_token.len() > 8192 {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        let header = decode_header(&token.id_token).map_err(|_| {
            ApiError::bad_request("The provider sign-in could not be verified. Please try again.")
        })?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        let kid = header.kid.ok_or_else(|| {
            ApiError::bad_request("The provider sign-in could not be verified. Please try again.")
        })?;
        let jwks: GoogleJwks = Self::json(
            self.client
                .get(&self.endpoints.google_keys)
                .send()
                .await
                .map_err(ApiError::internal)?,
        )
        .await?;
        let jwk = jwks
            .keys
            .into_iter()
            .find(|key| {
                key.kid == kid
                    && key.kty == "RSA"
                    && key.alg.as_deref().is_none_or(|alg| alg == "RS256")
                    && key.key_use.as_deref().is_none_or(|usage| usage == "sig")
            })
            .ok_or_else(|| {
                ApiError::bad_request(
                    "The provider sign-in could not be verified. Please try again.",
                )
            })?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|_| {
            ApiError::bad_request("The provider sign-in could not be verified. Please try again.")
        })?;
        let claims = Self::verify_google_token(&token.id_token, &key, client_id, nonce)?;
        let email = claims
            .email
            .filter(|_| claims.email_verified)
            .and_then(|email| normalize(&email).ok())
            .map(|email| email.as_str().to_owned());
        Ok(VerifiedIdentity {
            subject: claims.sub,
            email,
            display_name: claims
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "Google user".into())
                .chars()
                .take(80)
                .collect(),
        })
    }
    pub(super) fn verify_google_token(
        token: &str,
        key: &DecodingKey,
        client_id: &str,
        nonce: &str,
    ) -> Result<GoogleClaims, ApiError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[Provider::Google.issuer(), "accounts.google.com"]);
        validation.leeway = 30;
        let claims = decode::<GoogleClaims>(token, key, &validation)
            .map_err(|_| {
                ApiError::bad_request(
                    "The provider sign-in could not be verified. Please try again.",
                )
            })?
            .claims;
        if !matches!(
            claims.iss.as_str(),
            "https://accounts.google.com" | "accounts.google.com"
        ) || !claims.aud.only_contains(client_id)
            || claims.nonce != nonce
            || claims.sub.is_empty()
            || claims.exp <= Utc::now().timestamp()
            || claims.iat > Utc::now().timestamp() + 30
            || claims.azp.as_deref().is_some_and(|azp| azp != client_id)
        {
            return Err(ApiError::bad_request(
                "The provider sign-in could not be verified. Please try again.",
            ));
        }
        Ok(claims)
    }
    /// Bound even chunked provider responses before parsing them.
    async fn json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, ApiError> {
        let mut response = response.error_for_status().map_err(ApiError::internal)?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(ApiError::internal)? {
            if body.len() + chunk.len() > 65536 {
                return Err(ApiError::bad_request(
                    "The provider returned an unexpected response. Please try again.",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| {
            ApiError::bad_request("The provider returned an unexpected response. Please try again.")
        })
    }
}
#[derive(Deserialize)]
struct GithubToken {
    access_token: String,
}
#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    name: Option<String>,
    login: String,
}
#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    verified: bool,
    primary: bool,
}
#[derive(Deserialize)]
struct GoogleToken {
    id_token: String,
}
#[derive(Clone, Deserialize)]
pub(super) struct GoogleClaims {
    iss: String,
    aud: GoogleAudience,
    sub: String,
    exp: i64,
    iat: i64,
    nonce: String,
    azp: Option<String>,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    name: Option<String>,
}
#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum GoogleAudience {
    Single(String),
    Multiple(Vec<String>),
}
impl GoogleAudience {
    fn only_contains(&self, client_id: &str) -> bool {
        match self {
            Self::Single(value) => value == client_id,
            Self::Multiple(values) => {
                !values.is_empty() && values.iter().all(|value| value == client_id)
            }
        }
    }
}
#[derive(Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}
#[derive(Deserialize)]
struct GoogleJwk {
    kid: String,
    kty: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: String,
    e: String,
}
