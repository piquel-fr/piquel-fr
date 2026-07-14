//! Downstream facade for local token validation and server-side OIDC flows.
#![allow(missing_docs)]

pub use piquel_auth_middleware::{
    AuthMiddleware, AuthenticatedUser, AuthenticationError, ConfigurationError, JwksFetcher,
};
pub use piquel_auth_protocol::{AccessTokenClaims, Audience, ClientId, UserId};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};
use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub revocation_endpoint: Url,
    pub jwks_uri: Url,
    pub end_session_endpoint: Url,
    pub code_challenge_methods_supported: Vec<String>,
}

#[derive(Debug, Error)]
pub enum OidcClientError {
    #[error("OIDC configuration is invalid")]
    InvalidConfiguration,
    #[error("OIDC request failed")]
    Request,
    #[error("authorization callback is invalid")]
    InvalidCallback,
}

#[derive(Clone)]
pub struct OidcClient {
    client: reqwest::Client,
    client_id: ClientId,
    redirect_uri: Url,
    discovery: DiscoveryDocument,
}

impl OidcClient {
    /// Fetches and validates discovery from the exact issuer.
    ///
    /// # Errors
    ///
    /// Fails closed on non-HTTPS configuration, network errors, oversized responses, issuer mismatch, or missing S256 support.
    pub async fn discover(
        issuer: Url,
        client_id: ClientId,
        redirect_uri: Url,
    ) -> Result<Self, OidcClientError> {
        if issuer.scheme() != "https"
            || redirect_uri.scheme() != "https"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return Err(OidcClientError::InvalidConfiguration);
        }
        let client = reqwest::Client::new();
        let url = Url::parse(&format!(
            "{}/.well-known/openid-configuration",
            issuer.as_str().trim_end_matches('/')
        ))
        .map_err(|_| OidcClientError::InvalidConfiguration)?;
        let response = client
            .get(url)
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|_| OidcClientError::Request)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 128 * 1024)
        {
            return Err(OidcClientError::Request);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| OidcClientError::Request)?;
        if bytes.len() > 128 * 1024 {
            return Err(OidcClientError::Request);
        }
        let discovery: DiscoveryDocument =
            serde_json::from_slice(&bytes).map_err(|_| OidcClientError::InvalidConfiguration)?;
        if discovery.issuer.trim_end_matches('/') != issuer.as_str().trim_end_matches('/')
            || !discovery
                .code_challenge_methods_supported
                .iter()
                .any(|method| method == "S256")
            || [
                &discovery.authorization_endpoint,
                &discovery.token_endpoint,
                &discovery.revocation_endpoint,
                &discovery.jwks_uri,
                &discovery.end_session_endpoint,
            ]
            .iter()
            .any(|url| url.scheme() != "https")
        {
            return Err(OidcClientError::InvalidConfiguration);
        }
        Ok(Self {
            client,
            client_id,
            redirect_uri,
            discovery,
        })
    }

    /// Builds an authorization URL and server-side callback context with random state, nonce, and S256 verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the trusted authorization URL cannot be constructed.
    pub fn authorization_url(
        &self,
        scopes: &[&str],
        audience: &Audience,
    ) -> Result<(Url, CallbackContext), OidcClientError> {
        let state = random_b64(32);
        let nonce = random_b64(32);
        let verifier = random_b64(32);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut url = self.discovery.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client_id.as_str())
            .append_pair("redirect_uri", self.redirect_uri.as_str())
            .append_pair("scope", &scopes.join(" "))
            .append_pair("audience", audience.as_str())
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((
            url,
            CallbackContext {
                state,
                nonce,
                verifier,
            },
        ))
    }

    /// Validates callback state and exchanges the one-time code from the server side.
    ///
    /// # Errors
    ///
    /// Returns an error on state mismatch, OAuth error, malformed callback, or failed token exchange.
    pub async fn exchange_callback(
        &self,
        callback: &Url,
        context: CallbackContext,
    ) -> Result<TokenSet, OidcClientError> {
        let mut state = None;
        let mut code = None;
        let mut error = false;
        for (key, value) in callback.query_pairs() {
            match key.as_ref() {
                "state" => state = Some(value.into_owned()),
                "code" => code = Some(value.into_owned()),
                "error" => error = true,
                _ => {}
            }
        }
        if error || state.as_deref() != Some(&context.state) {
            return Err(OidcClientError::InvalidCallback);
        }
        let code = code.ok_or(OidcClientError::InvalidCallback)?;
        let response = self
            .client
            .post(self.discovery.token_endpoint.clone())
            .timeout(Duration::from_secs(5))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.client_id.as_str()),
                ("code", &code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("code_verifier", &context.verifier),
            ])
            .send()
            .await
            .map_err(|_| OidcClientError::Request)?;
        parse_token_response(response).await
    }

    /// Rotates a refresh token. Callers must persist only the returned replacement.
    ///
    /// # Errors
    ///
    /// Returns an error on network or invalid-grant responses.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenSet, OidcClientError> {
        let response = self
            .client
            .post(self.discovery.token_endpoint.clone())
            .timeout(Duration::from_secs(5))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", self.client_id.as_str()),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .map_err(|_| OidcClientError::Request)?;
        parse_token_response(response).await
    }

    /// Builds an exact post-logout redirect request.
    #[must_use]
    pub fn logout_url(&self, post_logout_redirect_uri: &Url, state: &str) -> Url {
        let mut url = self.discovery.end_session_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("client_id", self.client_id.as_str())
            .append_pair(
                "post_logout_redirect_uri",
                post_logout_redirect_uri.as_str(),
            )
            .append_pair("state", state);
        url
    }

    #[must_use]
    pub fn discovery(&self) -> &DiscoveryDocument {
        &self.discovery
    }
}

/// Secrets retained only in a server-side login transaction.
pub struct CallbackContext {
    state: String,
    nonce: String,
    verifier: String,
}
impl CallbackContext {
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}
impl fmt::Debug for CallbackContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallbackContext(REDACTED)")
    }
}

#[derive(Deserialize)]
struct RawTokenSet {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
}
pub struct TokenSet {
    raw: RawTokenSet,
}
impl TokenSet {
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.raw.access_token
    }
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.raw.id_token.as_deref()
    }
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.raw.refresh_token.as_deref()
    }
    #[must_use]
    pub fn expires_in(&self) -> i64 {
        self.raw.expires_in
    }
    #[must_use]
    pub fn scopes(&self) -> &str {
        &self.raw.scope
    }
}
impl fmt::Debug for TokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenSet")
            .field("token_type", &self.raw.token_type)
            .field("expires_in", &self.raw.expires_in)
            .field("scope", &self.raw.scope)
            .field("tokens", &"REDACTED")
            .finish()
    }
}

async fn parse_token_response(response: reqwest::Response) -> Result<TokenSet, OidcClientError> {
    if !response.status().is_success() {
        return Err(OidcClientError::Request);
    }
    let raw: RawTokenSet = response
        .json()
        .await
        .map_err(|_| OidcClientError::Request)?;
    if raw.token_type != "Bearer"
        || raw.access_token.is_empty()
        || raw.expires_in <= 0
        || raw.expires_in > 300
    {
        return Err(OidcClientError::Request);
    }
    Ok(TokenSet { raw })
}
fn random_b64(size: usize) -> String {
    let mut bytes = vec![0; size];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_are_redacted() {
        let context = CallbackContext {
            state: "state".into(),
            nonce: "nonce".into(),
            verifier: "secret".into(),
        };
        assert_eq!(format!("{context:?}"), "CallbackContext(REDACTED)");
    }
}
