//! Authorization Code + PKCE, signed tokens, and rotating opaque refresh tokens.

mod authorize;
mod error;
mod logout;
mod signing;
mod token;

use authorize::{
    authorization_decision, authorization_transaction, authorize, authorize_post, resume,
};
use error::{OAuthCode, OAuthError};
use logout::{logout, logout_start};
pub use signing::Rs256KeyProvider;
use token::{revoke, token, userinfo};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, header},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use piquel_auth_protocol::TokenId;
use piquel_repository::{Database, StoredOidcClient, StoredSession};
use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, str::FromStr, sync::Arc};
use url::Url;

const OPAQUE_SECRET_BYTES: usize = 32;
const ACCESS_TOKEN_SECONDS: i64 = 300;

/// Runnable OIDC application state.
#[derive(Clone)]
pub struct OidcApplication {
    database: Database,
    issuer: String,
    refresh_key: Arc<[u8; 32]>,
    keys: Arc<Rs256KeyProvider>,
}

impl OidcApplication {
    fn hmac(key: &[u8], value: &[u8]) -> Result<[u8; 32], ()> {
        let key = openssl::pkey::PKey::hmac(key).map_err(|_| ())?;
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)
            .map_err(|_| ())?;
        signer.update(value).map_err(|_| ())?;
        signer
            .sign_to_vec()
            .map_err(|_| ())?
            .try_into()
            .map_err(|_| ())
    }

    /// Hashes a high-entropy static client secret. Generate at least 32 random bytes.
    ///
    /// # Errors
    /// Returns an error when the encoded secret is too short or too large.
    pub fn client_secret_hash(secret: &str) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            (43..=512).contains(&secret.len()),
            "OIDC client secrets must encode at least 32 random bytes"
        );
        Ok(Sha256::digest(secret.as_bytes()).to_vec())
    }

    async fn authenticate_client(
        &self,
        headers: &HeaderMap,
        supplied_id: Option<&str>,
    ) -> Result<StoredOidcClient, OAuthError> {
        let basic = headers
            .get(header::AUTHORIZATION)
            .map(|header| {
                let value = header.to_str().map_err(|_| OAuthCode::InvalidClient)?;
                let encoded = value
                    .strip_prefix("Basic ")
                    .ok_or(OAuthCode::InvalidClient)?;
                if encoded.len() > 1024 {
                    return Err(OAuthCode::InvalidClient.into());
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| OAuthCode::InvalidClient)?;
                let decoded = String::from_utf8(bytes).map_err(|_| OAuthCode::InvalidClient)?;
                let (id, secret) = decoded.split_once(':').ok_or(OAuthCode::InvalidClient)?;
                let decode = |value: &str| {
                    url::form_urlencoded::parse(format!("v={value}").as_bytes())
                        .next()
                        .map(|(_, v)| v.into_owned())
                        .ok_or_else(|| OAuthError::from(OAuthCode::InvalidClient))
                };
                Ok::<_, OAuthError>((decode(id)?, decode(secret)?))
            })
            .transpose()?;
        let id = basic
            .as_ref()
            .map(|(id, _)| id.as_str())
            .or(supplied_id)
            .ok_or(OAuthCode::InvalidClient)?;
        if supplied_id.is_some_and(|supplied| supplied != id) {
            return Err(OAuthCode::InvalidClient.into());
        }
        let client = self
            .database
            .oidc()
            .find_client(id)
            .await
            .map_err(OAuthError::internal)?
            .filter(|c| c.enabled)
            .ok_or(OAuthCode::InvalidClient)?;
        match (&client.client_secret_hash, basic) {
            (None, None) => {}
            (Some(expected), Some((_, secret)))
                if openssl::memcmp::eq(expected, &Sha256::digest(secret.as_bytes())) => {}
            _ => return Err(OAuthCode::InvalidClient.into()),
        }
        Ok(client)
    }

    /// Constructs an OIDC endpoint set with an exact HTTPS issuer.
    ///
    /// # Errors
    ///
    /// Returns an error for an insecure issuer or insufficient key material.
    pub(crate) fn new(
        database: Database,
        issuer: &Url,
        secret: &[u8],
        keys: Arc<Rs256KeyProvider>,
    ) -> Result<Self, ()> {
        if issuer.scheme() != "https"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || secret.len() < 32
        {
            return Err(());
        }
        Self::build(database, issuer, secret, keys)
    }

    /// Constructs an HTTP issuer only for an explicit loopback development configuration.
    ///
    /// # Errors
    ///
    /// Returns an error unless the issuer is loopback-only and key material is sufficient.
    pub(crate) fn new_development(
        database: Database,
        issuer: &Url,
        secret: &[u8],
        keys: Arc<Rs256KeyProvider>,
    ) -> Result<Self, ()> {
        let loopback = piquel_configuration::PublicUrl::has_loopback_host(issuer);
        if !loopback
            || !matches!(issuer.scheme(), "http" | "https")
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || secret.len() < 32
        {
            return Err(());
        }
        Self::build(database, issuer, secret, keys)
    }

    fn build(
        database: Database,
        issuer: &Url,
        secret: &[u8],
        keys: Arc<Rs256KeyProvider>,
    ) -> Result<Self, ()> {
        let refresh_key = Self::hmac(secret, b"piquel-refresh-token-digest-v1")?;
        Ok(Self {
            database,
            issuer: issuer.as_str().trim_end_matches('/').into(),
            refresh_key: Arc::new(refresh_key),
            keys,
        })
    }
}

pub(super) fn routes(application: OidcApplication) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth/authorize", get(authorize).post(authorize_post))
        .route("/oauth/authorize/resume", get(resume))
        .route(
            "/oauth/authorize/transaction/{transaction}",
            get(authorization_transaction),
        )
        .route("/oauth/authorize/decision", post(authorization_decision))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/oidc/userinfo", get(userinfo).post(userinfo))
        .route("/oidc/logout", get(logout_start).post(logout))
        .with_state(application)
}

async fn discovery(State(app): State<OidcApplication>) -> Json<Value> {
    let base = &app.issuer;
    Json(json!({
        "issuer":base, "authorization_endpoint":format!("{base}/oauth/authorize"),
        "token_endpoint":format!("{base}/oauth/token"), "revocation_endpoint":format!("{base}/oauth/revoke"),
        "userinfo_endpoint":format!("{base}/oidc/userinfo"), "jwks_uri":format!("{base}/.well-known/jwks.json"),
        "end_session_endpoint":format!("{base}/oidc/logout"), "response_types_supported":["code"],
        "grant_types_supported":["authorization_code","refresh_token"], "code_challenge_methods_supported":["S256"],
        "token_endpoint_auth_methods_supported":["none","client_secret_basic"], "subject_types_supported":["public"], "response_modes_supported":["query"], "claims_supported":["sub","name","preferred_username","email","email_verified","profile_version","auth_time","amr","sid"], "id_token_signing_alg_values_supported":["RS256"],
        "request_uri_parameter_supported":false, "request_parameter_supported":false,
        "scopes_supported":["openid","profile","email","offline_access"]
    }))
}
async fn jwks(State(app): State<OidcApplication>) -> Json<Value> {
    Json(app.keys.jwks())
}

fn require_same_origin(app: &OidcApplication, headers: &HeaderMap) -> Result<(), OAuthError> {
    let origin_matches = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == app.issuer);
    let csrf_header = headers
        .get("x-piquel-csrf")
        .and_then(|value| value.to_str().ok())
        == Some("1");
    let same_origin_fetch = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        == Some("same-origin");
    (origin_matches && (csrf_header || same_origin_fetch))
        .then_some(())
        .ok_or_else(|| OAuthError::from(OAuthCode::InvalidRequest))
}

async fn browser_session(
    database: &Database,
    headers: &HeaderMap,
) -> Result<Option<StoredSession>, OAuthError> {
    let Some(secret) = crate::security::BrowserCookie::Session.read(headers) else {
        return Ok(None);
    };
    database
        .sessions()
        .find_active_by_browser_secret(&secret.digest())
        .await
        .map_err(OAuthError::internal)
}

fn parse_scopes(value: &str) -> Option<BTreeSet<String>> {
    let scopes: BTreeSet<_> = value.split_ascii_whitespace().map(str::to_owned).collect();
    (!scopes.is_empty() && scopes.len() <= 16).then_some(scopes)
}
fn new_opaque(prefix: &str) -> (String, TokenId, [u8; OPAQUE_SECRET_BYTES]) {
    let id = TokenId::new();
    let mut secret = [0; OPAQUE_SECRET_BYTES];
    OsRng.fill_bytes(&mut secret);
    (
        format!("{prefix}_{id}.{}", URL_SAFE_NO_PAD.encode(secret)),
        id,
        secret,
    )
}
fn parse_opaque(
    prefix: &str,
    value: &str,
) -> Result<(TokenId, [u8; OPAQUE_SECRET_BYTES]), OAuthError> {
    if value.len() > 160 {
        return Err(OAuthCode::InvalidGrant.into());
    }
    let rest = value
        .strip_prefix(&format!("{prefix}_"))
        .ok_or(OAuthCode::InvalidGrant)?;
    let (id, secret) = rest.split_once('.').ok_or(OAuthCode::InvalidGrant)?;
    let id = TokenId::from_str(id).map_err(|_| OAuthCode::InvalidGrant)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| OAuthCode::InvalidGrant)?;
    let secret: [u8; OPAQUE_SECRET_BYTES] =
        decoded.try_into().map_err(|_| OAuthCode::InvalidGrant)?;
    Ok((id, secret))
}
fn keyed_digest(key: &[u8], secret: &[u8]) -> Result<[u8; 32], OAuthError> {
    OidcApplication::hmac(key, secret).map_err(|()| OAuthError::from(OAuthCode::ServerError))
}

fn validate_pkce_s256(verifier: &str, challenge: &str) -> Result<(), ()> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(());
    }
    (URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge)
        .then_some(())
        .ok_or(())
}

#[cfg(test)]
mod tests;
