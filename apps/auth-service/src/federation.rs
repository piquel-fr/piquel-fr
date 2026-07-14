//! Explicit GitHub OAuth and Google OIDC login adapters.

use crate::email::normalize;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use piquel_auth_protocol::{AccountStatus, AuthenticationMethod, SessionId, TokenId, UserId};
use piquel_configuration::SecretReference;
use piquel_repository::{
    AppendAuditEvent, AppendInternalEvent, Database, DatabaseError, InsertExternalIdentity,
    InsertFederationTransaction, InsertSession, InsertUser, InsertVerifiedEmail,
};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt::Write, sync::Arc, time::Duration as StdDuration};
use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    GitHub,
    Google,
}
impl Provider {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "github" => Some(Self::GitHub),
            "google" => Some(Self::Google),
            _ => None,
        }
    }
    const fn name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
        }
    }
    const fn issuer(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::Google => "https://accounts.google.com",
        }
    }
    const fn authorization_endpoint(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com/login/oauth/authorize",
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth",
        }
    }
    const fn token_endpoint(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com/login/oauth/access_token",
            Self::Google => "https://oauth2.googleapis.com/token",
        }
    }
}

/// Secret-reference configuration for one approved provider.
#[derive(Clone, Debug)]
pub struct ProviderConfiguration {
    /// Public provider OAuth client identifier.
    pub client_id: String,
    /// Reference to the provider secret; never the secret value.
    pub client_secret: SecretReference,
}
/// Runnable two-provider federation state.
#[derive(Clone)]
pub struct FederationApplication {
    database: Database,
    base_url: Url,
    providers: Arc<HashMap<&'static str, ProviderConfiguration>>,
    client: reqwest::Client,
}
impl FederationApplication {
    /// Constructs the exact GitHub and Google provider set.
    ///
    /// # Errors
    ///
    /// Returns an error unless the callback base is HTTPS and both client IDs are present.
    pub fn new(
        database: Database,
        base_url: &Url,
        github: ProviderConfiguration,
        google: ProviderConfiguration,
    ) -> Result<Self, FederationConfigurationError> {
        if base_url.scheme() != "https"
            || github.client_id.is_empty()
            || google.client_id.is_empty()
        {
            return Err(FederationConfigurationError);
        }
        Ok(Self {
            database,
            base_url: base_url.clone(),
            providers: Arc::new(HashMap::from([("github", github), ("google", google)])),
            client: reqwest::Client::new(),
        })
    }
    /// Constructs loopback-only HTTP callbacks for explicit development.
    ///
    /// # Errors
    ///
    /// Returns an error unless the base URL is loopback-only and both client IDs are present.
    pub fn new_development(
        database: Database,
        base_url: &Url,
        github: ProviderConfiguration,
        google: ProviderConfiguration,
    ) -> Result<Self, FederationConfigurationError> {
        let loopback = base_url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !loopback {
            return Err(FederationConfigurationError);
        }
        let app = Self {
            database,
            base_url: base_url.clone(),
            providers: Arc::new(HashMap::from([("github", github), ("google", google)])),
            client: reqwest::Client::new(),
        };
        if app
            .providers
            .values()
            .any(|provider| provider.client_id.is_empty())
        {
            return Err(FederationConfigurationError);
        }
        Ok(app)
    }
}
#[derive(Debug, Error)]
#[error("invalid federation configuration")]
pub struct FederationConfigurationError;
pub(super) fn routes(app: FederationApplication) -> Router {
    Router::new()
        .route("/login/{provider}", get(start))
        .route("/login/{provider}/callback", get(callback))
        .with_state(app)
}

async fn start(
    State(app): State<FederationApplication>,
    Path(provider): Path<String>,
) -> Result<Response, ApiError> {
    let provider = Provider::parse(&provider).ok_or(ApiError)?;
    let config = app.providers.get(provider.name()).ok_or(ApiError)?;
    let state = random();
    let nonce = random();
    let verifier = random();
    let browser = random();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    app.database
        .federation()
        .insert_transaction(&InsertFederationTransaction {
            id: TokenId::new(),
            provider: provider.name().into(),
            state_digest: Sha256::digest(state.as_bytes()).to_vec(),
            browser_digest: Sha256::digest(browser.as_bytes()).to_vec(),
            nonce: nonce.clone(),
            pkce_verifier: verifier,
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .map_err(|_| ApiError)?;
    let callback = format!(
        "{}/login/{}/callback",
        app.base_url.as_str().trim_end_matches('/'),
        provider.name()
    );
    let mut url = Url::parse(provider.authorization_endpoint()).map_err(|_| ApiError)?;
    let scope = match provider {
        Provider::GitHub => "read:user user:email",
        Provider::Google => "openid email profile",
    };
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &callback)
        .append_pair("response_type", "code")
        .append_pair("scope", scope)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    if provider == Provider::Google {
        url.query_pairs_mut().append_pair("nonce", &nonce);
    }
    let mut response = Redirect::to(url.as_str()).into_response();
    response.headers_mut().insert(header::SET_COOKIE,HeaderValue::from_str(&format!("__Host-piquel_federation={browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")).map_err(|_|ApiError)?);
    Ok(response)
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}
async fn callback(
    State(app): State<FederationApplication>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    if query.error.is_some() {
        return Err(ApiError);
    }
    let provider = Provider::parse(&provider).ok_or(ApiError)?;
    let code = query
        .code
        .filter(|value| !value.is_empty() && value.len() <= 2048)
        .ok_or(ApiError)?;
    let state = query
        .state
        .filter(|value| value.len() <= 256)
        .ok_or(ApiError)?;
    let browser = cookie(&headers, "__Host-piquel_federation").ok_or(ApiError)?;
    let transaction = app
        .database
        .federation()
        .consume_transaction(
            provider.name(),
            &Sha256::digest(state.as_bytes()),
            &Sha256::digest(browser.as_bytes()),
        )
        .await
        .map_err(|_| ApiError)?;
    let identity = exchange(
        &app,
        provider,
        &code,
        &transaction.pkce_verifier,
        &transaction.nonce,
    )
    .await?;
    let user_id = link_identity(&app.database, provider, &identity).await?;
    let cookie = create_session(&app.database, user_id).await?;
    let mut destination = app.base_url.clone();
    destination.set_path("/");
    destination.set_query(None);
    let mut response = Redirect::to(destination.as_str()).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| ApiError)?,
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-piquel_federation=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        ),
    );
    Ok(response)
}

struct VerifiedIdentity {
    issuer: &'static str,
    subject: String,
    email: String,
    display_name: String,
}
async fn exchange(
    app: &FederationApplication,
    provider: Provider,
    code: &str,
    verifier: &str,
    nonce: &str,
) -> Result<VerifiedIdentity, ApiError> {
    let config = app.providers.get(provider.name()).ok_or(ApiError)?;
    let secret = config.client_secret.resolve().map_err(|_| ApiError)?;
    let secret = std::str::from_utf8(secret.expose_secret()).map_err(|_| ApiError)?;
    let callback = format!(
        "{}/login/{}/callback",
        app.base_url.as_str().trim_end_matches('/'),
        provider.name()
    );
    let response = app
        .client
        .post(provider.token_endpoint())
        .timeout(StdDuration::from_secs(5))
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
        .map_err(|_| ApiError)?;
    if !response.status().is_success() {
        return Err(ApiError);
    }
    match provider {
        Provider::GitHub => github_identity(app, response).await,
        Provider::Google => google_identity(app, response, &config.client_id, nonce).await,
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
async fn github_identity(
    app: &FederationApplication,
    response: reqwest::Response,
) -> Result<VerifiedIdentity, ApiError> {
    let token: GithubToken = response.json().await.map_err(|_| ApiError)?;
    if token.access_token.is_empty() {
        return Err(ApiError);
    }
    let auth = format!("Bearer {}", token.access_token);
    let user: GithubUser = app
        .client
        .get("https://api.github.com/user")
        .timeout(StdDuration::from_secs(5))
        .header(header::AUTHORIZATION, &auth)
        .header(header::USER_AGENT, "piquel-auth")
        .send()
        .await
        .map_err(|_| ApiError)?
        .error_for_status()
        .map_err(|_| ApiError)?
        .json()
        .await
        .map_err(|_| ApiError)?;
    let emails: Vec<GithubEmail> = app
        .client
        .get("https://api.github.com/user/emails")
        .timeout(StdDuration::from_secs(5))
        .header(header::AUTHORIZATION, auth)
        .header(header::USER_AGENT, "piquel-auth")
        .send()
        .await
        .map_err(|_| ApiError)?
        .error_for_status()
        .map_err(|_| ApiError)?
        .json()
        .await
        .map_err(|_| ApiError)?;
    let email = emails
        .iter()
        .find(|email| email.verified && email.primary)
        .or_else(|| emails.iter().find(|email| email.verified))
        .ok_or(ApiError)?
        .email
        .clone();
    Ok(VerifiedIdentity {
        issuer: Provider::GitHub.issuer(),
        subject: user.id.to_string(),
        email,
        display_name: user.name.unwrap_or(user.login),
    })
}

#[derive(Deserialize)]
struct GoogleToken {
    id_token: String,
}
#[derive(Deserialize)]
struct GoogleClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    nonce: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
}
#[derive(Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}
#[derive(Deserialize)]
struct GoogleJwk {
    kid: String,
    kty: String,
    alg: String,
    n: String,
    e: String,
}
async fn google_identity(
    app: &FederationApplication,
    response: reqwest::Response,
    client_id: &str,
    nonce: &str,
) -> Result<VerifiedIdentity, ApiError> {
    let token: GoogleToken = response.json().await.map_err(|_| ApiError)?;
    if token.id_token.len() > 8192 {
        return Err(ApiError);
    }
    let header = decode_header(&token.id_token).map_err(|_| ApiError)?;
    if header.alg != Algorithm::RS256 {
        return Err(ApiError);
    }
    let kid = header.kid.ok_or(ApiError)?;
    let jwks: GoogleJwks = app
        .client
        .get("https://www.googleapis.com/oauth2/v3/certs")
        .timeout(StdDuration::from_secs(3))
        .send()
        .await
        .map_err(|_| ApiError)?
        .error_for_status()
        .map_err(|_| ApiError)?
        .json()
        .await
        .map_err(|_| ApiError)?;
    let jwk = jwks
        .keys
        .into_iter()
        .find(|key| key.kid == kid && key.kty == "RSA" && key.alg == "RS256")
        .ok_or(ApiError)?;
    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|_| ApiError)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[Provider::Google.issuer()]);
    validation.leeway = 30;
    let claims = decode::<GoogleClaims>(&token.id_token, &key, &validation)
        .map_err(|_| ApiError)?
        .claims;
    if claims.iss != Provider::Google.issuer()
        || claims.aud != client_id
        || claims.nonce != nonce
        || !claims.email_verified
        || claims.sub.is_empty()
        || claims.exp <= Utc::now().timestamp()
    {
        return Err(ApiError);
    }
    Ok(VerifiedIdentity {
        issuer: Provider::Google.issuer(),
        subject: claims.sub,
        email: claims.email,
        display_name: claims.name.unwrap_or_else(|| "Google user".into()),
    })
}

#[allow(clippy::too_many_lines)]
async fn link_identity(
    database: &Database,
    provider: Provider,
    identity: &VerifiedIdentity,
) -> Result<UserId, ApiError> {
    if identity.issuer != provider.issuer()
        || identity.subject.is_empty()
        || identity.subject.len() > 255
    {
        return Err(ApiError);
    }
    if let Some(existing) = database
        .federation()
        .find_active(identity.issuer, &identity.subject)
        .await
        .map_err(|_| ApiError)?
    {
        let user = database
            .users()
            .find_by_id(existing.user_id)
            .await
            .map_err(|_| ApiError)?
            .ok_or(ApiError)?;
        if user.status != AccountStatus::Active {
            return Err(ApiError);
        }
        database
            .federation()
            .record_login(existing.id)
            .await
            .map_err(|_| ApiError)?;
        return Ok(user.id);
    }
    let email = normalize(&identity.email).map_err(|()| ApiError)?;
    let mut tx = database.begin().await.map_err(|_| ApiError)?;
    let users = tx
        .emails()
        .find_users_by_verified_email(email.as_str())
        .await
        .map_err(|_| ApiError)?;
    let user_id = if users.is_empty() {
        let id = UserId::new();
        let suffix = &hex_digest(identity.subject.as_bytes())[..12];
        let username = format!("{}_{}", provider.name(), suffix);
        tx.users()
            .insert(&InsertUser {
                id,
                username,
                display_name: identity.display_name.chars().take(80).collect(),
            })
            .await
            .map_err(|_| ApiError)?;
        tx.emails()
            .insert_verified(&InsertVerifiedEmail {
                id: TokenId::new(),
                user_id: id,
                normalized_email: email.as_str().into(),
                is_primary: true,
                verified_at: Utc::now(),
            })
            .await
            .map_err(|_| ApiError)?;
        id
    } else if users.len() == 1 && users[0].status == AccountStatus::Active {
        users[0].id
    } else {
        return Err(ApiError);
    };
    match tx
        .federation()
        .insert_identity(&InsertExternalIdentity {
            id: TokenId::new(),
            user_id,
            provider: provider.name().into(),
            issuer: identity.issuer.into(),
            subject: identity.subject.clone(),
            linked_email: email.as_str().into(),
        })
        .await
    {
        Ok(_) => {}
        Err(DatabaseError::Conflict) => {
            tx.rollback().await.map_err(|_| ApiError)?;
            return database
                .federation()
                .find_active(identity.issuer, &identity.subject)
                .await
                .map_err(|_| ApiError)?
                .map(|mapping| mapping.user_id)
                .ok_or(ApiError);
        }
        Err(_) => return Err(ApiError),
    }
    tx.audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(user_id),
            action: "federation.link".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({"provider":provider.name()}),
        })
        .await
        .map_err(|_| ApiError)?;
    tx.internal_events()
        .append(&AppendInternalEvent {
            id: TokenId::new(),
            aggregate_type: "user".into(),
            aggregate_id: user_id,
            event_type: "federation.linked".into(),
            schema_version: 1,
            payload: serde_json::json!({"provider":provider.name()}),
        })
        .await
        .map_err(|_| ApiError)?;
    tx.commit().await.map_err(|_| ApiError)?;
    Ok(user_id)
}

async fn create_session(database: &Database, user_id: UserId) -> Result<String, ApiError> {
    let mut tx = database.begin().await.map_err(|_| ApiError)?;
    let id = SessionId::new();
    let now = Utc::now();
    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    tx.sessions()
        .insert(&InsertSession {
            id,
            user_id,
            authentication_methods: vec![AuthenticationMethod::Federation],
            authenticated_at: now,
            expires_at: now + Duration::days(30),
            user_agent_family: None,
        })
        .await
        .map_err(|_| ApiError)?;
    tx.sessions()
        .insert_browser_secret(id, &Sha256::digest(secret))
        .await
        .map_err(|_| ApiError)?;
    tx.audit_events()
        .append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(user_id),
            action: "federation.login".into(),
            outcome: "success".into(),
            request_metadata: serde_json::json!({}),
        })
        .await
        .map_err(|_| ApiError)?;
    tx.commit().await.map_err(|_| ApiError)?;
    Ok(format!(
        "__Host-piquel_session={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000",
        URL_SAFE_NO_PAD.encode(secret)
    ))
}
fn random() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}=")).map(str::to_owned))
}
fn hex_digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}
#[derive(Debug, Error)]
#[error("social authentication failed")]
struct ApiError;
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"social_authentication_failed"})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn providers_are_explicit() {
        assert_eq!(Provider::parse("github"), Some(Provider::GitHub));
        assert_eq!(Provider::parse("google"), Some(Provider::Google));
        assert_eq!(Provider::parse("other"), None);
    }
    #[test]
    fn callback_secrets_are_bounded() {
        assert_eq!(random().len(), 43);
        assert!(normalize("Ada+work@Example.COM").is_ok());
    }
}
