//! Authorization Code + PKCE, ES256 tokens, and rotating opaque refresh tokens.

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use p256::{
    ecdsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    },
    pkcs8::DecodePrivateKey,
};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use piquel_repository::{
    Database, InsertAuthorizationCode, InsertRefreshFamily, InsertRefreshToken,
    RefreshRotationError, StoredSession,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, str::FromStr, sync::Arc};
use thiserror::Error;
use url::Url;

type HmacSha256 = Hmac<Sha256>;
const OPAQUE_SECRET_BYTES: usize = 32;
const ACCESS_TOKEN_SECONDS: i64 = 300;

/// Supplies a stable active ES256 key and its public JWK.
pub trait KeyProvider: Send + Sync {
    fn sign(&self, token_type: &str, claims: &Value) -> Result<String, ()>;
    fn jwks(&self) -> Value;
    fn verify_access(&self, token: &str, issuer: &str) -> Result<Value, ()>;
}

/// Local PEM-backed key provider. Production callers resolve the PEM through a secret reference.
pub struct Es256KeyProvider {
    kid: String,
    signing: SigningKey,
}

impl Es256KeyProvider {
    /// Loads a PKCS#8 PEM signing key.
    ///
    /// # Errors
    ///
    /// Returns an error when the PEM is not a P-256 PKCS#8 private key.
    #[allow(clippy::result_unit_err)]
    pub fn from_pkcs8_pem(kid: impl Into<String>, pem: &str) -> Result<Self, ()> {
        Ok(Self {
            kid: kid.into(),
            signing: SigningKey::from_pkcs8_pem(pem).map_err(|_| ())?,
        })
    }

    /// Generates an ephemeral key for explicit development and tests only.
    #[must_use]
    pub fn generate_for_development(kid: impl Into<String>) -> Self {
        Self {
            kid: kid.into(),
            signing: SigningKey::random(&mut OsRng),
        }
    }
}

impl KeyProvider for Es256KeyProvider {
    fn sign(&self, token_type: &str, claims: &Value) -> Result<String, ()> {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg":"ES256", "kid":self.kid, "typ":token_type
            }))
            .map_err(|_| ())?,
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| ())?);
        let signing_input = format!("{header}.{payload}");
        let signature: Signature = self.signing.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    fn jwks(&self) -> Value {
        let point = self.signing.verifying_key().to_encoded_point(false);
        json!({"keys":[{
            "kty":"EC", "crv":"P-256", "use":"sig", "alg":"ES256", "kid":self.kid,
            "x":URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point")),
            "y":URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point"))
        }]})
    }

    fn verify_access(&self, token: &str, issuer: &str) -> Result<Value, ()> {
        if token.len() > 8192 {
            return Err(());
        }
        let mut pieces = token.split('.');
        let header_part = pieces.next().ok_or(())?;
        let claims_part = pieces.next().ok_or(())?;
        let signature_part = pieces.next().ok_or(())?;
        if pieces.next().is_some() {
            return Err(());
        }
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_part).map_err(|_| ())?)
                .map_err(|_| ())?;
        if header.get("alg") != Some(&json!("ES256"))
            || header.get("kid") != Some(&json!(self.kid))
            || header.get("typ") != Some(&json!("at+jwt"))
        {
            return Err(());
        }
        let signature = URL_SAFE_NO_PAD.decode(signature_part).map_err(|_| ())?;
        let signature = Signature::from_slice(&signature).map_err(|_| ())?;
        self.signing
            .verifying_key()
            .verify(
                format!("{header_part}.{claims_part}").as_bytes(),
                &signature,
            )
            .map_err(|_| ())?;
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_part).map_err(|_| ())?)
                .map_err(|_| ())?;
        let now = Utc::now().timestamp();
        if claims.get("iss") != Some(&json!(issuer))
            || claims
                .get("exp")
                .and_then(Value::as_i64)
                .is_none_or(|exp| exp <= now)
            || claims
                .get("iat")
                .and_then(Value::as_i64)
                .is_none_or(|iat| iat > now + 30)
        {
            return Err(());
        }
        Ok(claims)
    }
}

/// Runnable OIDC application state.
#[derive(Clone)]
pub struct OidcApplication {
    database: Database,
    issuer: String,
    refresh_key: Arc<[u8; 32]>,
    keys: Arc<dyn KeyProvider>,
}

impl OidcApplication {
    /// Constructs an OIDC endpoint set with an exact HTTPS issuer.
    ///
    /// # Errors
    ///
    /// Returns an error for an insecure issuer or insufficient key material.
    #[allow(clippy::result_unit_err)]
    pub fn new(
        database: Database,
        issuer: &Url,
        secret: &[u8],
        keys: Arc<dyn KeyProvider>,
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
    #[allow(clippy::result_unit_err)]
    pub fn new_development(
        database: Database,
        issuer: &Url,
        secret: &[u8],
        keys: Arc<dyn KeyProvider>,
    ) -> Result<Self, ()> {
        let loopback = issuer.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
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
        keys: Arc<dyn KeyProvider>,
    ) -> Result<Self, ()> {
        let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| ())?;
        mac.update(b"piquel-refresh-token-digest-v1");
        let refresh_key = mac.finalize().into_bytes().into();
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
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/oidc/userinfo", get(userinfo))
        .route("/oidc/logout", get(logout))
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
        "token_endpoint_auth_methods_supported":["none"], "id_token_signing_alg_values_supported":["ES256"],
        "scopes_supported":["openid","profile","email","offline_access"]
    }))
}
async fn jwks(State(app): State<OidcApplication>) -> Json<Value> {
    Json(app.keys.jwks())
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    audience: String,
    prompt: Option<String>,
    max_age: Option<i64>,
}

async fn authorize(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Redirect, ApiError> {
    let client = app
        .database
        .oidc()
        .find_client(&q.client_id)
        .await
        .map_err(|_| ApiError::server())?
        .ok_or_else(ApiError::request)?;
    if !client.enabled || !client.redirect_uris.contains(&q.redirect_uri) {
        return Err(ApiError::request());
    }
    let redirect = Url::parse(&q.redirect_uri).map_err(|_| ApiError::request())?;
    let fail = |error: &str| redirect_error(&redirect, error, &q.state);
    let challenge_valid = URL_SAFE_NO_PAD
        .decode(&q.code_challenge)
        .is_ok_and(|value| value.len() == 32);
    if q.response_type != "code"
        || q.state.is_empty()
        || q.state.len() > 512
        || q.code_challenge_method != "S256"
        || !challenge_valid
    {
        return Err(fail("invalid_request"));
    }
    let scopes = parse_scopes(&q.scope).ok_or_else(|| fail("invalid_scope"))?;
    if !scopes
        .iter()
        .all(|scope| client.allowed_scopes.contains(scope))
    {
        return Err(fail("invalid_scope"));
    }
    if !client.allowed_audiences.contains(&q.audience) {
        return Err(fail("invalid_target"));
    }
    if scopes.contains("openid") && q.nonce.as_deref().is_none_or(str::is_empty) {
        return Err(fail("invalid_request"));
    }
    if q.prompt
        .as_deref()
        .is_some_and(|value| !matches!(value, "none" | "login"))
    {
        return Err(fail("invalid_request"));
    }
    let session = browser_session(&app.database, &headers)
        .await
        .ok_or_else(|| fail("login_required"))?;
    if q.prompt.as_deref() == Some("login")
        || q.max_age.is_some_and(|age| {
            age < 0
                || Utc::now()
                    .signed_duration_since(session.authenticated_at)
                    .num_seconds()
                    > age
        })
    {
        return Err(fail("login_required"));
    }
    let (code, id, secret) = new_opaque("pac_v1");
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    app.database
        .oidc()
        .insert_code(&InsertAuthorizationCode {
            id,
            secret_digest: digest.to_vec(),
            client_id: q.client_id,
            user_id: session.user_id,
            session_id: session.id,
            redirect_uri: q.redirect_uri,
            pkce_challenge: q.code_challenge,
            nonce: q.nonce,
            scopes: scopes.into_iter().collect(),
            audience: q.audience,
            expires_at: Utc::now() + Duration::minutes(2),
        })
        .await
        .map_err(|_| ApiError::server())?;
    let mut location = redirect;
    location
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &q.state);
    Ok(Redirect::to(location.as_str()))
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    client_id: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}
#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

async fn token(
    State(app): State<OidcApplication>,
    Form(form): Form<TokenForm>,
) -> Result<Json<TokenResponse>, ApiError> {
    match form.grant_type.as_str() {
        "authorization_code" => exchange_code(&app, form).await.map(Json),
        "refresh_token" => rotate_refresh(&app, form).await.map(Json),
        _ => Err(ApiError::oauth("unsupported_grant_type")),
    }
}

async fn exchange_code(app: &OidcApplication, form: TokenForm) -> Result<TokenResponse, ApiError> {
    let (id, secret) = parse_opaque(
        "pac_v1",
        form.code
            .as_deref()
            .ok_or_else(|| ApiError::oauth("invalid_grant"))?,
    )?;
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    let mut tx = app.database.begin().await.map_err(|_| ApiError::server())?;
    let code = tx
        .oidc()
        .consume_code(id, &digest)
        .await
        .map_err(|_| ApiError::oauth("invalid_grant"))?;
    if code.client_id != form.client_id
        || form.redirect_uri.as_deref() != Some(&code.redirect_uri)
        || validate_pkce_s256(
            form.code_verifier.as_deref().unwrap_or_default(),
            &code.pkce_challenge,
        )
        .is_err()
    {
        return Err(ApiError::oauth("invalid_grant"));
    }
    let user = tx
        .users()
        .find_by_id(code.user_id)
        .await
        .map_err(|_| ApiError::server())?
        .ok_or_else(|| ApiError::oauth("invalid_grant"))?;
    let session = tx
        .sessions()
        .find_by_id(code.session_id)
        .await
        .map_err(|_| ApiError::server())?
        .ok_or_else(|| ApiError::oauth("invalid_grant"))?;
    let client = tx
        .oidc()
        .find_client(&form.client_id)
        .await
        .map_err(|_| ApiError::server())?
        .ok_or_else(|| ApiError::oauth("invalid_client"))?;
    let tokens = issue_tokens(
        app,
        &client.id,
        &code.audience,
        &code.scopes,
        code.nonce.as_deref(),
        &user,
        &session,
    )?;
    let refresh =
        if client.allow_refresh && code.scopes.iter().any(|scope| scope == "offline_access") {
            Some(
                create_refresh(
                    &mut tx,
                    app,
                    code.user_id,
                    code.session_id,
                    client.id,
                    code.audience,
                    code.scopes,
                )
                .await?,
            )
        } else {
            None
        };
    tx.commit().await.map_err(|_| ApiError::server())?;
    Ok(TokenResponse {
        refresh_token: refresh,
        ..tokens
    })
}

async fn rotate_refresh(app: &OidcApplication, form: TokenForm) -> Result<TokenResponse, ApiError> {
    let (id, secret) = parse_opaque(
        "prt_v1",
        form.refresh_token
            .as_deref()
            .ok_or_else(|| ApiError::oauth("invalid_grant"))?,
    )?;
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    let mut tx = app.database.begin().await.map_err(|_| ApiError::server())?;
    let rotated = match tx.tokens().consume_for_rotation(id, &digest).await {
        Ok(value) => value,
        Err(RefreshRotationError::Replay) => {
            tx.commit().await.map_err(|_| ApiError::server())?;
            return Err(ApiError::oauth("invalid_grant"));
        }
        Err(RefreshRotationError::Invalid) => return Err(ApiError::oauth("invalid_grant")),
    };
    if rotated.client_id != form.client_id {
        return Err(ApiError::oauth("invalid_grant"));
    }
    let user = tx
        .users()
        .find_by_id(rotated.user_id)
        .await
        .map_err(|_| ApiError::server())?
        .ok_or_else(|| ApiError::oauth("invalid_grant"))?;
    let session = tx
        .sessions()
        .find_by_id(rotated.session_id)
        .await
        .map_err(|_| ApiError::server())?
        .ok_or_else(|| ApiError::oauth("invalid_grant"))?;
    let (raw, new_id, new_secret) = new_opaque("prt_v1");
    let new_digest = keyed_digest(app.refresh_key.as_ref(), &new_secret)?;
    tx.tokens()
        .insert_token(&InsertRefreshToken {
            id: new_id,
            family_id: rotated.family_id,
            secret_digest: new_digest.to_vec(),
            expires_at: Utc::now() + Duration::days(30),
        })
        .await
        .map_err(|_| ApiError::server())?;
    let mut tokens = issue_tokens(
        app,
        &rotated.client_id,
        &rotated.audience,
        &rotated.scopes,
        None,
        &user,
        &session,
    )?;
    tokens.refresh_token = Some(raw);
    tx.commit().await.map_err(|_| ApiError::server())?;
    Ok(tokens)
}

async fn create_refresh(
    tx: &mut piquel_repository::DatabaseTransaction<'_>,
    app: &OidcApplication,
    user_id: UserId,
    session_id: SessionId,
    client_id: String,
    audience: String,
    scopes: Vec<String>,
) -> Result<String, ApiError> {
    let family_id = TokenId::new();
    let (raw, id, secret) = new_opaque("prt_v1");
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    tx.tokens()
        .insert_family(
            &InsertRefreshFamily {
                id: family_id,
                user_id,
                client_id,
                session_id,
                audience,
                scopes,
            },
            &InsertRefreshToken {
                id,
                family_id,
                secret_digest: digest.to_vec(),
                expires_at: Utc::now() + Duration::days(30),
            },
        )
        .await
        .map_err(|_| ApiError::server())?;
    Ok(raw)
}

fn issue_tokens(
    app: &OidcApplication,
    client: &str,
    audience: &str,
    scopes: &[String],
    nonce: Option<&str>,
    user: &piquel_repository::StoredUser,
    session: &StoredSession,
) -> Result<TokenResponse, ApiError> {
    let now = Utc::now().timestamp();
    let amr = &session.authentication_methods;
    let access=app.keys.sign("at+jwt",&json!({"iss":app.issuer,"sub":user.id,"aud":audience,"client_id":client,"sid":session.id,"jti":TokenId::new(),"profile_version":user.profile_version,"preferred_username":user.username,"name":user.display_name,"amr":amr,"auth_time":session.authenticated_at.timestamp(),"scope":scopes.join(" "),"iat":now,"exp":now+ACCESS_TOKEN_SECONDS})).map_err(|()|ApiError::server())?;
    let id_token = if scopes.iter().any(|s| s == "openid") {
        Some(app.keys.sign("JWT",&json!({"iss":app.issuer,"sub":user.id,"aud":client,"sid":session.id,"nonce":nonce,"profile_version":user.profile_version,"preferred_username":user.username,"name":user.display_name,"auth_time":session.authenticated_at.timestamp(),"amr":amr,"iat":now,"exp":now+ACCESS_TOKEN_SECONDS})).map_err(|()|ApiError::server())?)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_SECONDS,
        scope: scopes.join(" "),
        id_token,
        refresh_token: None,
    })
}

#[derive(Deserialize)]
struct RevokeForm {
    token: String,
}
async fn revoke(
    State(app): State<OidcApplication>,
    Form(form): Form<RevokeForm>,
) -> Result<StatusCode, ApiError> {
    if let Ok((id, secret)) = parse_opaque("prt_v1", &form.token) {
        let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
        let mut tx = app.database.begin().await.map_err(|_| ApiError::server())?;
        tx.tokens()
            .revoke_family_for_token(id, &digest)
            .await
            .map_err(|_| ApiError::server())?;
        tx.commit().await.map_err(|_| ApiError::server())?;
    }
    Ok(StatusCode::OK)
}

async fn userinfo(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)?;
    let claims = app
        .keys
        .verify_access(token, &app.issuer)
        .map_err(|()| ApiError::unauthorized())?;
    let scopes: BTreeSet<_> = claims
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .split_ascii_whitespace()
        .collect();
    if !scopes.contains("openid") {
        return Err(ApiError::unauthorized());
    }
    let mut response = json!({"sub":claims.get("sub")});
    if scopes.contains("profile") {
        response["preferred_username"] = claims
            .get("preferred_username")
            .cloned()
            .unwrap_or(Value::Null);
        response["name"] = claims.get("name").cloned().unwrap_or(Value::Null);
        response["profile_version"] = claims
            .get("profile_version")
            .cloned()
            .unwrap_or(Value::Null);
    }
    Ok(Json(response))
}

#[derive(Deserialize)]
struct LogoutQuery {
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}
async fn logout(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    Query(q): Query<LogoutQuery>,
) -> Result<Response, ApiError> {
    if let Some(session) = browser_session(&app.database, &headers).await {
        app.database
            .sessions()
            .revoke(session.id)
            .await
            .map_err(|_| ApiError::server())?;
    }
    if let (Some(client_id), Some(uri)) = (q.client_id, q.post_logout_redirect_uri) {
        let client = app
            .database
            .oidc()
            .find_client(&client_id)
            .await
            .map_err(|_| ApiError::server())?
            .ok_or_else(ApiError::request)?;
        if !client.post_logout_uris.contains(&uri) {
            return Err(ApiError::request());
        }
        let mut url = Url::parse(&uri).map_err(|_| ApiError::request())?;
        if let Some(state) = q.state {
            url.query_pairs_mut().append_pair("state", &state);
        }
        return Ok(Redirect::to(url.as_str()).into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn browser_session(database: &Database, headers: &HeaderMap) -> Option<StoredSession> {
    let raw = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("__Host-piquel_session="))?;
    let secret = URL_SAFE_NO_PAD.decode(raw).ok()?;
    if secret.len() != OPAQUE_SECRET_BYTES {
        return None;
    }
    let digest = Sha256::digest(secret);
    database
        .sessions()
        .find_active_by_browser_secret(&digest)
        .await
        .ok()
        .flatten()
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
) -> Result<(TokenId, [u8; OPAQUE_SECRET_BYTES]), ApiError> {
    if value.len() > 160 {
        return Err(ApiError::oauth("invalid_grant"));
    }
    let rest = value
        .strip_prefix(&format!("{prefix}_"))
        .ok_or_else(|| ApiError::oauth("invalid_grant"))?;
    let (id, secret) = rest
        .split_once('.')
        .ok_or_else(|| ApiError::oauth("invalid_grant"))?;
    let id = TokenId::from_str(id).map_err(|_| ApiError::oauth("invalid_grant"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| ApiError::oauth("invalid_grant"))?;
    let secret: [u8; OPAQUE_SECRET_BYTES] = decoded
        .try_into()
        .map_err(|_| ApiError::oauth("invalid_grant"))?;
    Ok((id, secret))
}
fn keyed_digest(key: &[u8], secret: &[u8]) -> Result<[u8; 32], ApiError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ApiError::server())?;
    mac.update(secret);
    Ok(mac.finalize().into_bytes().into())
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
fn redirect_error(base: &Url, error: &str, state: &str) -> ApiError {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("error", error)
        .append_pair("state", state);
    ApiError(
        StatusCode::FOUND,
        json!({"error":error}),
        Some(url.to_string()),
    )
}

#[derive(Debug, Error)]
#[error("OIDC request failed")]
struct ApiError(StatusCode, Value, Option<String>);
impl ApiError {
    fn request() -> Self {
        Self(
            StatusCode::BAD_REQUEST,
            json!({"error":"invalid_request"}),
            None,
        )
    }
    fn oauth(code: &str) -> Self {
        Self(StatusCode::BAD_REQUEST, json!({"error":code}), None)
    }
    fn unauthorized() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            json!({"error":"invalid_token"}),
            None,
        )
    }
    fn server() -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"server_error"}),
            None,
        )
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Some(location) = self.2 {
            return Redirect::to(&location).into_response();
        }
        (self.0, Json(self.1)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_redirect_and_pkce_and_refresh_bounds() {
        let registered = ["https://a.example/cb".to_owned()];
        assert!(!registered.contains(&"https://a.example/cb.evil".to_owned()));
        assert!(validate_pkce_s256("short", "x").is_err());
        let huge = format!("prt_v1_{}.{:0200}", TokenId::new(), "x");
        assert!(parse_opaque("prt_v1", &huge).is_err());
    }
    #[test]
    fn jwt_types_are_cryptographically_distinct() {
        let keys = Es256KeyProvider::generate_for_development("test");
        let now = Utc::now().timestamp();
        let id = keys
            .sign(
                "JWT",
                &json!({"iss":"https://issuer","exp":now+60,"iat":now}),
            )
            .expect("sign");
        assert!(keys.verify_access(&id, "https://issuer").is_err());
        let access = keys
            .sign(
                "at+jwt",
                &json!({"iss":"https://issuer","exp":now+60,"iat":now}),
            )
            .expect("sign");
        assert!(keys.verify_access(&access, "https://issuer").is_ok());
    }
}
