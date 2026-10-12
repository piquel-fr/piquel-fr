//! Authorization Code + PKCE, signed tokens, and rotating opaque refresh tokens.

mod signing;
pub use signing::Rs256KeyProvider;

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use piquel_repository::{
    AppendAuditEvent, Database, InsertAuthorizationCode, InsertAuthorizationRequest,
    InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, StoredAuthorizationRequest,
    StoredOidcClient, StoredSession,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
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

#[derive(Default, Deserialize)]
#[serde(default)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    audience: Option<String>,
    prompt: Option<String>,
    max_age: Option<i64>,
    id_token_hint: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    response_mode: Option<String>,
}

impl AuthorizeQuery {
    fn requires_login(
        &self,
        session: Option<&StoredSession>,
        force_login: bool,
        hinted_user_id: Option<UserId>,
    ) -> bool {
        force_login
            || session.is_none()
            || hinted_user_id
                .is_some_and(|subject| session.is_some_and(|session| session.user_id != subject))
            || self.max_age.is_some_and(|age| {
                age == 0
                    || session.is_none_or(|session| {
                        Utc::now()
                            .signed_duration_since(session.authenticated_at)
                            .num_seconds()
                            > age
                    })
            })
    }

    /// Reject unsupported security parameters and bind a verified ID-token hint.
    fn hinted_user_id(
        &self,
        app: &OidcApplication,
        redirect: &Url,
    ) -> Result<Option<UserId>, OAuthError> {
        let fail = |code| OAuthError::redirect(redirect, code, &self.state);
        if self.request.is_some() {
            return Err(fail(OAuthCode::RequestNotSupported));
        }
        if self.request_uri.is_some() {
            return Err(fail(OAuthCode::RequestUriNotSupported));
        }
        if self
            .response_mode
            .as_deref()
            .is_some_and(|mode| mode != "query")
        {
            return Err(fail(OAuthCode::InvalidRequest));
        }
        self.id_token_hint
            .as_deref()
            .map(|hint| {
                // A previously issued, expired ID token still identifies an account.
                let claims = app
                    .keys
                    .verify_id_token_hint(hint, &app.issuer)
                    .map_err(|()| fail(OAuthCode::InvalidRequest))?;
                if claims["aud"] != self.client_id
                    || claims.get("exp").and_then(Value::as_i64).is_none()
                {
                    return Err(fail(OAuthCode::InvalidRequest));
                }
                claims
                    .get("sub")
                    .and_then(Value::as_str)
                    .and_then(|subject| UserId::from_str(subject).ok())
                    .ok_or_else(|| fail(OAuthCode::InvalidRequest))
            })
            .transpose()
    }
}

async fn authorize(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    query: Result<Query<AuthorizeQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Redirect, OAuthError> {
    let Query(query) = query.map_err(|_| OAuthCode::InvalidRequest)?;
    authorize_request(app, headers, query).await
}

async fn authorize_post(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    form: Result<Form<AuthorizeQuery>, axum::extract::rejection::FormRejection>,
) -> Result<Redirect, OAuthError> {
    let Form(query) = form.map_err(|_| OAuthCode::InvalidRequest)?;
    authorize_request(app, headers, query).await
}

async fn authorize_request(
    app: OidcApplication,
    headers: HeaderMap,
    q: AuthorizeQuery,
) -> Result<Redirect, OAuthError> {
    let client = app
        .database
        .oidc()
        .find_client(&q.client_id)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidRequest)?;
    if !client.enabled || !client.redirect_uris.contains(&q.redirect_uri) {
        return Err(OAuthCode::InvalidRequest.into());
    }
    let redirect = Url::parse(&q.redirect_uri).map_err(|_| OAuthCode::InvalidRequest)?;
    let fail = |code| OAuthError::redirect(&redirect, code, &q.state);
    let hinted_user_id = q.hinted_user_id(&app, &redirect)?;
    let challenge_valid = URL_SAFE_NO_PAD
        .decode(&q.code_challenge)
        .is_ok_and(|value| value.len() == 32);
    if q.response_type != "code"
        || q.state.len() > 512
        || q.code_challenge_method != "S256"
        || !challenge_valid
    {
        return Err(fail(OAuthCode::InvalidRequest));
    }
    let scopes = parse_scopes(&q.scope).ok_or_else(|| fail(OAuthCode::InvalidScope))?;
    if !scopes
        .iter()
        .all(|scope| client.allowed_scopes.contains(scope))
    {
        return Err(fail(OAuthCode::InvalidScope));
    }
    let audience = q
        .audience
        .clone()
        .or_else(|| client.allowed_audiences.first().cloned())
        .ok_or(OAuthCode::ServerError)?;
    if !client.allowed_audiences.contains(&audience) {
        return Err(fail(OAuthCode::InvalidTarget));
    }
    if q.nonce
        .as_ref()
        .is_some_and(|nonce| nonce.is_empty() || nonce.len() > 512)
        || q.max_age.is_some_and(|age| age < 0)
    {
        return Err(fail(OAuthCode::InvalidRequest));
    }
    let prompts: BTreeSet<_> = q
        .prompt
        .as_deref()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .collect();
    if prompts
        .iter()
        .any(|value| !matches!(*value, "none" | "login" | "consent" | "select_account"))
        || (prompts.contains("none") && prompts.len() > 1)
    {
        return Err(fail(OAuthCode::InvalidRequest));
    }
    let session = browser_session(&app.database, &headers).await?;
    let force_login = prompts.contains("login") || prompts.contains("select_account");
    let requires_login = q.requires_login(session.as_ref(), force_login, hinted_user_id);
    if prompts.contains("none") && requires_login {
        return Err(fail(OAuthCode::LoginRequired));
    }
    let (transaction, id, secret) = new_opaque("par_v1");
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    app.database
        .oidc()
        .insert_authorization_request(&InsertAuthorizationRequest {
            id,
            secret_digest: digest.to_vec(),
            client_id: q.client_id,
            redirect_uri: q.redirect_uri,
            client_state: q.state.clone(),
            pkce_challenge: q.code_challenge,
            nonce: q.nonce,
            scopes: scopes.into_iter().collect(),
            audience,
            force_consent: prompts.contains("consent"),
            force_login,
            max_age: q.max_age,
            hinted_user_id,
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .map_err(OAuthError::internal)?;
    if requires_login {
        return Ok(app.continuation_page("login", &transaction));
    }
    app.continue_authorization(&headers, transaction, prompts.contains("none"))
        .await
}

#[derive(Serialize)]
struct AuthorizationTransactionView {
    client_name: String,
    scopes: Vec<String>,
    audience: String,
}

async fn authorization_transaction(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    Path(transaction): Path<String>,
) -> Result<Json<AuthorizationTransactionView>, OAuthError> {
    let session = browser_session(&app.database, &headers)
        .await?
        .ok_or(OAuthCode::InvalidToken)?;
    let request = find_authorization_request(&app, &transaction).await?;
    require_authorization_session(&request, &session)?;
    Ok(Json(AuthorizationTransactionView {
        client_name: request.client_display_name,
        scopes: request.scopes,
        audience: request.audience,
    }))
}

#[derive(Deserialize)]
struct AuthorizationDecision {
    transaction: String,
    decision: String,
}

async fn authorization_decision(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    Form(input): Form<AuthorizationDecision>,
) -> Result<Json<Value>, OAuthError> {
    require_same_origin(&app, &headers)?;
    let redirect = decide(&app, &headers, input, true).await?;
    let response = redirect.into_response();
    Ok(Json(
        json!({"redirect_url":response.headers().get(header::LOCATION).and_then(|v|v.to_str().ok()).ok_or(OAuthCode::ServerError)?}),
    ))
}

async fn decide(
    app: &OidcApplication,
    headers: &HeaderMap,
    input: AuthorizationDecision,
    explicit: bool,
) -> Result<Redirect, OAuthError> {
    let session = browser_session(&app.database, headers)
        .await?
        .ok_or(OAuthCode::InvalidToken)?;
    let pending = find_authorization_request(app, &input.transaction).await?;
    if !explicit && !can_authorize(app, &pending, &session).await? {
        return Err(OAuthCode::InvalidRequest.into());
    }
    let (id, secret) = parse_opaque("par_v1", &input.transaction)?;
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    let mut transaction = app.database.begin().await.map_err(OAuthError::internal)?;
    let request = transaction
        .oidc()
        .consume_authorization_request(id, &digest)
        .await
        .map_err(|error| OAuthError::database(error, OAuthCode::InvalidRequest))?;
    require_authorization_session(&request, &session)?;
    let mut redirect = Url::parse(&request.redirect_uri).map_err(OAuthError::internal)?;
    match input.decision.as_str() {
        "deny" => {
            redirect
                .query_pairs_mut()
                .append_pair("error", "access_denied")
                .append_pair("state", &request.client_state);
        }
        "approve" => {
            if explicit {
                transaction
                    .oidc()
                    .save_consent(
                        session.user_id,
                        &request.client_id,
                        &request.audience,
                        &request.scopes,
                    )
                    .await
                    .map_err(OAuthError::internal)?;
            }
            let user = transaction
                .users()
                .find_active_by_id_for_update(session.user_id)
                .await
                .map_err(OAuthError::internal)?
                .ok_or(OAuthCode::InvalidToken)?;
            if user.id != session.user_id {
                return Err(OAuthCode::InvalidToken.into());
            }
            let (code, code_id, code_secret) = new_opaque("pac_v1");
            let code_digest = keyed_digest(app.refresh_key.as_ref(), &code_secret)?;
            transaction
                .oidc()
                .insert_code(&InsertAuthorizationCode {
                    id: code_id,
                    secret_digest: code_digest.to_vec(),
                    client_id: request.client_id,
                    user_id: session.user_id,
                    session_id: session.id,
                    redirect_uri: request.redirect_uri,
                    pkce_challenge: request.pkce_challenge,
                    nonce: request.nonce,
                    scopes: request.scopes,
                    audience: request.audience,
                    expires_at: Utc::now() + Duration::minutes(2),
                })
                .await
                .map_err(OAuthError::internal)?;
            redirect
                .query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &request.client_state);
        }
        _ => return Err(OAuthCode::InvalidRequest.into()),
    }
    transaction.commit().await.map_err(OAuthError::internal)?;
    Ok(Redirect::to(redirect.as_str()))
}

async fn find_authorization_request(
    app: &OidcApplication,
    value: &str,
) -> Result<StoredAuthorizationRequest, OAuthError> {
    let (id, secret) = parse_opaque("par_v1", value)?;
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    app.database
        .oidc()
        .find_authorization_request(id, &digest)
        .await
        .map_err(OAuthError::internal)?
        .ok_or_else(|| OAuthError::from(OAuthCode::InvalidRequest))
}

fn require_authorization_session(
    request: &StoredAuthorizationRequest,
    session: &StoredSession,
) -> Result<(), OAuthError> {
    let newer_than_request = session.authenticated_at >= request.created_at;
    let within_max_age = request.max_age.is_none_or(|age| {
        if age == 0 {
            return newer_than_request;
        }
        age >= 0
            && Utc::now()
                .signed_duration_since(session.authenticated_at)
                .num_seconds()
                <= age
    });
    (!request.force_login || newer_than_request)
        .then_some(())
        .filter(|()| within_max_age)
        .filter(|()| {
            request
                .hinted_user_id
                .is_none_or(|subject| subject == session.user_id)
        })
        .ok_or_else(|| OAuthError::from(OAuthCode::InvalidToken))
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    client_id: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
}
impl TokenForm {
    fn refresh_scopes(&self, granted: &[String]) -> Result<Vec<String>, OAuthError> {
        let Some(requested) = self.scope.as_deref() else {
            return Ok(granted.to_vec());
        };
        let scopes = parse_scopes(requested).ok_or(OAuthCode::InvalidScope)?;
        if !scopes.iter().all(|scope| granted.contains(scope)) {
            return Err(OAuthCode::InvalidScope.into());
        }
        Ok(scopes.into_iter().collect())
    }
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
    headers: HeaderMap,
    form: Result<Form<TokenForm>, axum::extract::rejection::FormRejection>,
) -> Result<Json<TokenResponse>, OAuthError> {
    let Form(mut form) = form.map_err(|_| OAuthCode::InvalidRequest)?;
    let client = app
        .authenticate_client(&headers, form.client_id.as_deref())
        .await?;
    form.client_id = Some(client.id);
    match form.grant_type.as_str() {
        "authorization_code" => exchange_code(&app, form).await.map(Json),
        "refresh_token" => rotate_refresh(&app, form).await.map(Json),
        _ => Err(OAuthCode::UnsupportedGrantType.into()),
    }
}

async fn exchange_code(
    app: &OidcApplication,
    form: TokenForm,
) -> Result<TokenResponse, OAuthError> {
    let (id, secret) = parse_opaque(
        "pac_v1",
        form.code.as_deref().ok_or(OAuthCode::InvalidGrant)?,
    )?;
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    let mut tx = app.database.begin().await.map_err(OAuthError::internal)?;
    let code = tx
        .oidc()
        .consume_code(id, &digest)
        .await
        .map_err(|error| OAuthError::database(error, OAuthCode::InvalidGrant))?;
    if Some(code.client_id.as_str()) != form.client_id.as_deref()
        || form.redirect_uri.as_deref() != Some(&code.redirect_uri)
        || validate_pkce_s256(
            form.code_verifier.as_deref().unwrap_or_default(),
            &code.pkce_challenge,
        )
        .is_err()
    {
        return Err(OAuthCode::InvalidGrant.into());
    }
    let user = tx
        .users()
        .find_active_by_id_for_update(code.user_id)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidGrant)?;
    let session = tx
        .sessions()
        .find_by_id(code.session_id)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidGrant)?;
    let client = tx
        .oidc()
        .find_client(form.client_id.as_deref().ok_or(OAuthCode::InvalidClient)?)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidClient)?;
    let email = tx
        .oidc()
        .primary_email(user.id)
        .await
        .map_err(OAuthError::internal)?;
    let tokens = TokenGrant {
        client: &client.id,
        audience: &code.audience,
        scopes: &code.scopes,
        nonce: code.nonce.as_deref(),
    }
    .issue(app, &user, &session, email.as_deref())?;
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
    tx.commit().await.map_err(OAuthError::internal)?;
    Ok(TokenResponse {
        refresh_token: refresh,
        ..tokens
    })
}

async fn rotate_refresh(
    app: &OidcApplication,
    form: TokenForm,
) -> Result<TokenResponse, OAuthError> {
    let (id, secret) = parse_opaque(
        "prt_v1",
        form.refresh_token
            .as_deref()
            .ok_or(OAuthCode::InvalidGrant)?,
    )?;
    let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
    let mut tx = app.database.begin().await.map_err(OAuthError::internal)?;
    let rotated = match tx
        .tokens()
        .consume_for_rotation(
            id,
            &digest,
            form.client_id.as_deref().ok_or(OAuthCode::InvalidClient)?,
        )
        .await
    {
        Ok(value) => value,
        Err(RefreshRotationError::Replay { user_id }) => {
            tx.audit_events()
                .append(&AppendAuditEvent {
                    id: TokenId::new(),
                    user_id: Some(user_id),
                    action: "refresh.replay".into(),
                    outcome: "rejected".into(),
                    request_metadata: json!({}),
                })
                .await
                .map_err(OAuthError::internal)?;
            tx.commit().await.map_err(OAuthError::internal)?;
            tracing::warn!(
                event = "auth.refresh_replay",
                "refresh token replay rejected"
            );
            return Err(OAuthCode::InvalidGrant.into());
        }
        Err(RefreshRotationError::Policy { user_id }) => {
            tx.audit_events()
                .append(&AppendAuditEvent {
                    id: TokenId::new(),
                    user_id: Some(user_id),
                    action: "refresh.policy_rejected".into(),
                    outcome: "rejected".into(),
                    request_metadata: json!({}),
                })
                .await
                .map_err(OAuthError::internal)?;
            tx.commit().await.map_err(OAuthError::internal)?;
            return Err(OAuthCode::InvalidGrant.into());
        }
        Err(RefreshRotationError::Invalid) => {
            return Err(OAuthCode::InvalidGrant.into());
        }
        Err(RefreshRotationError::Database(error)) => return Err(OAuthError::internal(error)),
    };
    if Some(rotated.client_id.as_str()) != form.client_id.as_deref() {
        return Err(OAuthCode::InvalidGrant.into());
    }
    let scopes = form.refresh_scopes(&rotated.scopes)?;
    let user = tx
        .users()
        .find_by_id(rotated.user_id)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidGrant)?;
    let session = tx
        .sessions()
        .find_by_id(rotated.session_id)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidGrant)?;
    let (raw, new_id, new_secret) = new_opaque("prt_v1");
    let new_digest = keyed_digest(app.refresh_key.as_ref(), &new_secret)?;
    tx.tokens()
        .insert_token(&InsertRefreshToken {
            id: new_id,
            family_id: rotated.family_id,
            secret_digest: new_digest.to_vec(),
            expires_at: session.expires_at,
        })
        .await
        .map_err(OAuthError::internal)?;
    let email = tx
        .oidc()
        .primary_email(user.id)
        .await
        .map_err(OAuthError::internal)?;
    let mut tokens = TokenGrant {
        client: &rotated.client_id,
        audience: &rotated.audience,
        scopes: &scopes,
        nonce: None,
    }
    .issue(app, &user, &session, email.as_deref())?;
    tokens.refresh_token = Some(raw);
    tx.commit().await.map_err(OAuthError::internal)?;
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
) -> Result<String, OAuthError> {
    let session = tx
        .sessions()
        .find_active_by_id(session_id)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidGrant)?;
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
                expires_at: session.expires_at,
            },
        )
        .await
        .map_err(OAuthError::internal)?;
    Ok(raw)
}

struct TokenGrant<'a> {
    client: &'a str,
    audience: &'a str,
    scopes: &'a [String],
    nonce: Option<&'a str>,
}
impl TokenGrant<'_> {
    fn issue(
        &self,
        app: &OidcApplication,
        user: &piquel_repository::StoredUser,
        session: &StoredSession,
        email: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let Self {
            client,
            audience,
            scopes,
            nonce,
        } = self;
        let now = Utc::now().timestamp();
        let mut claims = json!({"iss":app.issuer,"sub":user.id,"sid":session.id,"auth_time":session.authenticated_at.timestamp(),"amr":session.authentication_methods,"iat":now,"exp":now+ACCESS_TOKEN_SECONDS});
        if scopes.iter().any(|s| s == "profile") {
            claims["preferred_username"] = json!(user.username);
            claims["name"] = json!(user.display_name);
            claims["profile_version"] = json!(user.profile_version);
        }
        if scopes.iter().any(|s| s == "email")
            && let Some(email) = email
        {
            claims["email"] = json!(email);
            claims["email_verified"] = json!(true);
        }
        let mut access = claims.clone();
        access["aud"] = json!(audience);
        access["client_id"] = json!(client);
        access["jti"] = json!(TokenId::new());
        access["scope"] = json!(scopes.join(" "));
        let access_token = app
            .keys
            .sign("at+jwt", &access)
            .map_err(|()| OAuthCode::ServerError)?;
        let id_token = if scopes.iter().any(|s| s == "openid") {
            claims["aud"] = json!(client);
            if let Some(nonce) = nonce {
                claims["nonce"] = json!(nonce);
            }
            Some(
                app.keys
                    .sign("JWT", &claims)
                    .map_err(|()| OAuthCode::ServerError)?,
            )
        } else {
            None
        };
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_SECONDS,
            scope: scopes.join(" "),
            id_token,
            refresh_token: None,
        })
    }
}

#[derive(Deserialize)]
struct RevokeForm {
    token: String,
    client_id: Option<String>,
}
async fn revoke(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    form: Result<Form<RevokeForm>, axum::extract::rejection::FormRejection>,
) -> Result<StatusCode, OAuthError> {
    let Form(form) = form.map_err(|_| OAuthCode::InvalidRequest)?;
    let client = app
        .authenticate_client(&headers, form.client_id.as_deref())
        .await?;
    if let Ok((id, secret)) = parse_opaque("prt_v1", &form.token) {
        let digest = keyed_digest(app.refresh_key.as_ref(), &secret)?;
        let mut tx = app.database.begin().await.map_err(OAuthError::internal)?;
        tx.tokens()
            .revoke_family_for_client_token(id, &digest, &client.id)
            .await
            .map_err(OAuthError::internal)?;
        tx.commit().await.map_err(OAuthError::internal)?;
    }
    Ok(StatusCode::OK)
}

async fn userinfo(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
) -> Result<Json<Value>, OAuthError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(OAuthCode::InvalidToken)?;
    let claims = app
        .keys
        .verify(token, "at+jwt", &app.issuer)
        .map_err(|()| OAuthCode::InvalidToken)?;
    let scopes: BTreeSet<_> = claims
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .split_ascii_whitespace()
        .collect();
    if !scopes.contains("openid") {
        return Err(OAuthCode::InvalidToken.into());
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
    if scopes.contains("email") {
        for name in ["email", "email_verified"] {
            if let Some(value) = claims.get(name) {
                response[name] = value.clone();
            }
        }
    }
    Ok(Json(response))
}

#[derive(Deserialize, Serialize)]
struct LogoutQuery {
    client_id: Option<String>,
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

impl OidcApplication {
    async fn logout_destination(&self, q: &LogoutQuery) -> Result<String, OAuthError> {
        if q.state.as_ref().is_some_and(|s| s.len() > 512) {
            return Err(OAuthCode::InvalidRequest.into());
        }
        let hint = q
            .id_token_hint
            .as_ref()
            .map(|token| {
                self.keys
                    .verify_id_token_hint(token, &self.issuer)
                    .map_err(|()| OAuthError::from(OAuthCode::InvalidRequest))
            })
            .transpose()?;
        let hinted_client = hint
            .as_ref()
            .and_then(|c| c.get("aud"))
            .and_then(Value::as_str);
        if q.client_id
            .as_deref()
            .zip(hinted_client)
            .is_some_and(|(a, b)| a != b)
        {
            return Err(OAuthCode::InvalidRequest.into());
        }
        let Some(uri) = q.post_logout_redirect_uri.as_ref() else {
            return Ok(format!("{}/login", self.issuer));
        };
        let id = q
            .client_id
            .as_deref()
            .or(hinted_client)
            .ok_or(OAuthCode::InvalidRequest)?;
        let client = self
            .database
            .oidc()
            .find_client(id)
            .await
            .map_err(OAuthError::internal)?
            .filter(|c| c.enabled)
            .ok_or(OAuthCode::InvalidRequest)?;
        if !client.post_logout_uris.contains(uri) {
            return Err(OAuthCode::InvalidRequest.into());
        }
        let mut url = Url::parse(uri).map_err(|_| OAuthCode::InvalidRequest)?;
        if let Some(state) = &q.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        Ok(url.into())
    }
}

async fn logout_start(
    State(app): State<OidcApplication>,
    Query(q): Query<LogoutQuery>,
) -> Result<Redirect, OAuthError> {
    app.logout_destination(&q).await?;
    let mut url = Url::parse(&format!("{}/logout", app.issuer)).map_err(OAuthError::internal)?;
    for (name, value) in [
        ("client_id", &q.client_id),
        ("id_token_hint", &q.id_token_hint),
        ("post_logout_redirect_uri", &q.post_logout_redirect_uri),
        ("state", &q.state),
    ] {
        if let Some(value) = value {
            url.query_pairs_mut().append_pair(name, value);
        }
    }
    Ok(Redirect::to(url.as_str()))
}

async fn logout(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    Form(q): Form<LogoutQuery>,
) -> Result<Response, OAuthError> {
    if require_same_origin(&app, &headers).is_err() {
        return logout_start(State(app), Query(q))
            .await
            .map(IntoResponse::into_response);
    }
    let destination = app.logout_destination(&q).await?;
    if let Some(session) = browser_session(&app.database, &headers).await? {
        let mut tx = app.database.begin().await.map_err(OAuthError::internal)?;
        tx.oidc()
            .revoke_session(session.id)
            .await
            .map_err(OAuthError::internal)?;
        tx.commit().await.map_err(OAuthError::internal)?;
    }
    let mut response = Json(json!({"redirect_url":destination})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        crate::security::BrowserCookie::Session
            .clear()
            .parse()
            .map_err(OAuthError::internal)?,
    );
    Ok(response)
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
/// OAuth 2.0 and OIDC error codes returned by this provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OAuthCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    InvalidTarget,
    InvalidToken,
    UnsupportedGrantType,
    LoginRequired,
    ConsentRequired,
    RequestNotSupported,
    RequestUriNotSupported,
    ServerError,
}
impl OAuthCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidToken => "invalid_token",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::ServerError => "server_error",
        }
    }
    const fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
    /// `WWW-Authenticate` challenge for failed client or bearer-token authentication.
    const fn challenge(self) -> Option<&'static str> {
        match self {
            Self::InvalidClient => Some("Basic realm=\"token\""),
            Self::InvalidToken => Some("Bearer error=\"invalid_token\""),
            _ => None,
        }
    }
}

/// A protocol failure, answered with `{"error": code}` or by redirecting to the client.
///
/// Browser-facing account APIs use `security::ApiError` instead; OIDC clients and the
/// auth pages rely on these machine-readable codes.
#[derive(Debug)]
struct OAuthError {
    code: OAuthCode,
    redirect: Option<Url>,
}
impl From<OAuthCode> for OAuthError {
    fn from(code: OAuthCode) -> Self {
        Self {
            code,
            redirect: None,
        }
    }
}
impl OAuthError {
    fn internal(error: impl std::fmt::Debug) -> Self {
        tracing::error!(error=?error,"OIDC operation failed");
        OAuthCode::ServerError.into()
    }
    fn database(error: piquel_repository::DatabaseError, expected: OAuthCode) -> Self {
        match error {
            piquel_repository::DatabaseError::NotFound => expected.into(),
            error => Self::internal(error),
        }
    }
    /// Returns `code` to a validated client redirect URI with its `state`.
    fn redirect(base: &Url, code: OAuthCode, state: &str) -> Self {
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("error", code.as_str())
            .append_pair("state", state);
        Self {
            code,
            redirect: Some(url),
        }
    }
}
impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        if let Some(location) = self.redirect {
            return Redirect::to(location.as_str()).into_response();
        }
        let mut response = (
            self.code.status(),
            Json(json!({"error":self.code.as_str()})),
        )
            .into_response();
        if let Some(challenge) = self.code.challenge() {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(challenge),
            );
        }
        response
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
}

#[derive(Deserialize)]
struct ResumeQuery {
    transaction: String,
}
async fn resume(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    Query(q): Query<ResumeQuery>,
) -> Result<Redirect, OAuthError> {
    app.continue_authorization(&headers, q.transaction, false)
        .await
}
impl OidcApplication {
    fn continuation_page(&self, page: &str, transaction: &str) -> Redirect {
        Redirect::to(&format!("{}/{page}?transaction={transaction}", self.issuer))
    }
    async fn continue_authorization(
        &self,
        headers: &HeaderMap,
        transaction: String,
        silent: bool,
    ) -> Result<Redirect, OAuthError> {
        let request = find_authorization_request(self, &transaction).await?;
        let redirect = Url::parse(&request.redirect_uri).map_err(OAuthError::internal)?;
        let fail = |code| OAuthError::redirect(&redirect, code, &request.client_state);
        let session = browser_session(&self.database, headers).await?;
        let Some(session) =
            session.filter(|session| require_authorization_session(&request, session).is_ok())
        else {
            if silent {
                return Err(fail(OAuthCode::LoginRequired));
            }
            return Ok(self.continuation_page("login", &transaction));
        };
        if can_authorize(self, &request, &session).await? {
            return decide(
                self,
                headers,
                AuthorizationDecision {
                    transaction,
                    decision: "approve".into(),
                },
                false,
            )
            .await;
        }
        if silent {
            return Err(fail(OAuthCode::ConsentRequired));
        }
        Ok(self.continuation_page("authorize", &transaction))
    }
}

async fn can_authorize(
    app: &OidcApplication,
    request: &StoredAuthorizationRequest,
    session: &StoredSession,
) -> Result<bool, OAuthError> {
    if request.force_consent {
        return Ok(false);
    }
    let client = app
        .database
        .oidc()
        .find_client(&request.client_id)
        .await
        .map_err(OAuthError::internal)?
        .ok_or(OAuthCode::InvalidRequest)?;
    Ok(client.trusted
        || app
            .database
            .oidc()
            .consented(
                session.user_id,
                &request.client_id,
                &request.audience,
                &request.scopes,
            )
            .await
            .map_err(OAuthError::internal)?)
}

#[cfg(test)]
#[path = "oidc/tests.rs"]
mod flow_tests;
