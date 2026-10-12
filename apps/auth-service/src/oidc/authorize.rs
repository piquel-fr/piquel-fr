//! Authorization requests, login/consent continuation and the consent decision.

use super::{
    OAuthCode, OAuthError, OidcApplication, browser_session, keyed_digest, new_opaque,
    parse_opaque, parse_scopes, require_same_origin,
};
use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use piquel_auth_protocol::UserId;
use piquel_repository::{
    InsertAuthorizationCode, InsertAuthorizationRequest, StoredAuthorizationRequest, StoredSession,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, str::FromStr};
use url::Url;

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct AuthorizeQuery {
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
pub(super) async fn authorize(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
    query: Result<Query<AuthorizeQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Redirect, OAuthError> {
    let Query(query) = query.map_err(|_| OAuthCode::InvalidRequest)?;
    authorize_request(app, headers, query).await
}
pub(super) async fn authorize_post(
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
pub(super) struct AuthorizationTransactionView {
    client_name: String,
    scopes: Vec<String>,
    audience: String,
}
pub(super) async fn authorization_transaction(
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
pub(super) struct AuthorizationDecision {
    transaction: String,
    decision: String,
}
pub(super) async fn authorization_decision(
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
pub(super) struct ResumeQuery {
    transaction: String,
}
pub(super) async fn resume(
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
