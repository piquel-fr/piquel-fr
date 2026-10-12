//! Token exchange, refresh rotation, revocation and `UserInfo`.

use super::{
    ACCESS_TOKEN_SECONDS, AuthScheme, OAuthCode, OAuthError, OidcApplication, keyed_digest,
    new_opaque, parse_opaque, parse_scopes, validate_pkce_s256,
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use chrono::Utc;
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use piquel_repository::{
    AppendAuditEvent, InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, StoredSession,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Deserialize)]
pub(super) struct TokenForm {
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
pub(super) struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}
pub(super) async fn token(
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
pub(super) struct RevokeForm {
    token: String,
    client_id: Option<String>,
}
pub(super) async fn revoke(
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
pub(super) async fn userinfo(
    State(app): State<OidcApplication>,
    headers: HeaderMap,
) -> Result<Json<Value>, OAuthError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| AuthScheme::Bearer.credentials(v))
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
