//! RP-initiated logout.

use super::{OAuthCode, OAuthError, OidcApplication, browser_session, require_same_origin};
use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

#[derive(Deserialize, Serialize)]
pub(super) struct LogoutQuery {
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
pub(super) async fn logout_start(
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
pub(super) async fn logout(
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
