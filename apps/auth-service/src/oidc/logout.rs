//! RP-initiated logout.

use super::{Claim, MAX_STATE_BYTES, OAuthCode, OAuthError, OidcApplication};
use crate::{routes, security::Session};
use axum::{
    Form, Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

/// RP-initiated logout parameters bound to a registered destination and optional ID hint.
#[derive(Deserialize, Serialize)]
pub(super) struct LogoutQuery {
    /// Registered relying-party identifier.
    client_id: Option<String>,
    /// Previously issued signed ID token identifying the client and account.
    id_token_hint: Option<String>,
    /// Exact registered destination after logout.
    post_logout_redirect_uri: Option<String>,
    /// Opaque client correlation value returned unchanged.
    state: Option<String>,
}

impl OidcApplication {
    /// Validates the client, hint and exact registered post-logout redirect.
    async fn logout_destination(&self, q: &LogoutQuery) -> Result<String, OAuthError> {
        if q.state.as_ref().is_some_and(|s| s.len() > MAX_STATE_BYTES) {
            return Err(OAuthCode::InvalidRequest.into());
        }
        let hint = q
            .id_token_hint
            .as_ref()
            .map(|token| {
                self.keys
                    .verify_id_token_hint(token, &self.issuer)
                    .map_err(|error| OAuthError::rejected(OAuthCode::InvalidRequest, error))
            })
            .transpose()?;
        let hinted_client = hint
            .as_ref()
            .and_then(|c| c.get(Claim::Audience.as_str()))
            .and_then(Value::as_str);
        if q.client_id
            .as_deref()
            .zip(hinted_client)
            .is_some_and(|(a, b)| a != b)
        {
            return Err(OAuthCode::InvalidRequest.into());
        }
        let Some(uri) = q.post_logout_redirect_uri.as_ref() else {
            return Ok(format!("{}{}", self.issuer, routes::page::LOGIN));
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
            .await?
            .filter(|c| c.enabled)
            .ok_or(OAuthCode::InvalidRequest)?;
        if !client.post_logout_uris.contains(uri) {
            return Err(OAuthCode::InvalidRequest.into());
        }
        let mut url = Url::parse(uri)
            .map_err(|error| OAuthError::rejected(OAuthCode::InvalidRequest, error))?;
        if let Some(state) = &q.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        Ok(url.into())
    }

    /// Validates RP logout parameters before sending the browser to confirmation.
    pub(super) async fn start_logout(
        State(app): State<Self>,
        Query(q): Query<LogoutQuery>,
    ) -> Result<Redirect, OAuthError> {
        app.logout_destination(&q).await?;
        let mut url = Url::parse(&format!("{}{}", app.issuer, routes::page::LOGOUT))?;
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

    /// Confirms same-origin logout, revokes the session and expires its browser cookie.
    pub(super) async fn logout(
        State(app): State<Self>,
        headers: HeaderMap,
        Form(q): Form<LogoutQuery>,
    ) -> Result<Response, OAuthError> {
        // Cross-site RP form submissions navigate to confirmation; only issuer-origin
        // browser requests may revoke a session.
        if app.require_same_origin(&headers).is_err() {
            return Self::start_logout(State(app), Query(q))
                .await
                .map(IntoResponse::into_response);
        }
        let destination = app.logout_destination(&q).await?;
        if let Some(session) = Session::optional(&app.database, &headers).await? {
            let mut tx = app.database.begin().await?;
            tx.oidc().revoke_session(session.id).await?;
            tx.commit().await?;
        }
        let mut response = Json(json!({"redirect_url":destination})).into_response();
        crate::security::BrowserCookie::Session.clear_on(&mut response)?;
        Ok(response)
    }
}
