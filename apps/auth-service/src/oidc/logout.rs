//! RP-initiated logout.

use super::{Claim, MAX_STATE_BYTES, OAuthCode, OAuthError, OidcApplication, Reject};
use crate::{
    routes,
    security::{RequestContext, Session},
};
use axum::{
    Form, Json,
    extract::{State, rejection::FormRejection},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use piquel_common::{ClientId, events::RevocationReason};
use piquel_repository::SessionScope;
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

impl LogoutQuery {
    /// Unwraps the extracted parameters, describing why they could not be read.
    fn parse(form: Result<Form<Self>, FormRejection>) -> Result<Self, OAuthError> {
        form.map(|Form(q)| q).map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("logout request is malformed: {error}"), error)
        })
    }
}

impl OidcApplication {
    /// Validates the client, hint and exact registered post-logout redirect. Returns
    /// the destination, and the client that asked for the logout when a verified
    /// `id_token_hint` or a registered `post_logout_redirect_uri` names it.
    async fn logout_destination(
        &self,
        q: &LogoutQuery,
    ) -> Result<(String, Option<ClientId>), OAuthError> {
        if q.state.as_ref().is_some_and(|s| s.len() > MAX_STATE_BYTES) {
            return Err(OAuthCode::InvalidRequest
                .reject(format!("state must be at most {MAX_STATE_BYTES} bytes")));
        }
        let hint = q
            .id_token_hint
            .as_ref()
            .map(|token| {
                self.keys
                    .verify_id_token_hint(token, &self.issuer)
                    .map_err(|error| {
                        OAuthCode::InvalidRequest
                            .reject_with(format!("id_token_hint is invalid: {error}"), error)
                    })
            })
            .transpose()?;
        // Auth signed the hint, so its audience is a client ID it issued to.
        let hinted_client = hint
            .as_ref()
            .and_then(|c| c.get(Claim::Audience.as_str()))
            .and_then(Value::as_str)
            .map(str::parse::<ClientId>)
            .transpose()
            .map_err(|error| {
                OAuthCode::InvalidRequest
                    .reject_with("id_token_hint audience is not a client ID", error)
            })?;
        if q.client_id
            .as_deref()
            .zip(hinted_client.as_ref())
            .is_some_and(|(a, b)| a != b.as_str())
        {
            return Err(OAuthCode::InvalidRequest
                .reject("client_id does not match the id_token_hint audience"));
        }
        let Some(uri) = q.post_logout_redirect_uri.as_ref() else {
            return Ok((
                format!("{}{}", self.issuer, routes::page::LOGIN),
                hinted_client,
            ));
        };
        let id = q
            .client_id
            .as_deref()
            .or(hinted_client.as_ref().map(ClientId::as_str))
            .ok_or_else(|| {
                OAuthCode::InvalidRequest
                    .reject("post_logout_redirect_uri needs client_id or id_token_hint")
            })?;
        let client = self
            .database
            .oidc()
            .find_client(id)
            .await?
            .filter(|c| c.enabled)
            .ok_or_else(|| {
                OAuthCode::InvalidRequest.reject("client_id is not a registered, enabled client")
            })?;
        if !client.post_logout_uris.contains(uri) {
            return Err(OAuthCode::InvalidRequest.reject(
                "post_logout_redirect_uri is not registered for this client; it must match exactly",
            ));
        }
        let mut url = Url::parse(uri).map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with("post_logout_redirect_uri is not a valid URL", error)
        })?;
        if let Some(state) = &q.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        Ok((url.into(), Some(client.id)))
    }

    /// Validates RP logout parameters before sending the browser to confirmation.
    /// `Form` reads the query string of GET requests.
    pub(super) async fn start_logout(
        State(app): State<Self>,
        form: Result<Form<LogoutQuery>, FormRejection>,
    ) -> Result<Redirect, OAuthError> {
        app.confirm_logout(&LogoutQuery::parse(form)?).await
    }

    /// Sends the browser to the logout confirmation page with the validated parameters.
    async fn confirm_logout(&self, q: &LogoutQuery) -> Result<Redirect, OAuthError> {
        self.logout_destination(q).await?;
        let mut url = Url::parse(&format!("{}{}", self.issuer, routes::page::LOGOUT))?;
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
        context: RequestContext,
        headers: HeaderMap,
        form: Result<Form<LogoutQuery>, FormRejection>,
    ) -> Result<Response, OAuthError> {
        let q = LogoutQuery::parse(form)?;
        // Cross-site RP form submissions navigate to confirmation; only issuer-origin
        // browser requests may revoke a session.
        if app.require_same_origin(&headers).is_err() {
            return app
                .confirm_logout(&q)
                .await
                .map(IntoResponse::into_response);
        }
        let (destination, client) = app.logout_destination(&q).await?;
        if let Some(session) = Session::optional(&app.database, &headers).await? {
            let reason = client.map_or(RevocationReason::Logout, |client_id| {
                RevocationReason::RelyingPartyLogout { client_id }
            });
            let mut tx = app.database.begin().await?;
            Session::revoke(
                &mut tx,
                context,
                &session,
                SessionScope::One(session.id),
                reason,
            )
            .await?;
            tx.commit().await?;
        }
        let mut response = Json(json!({"redirect_url":destination})).into_response();
        crate::security::BrowserCookie::Session.clear_on(&mut response)?;
        Ok(response)
    }
}
