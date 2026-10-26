//! RP-initiated logout: the request, sent on to the logout page to confirm, and the
//! end of the session once confirmed.

use super::{Claim, MAX_STATE_BYTES, OAuthCode, OAuthError, OidcApplication, Reject};
use crate::{account::AccountService, routes, security::RequestContext, sessions::SignedOut};
use axum::{
    Form,
    extract::{State, rejection::FormRejection},
    http::HeaderMap,
    response::Redirect,
};
use piquel_common::{ClientId, events::RevocationReason};
use piquel_ui::LoginQuery;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use url::Url;

/// RP-initiated logout parameters bound to a registered destination and optional ID
/// hint. A parameter sent empty is kept, as sent, whichever decoder reads it, so it
/// means the same at the endpoint and on the logout page: an included `state` goes
/// back to the client even when empty (RP-Initiated Logout §2), and Topcoat's own
/// decoder would read an empty value as absent.
#[derive(Deserialize)]
pub(crate) struct LogoutQuery {
    /// Registered relying-party identifier.
    #[serde(default, deserialize_with = "LogoutQuery::parameter")]
    client_id: Option<String>,
    /// Previously issued signed ID token identifying the client and account.
    #[serde(default, deserialize_with = "LogoutQuery::parameter")]
    id_token_hint: Option<String>,
    /// Exact registered destination after logout.
    #[serde(default, deserialize_with = "LogoutQuery::parameter")]
    post_logout_redirect_uri: Option<String>,
    /// Opaque client correlation value returned unchanged.
    #[serde(default, deserialize_with = "LogoutQuery::parameter")]
    state: Option<String>,
}

impl LogoutQuery {
    /// Reads a parameter that is present, an empty one included; `default` makes an
    /// absent one `None`.
    fn parameter<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
        String::deserialize(deserializer).map(Some)
    }

    /// The parameters that are present, by name, in the order the logout page
    /// sends them on.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("client_id", &self.client_id),
            ("id_token_hint", &self.id_token_hint),
            ("post_logout_redirect_uri", &self.post_logout_redirect_uri),
            ("state", &self.state),
        ]
        .into_iter()
        .filter_map(|(name, value)| Some((name, value.as_deref()?)))
    }

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
    pub(crate) async fn logout_destination(
        &self,
        q: &LogoutQuery,
    ) -> Result<(Url, Option<ClientId>), OAuthError> {
        if q.state.as_ref().is_some_and(|s| s.len() > MAX_STATE_BYTES) {
            return Err(OAuthCode::InvalidRequest
                .reject(format!("state must be at most {MAX_STATE_BYTES} bytes")));
        }
        let hint = q
            .id_token_hint
            .as_ref()
            .map(|token| {
                self.keys
                    .current()
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
            let login = self.page(routes::page::LOGIN, &LoginQuery::default())?;
            return Ok((login, hinted_client));
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
        Ok((url, Some(client.id)))
    }

    /// Validates RP logout parameters, by GET query or form POST, before sending the
    /// browser to confirm on the logout page. `Form` reads the query string of GET
    /// requests.
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
        url.query_pairs_mut().extend_pairs(q.fields());
        Ok(Redirect::to(url.as_str()))
    }

    /// Ends the browser's session, once the logout page confirmed `q`, and returns
    /// where the browser goes next, with the sign-out its response applies.
    pub(crate) async fn end_session(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
        q: &LogoutQuery,
    ) -> Result<(Url, SignedOut), OAuthError> {
        let (destination, client) = self.logout_destination(q).await?;
        let reason = client.map_or(RevocationReason::Logout, |client_id| {
            RevocationReason::RelyingPartyLogout { client_id }
        });
        let signed_out = AccountService::new(self.database.clone())
            .sign_out(context, headers, reason)
            .await?;
        Ok((destination, signed_out))
    }
}
