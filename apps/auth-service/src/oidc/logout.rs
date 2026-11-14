//! RP-initiated logout: the request, validated when the logout page asks to confirm
//! it and again when its form confirms it, and the end of the sessions it names.

use super::{Claim, MAX_STATE_BYTES, OAuthCode, OAuthError, OidcApplication, Reject};
use crate::{
    account::AccountService,
    routes,
    security::{RequestContext, Session},
    sessions::SignedOut,
};
use axum::http::HeaderMap;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sourceorigin_common::{ClientId, SessionId, UserId, events::RevocationReason};
use sourceorigin_repository::SessionScope;
use sourceorigin_ui::LoginQuery;
use url::Url;

/// RP-initiated logout parameters, by `GET` query or form `POST`, which the logout
/// page's form posts back as hidden fields. None at all is the user signing out of
/// auth itself, from the settings or the admin dashboard. A parameter sent empty is
/// kept as sent, whichever decoder reads it: an included `state` goes back to the
/// client even when empty (RP-Initiated Logout §2), and Topcoat's own decoder would
/// read an empty value as absent.
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
    /// Set by the logout page's own form once it warned that the hint names
    /// another account than the browser's. Only auth's pages may post to
    /// `/logout`, so an application can't skip the warning.
    #[serde(default, deserialize_with = "LogoutQuery::parameter")]
    warned: Option<String>,
}

impl LogoutQuery {
    /// Reads a parameter that is present, an empty one included; `default` makes an
    /// absent one `None`.
    fn parameter<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
        String::deserialize(deserializer).map(Some)
    }

    /// Whether the logout page already warned that the hint names another account.
    pub(crate) const fn warned(&self) -> bool {
        self.warned.is_some()
    }

    /// The application's parameters that are present, by name, which the logout
    /// page's form posts back.
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
}

/// What a verified `id_token_hint` says: the client auth issued it to, and the
/// account and session it names.
struct Hint {
    /// The token's audience.
    client: ClientId,
    /// The token's `sub`.
    user: Option<UserId>,
    /// The token's `sid`.
    session: Option<SessionId>,
}

impl Hint {
    /// Reads the claims of an ID token auth signed. Auth signed it, so its audience
    /// is a client ID it issued to.
    fn read(claims: &Value) -> Result<Self, OAuthError> {
        let text = |claim: Claim| claims.get(claim.as_str()).and_then(Value::as_str);
        let client = text(Claim::Audience)
            .unwrap_or_default()
            .parse()
            .map_err(|error| {
                OAuthCode::InvalidRequest
                    .reject_with("id_token_hint audience is not a client ID", error)
            })?;
        Ok(Self {
            client,
            user: text(Claim::Subject).and_then(|sub| sub.parse().ok()),
            session: text(Claim::Session).and_then(|sid| sid.parse().ok()),
        })
    }
}

/// A validated logout request: who asked, what its hint names, and where the
/// browser goes once signed out.
struct LogoutRequest {
    /// The application that asked, when a verified hint or a registered
    /// post-logout URI names it.
    client: Option<ClientId>,
    /// The verified hint, issued to `client`.
    hint: Option<Hint>,
    /// Whether a hint was sent that auth could not verify, and was ignored.
    unverified: bool,
    /// Where the browser goes once signed out.
    destination: Url,
}

/// A logout request, as the logout page asking to confirm it shows it.
pub(crate) struct LogoutView {
    /// Whether the application's `id_token_hint` could not be verified, so it was
    /// ignored and the browser stays on auth afterwards.
    pub(crate) unverified: bool,
    /// Whether the hint names another account than the one signed in to this
    /// browser.
    pub(crate) another_account: bool,
    /// Where the browser goes once signed out.
    pub(crate) destination: Url,
}

impl OidcApplication {
    /// Validates an RP-initiated logout request. An `id_token_hint` auth can't
    /// verify, signed by a key auth no longer keeps or forged, is ignored: the
    /// logout goes on, attributed to no client and back to auth's sign-in page. An
    /// unregistered `post_logout_redirect_uri`, or one naming no client, is
    /// refused.
    async fn validate_logout(&self, q: &LogoutQuery) -> Result<LogoutRequest, OAuthError> {
        if q.state.as_ref().is_some_and(|s| s.len() > MAX_STATE_BYTES) {
            return Err(OAuthCode::InvalidRequest
                .reject(format!("state must be at most {MAX_STATE_BYTES} bytes")));
        }
        let verified = match &q.id_token_hint {
            Some(token) => Some(
                self.keys
                    .current()?
                    .verify_id_token_hint(token, &self.issuer),
            ),
            None => None,
        };
        let unverified = verified.as_ref().is_some_and(Result::is_err);
        let hint = verified
            .and_then(Result::ok)
            .map(|claims| Hint::read(&claims))
            .transpose()?;
        if let (Some(client_id), Some(hint)) = (q.client_id.as_deref(), &hint)
            && client_id != hint.client.as_str()
        {
            return Err(OAuthCode::InvalidRequest
                .reject("client_id does not match the id_token_hint audience"));
        }
        let (destination, client) = match &q.post_logout_redirect_uri {
            // The application asked to come back, but auth can't tell it sent the
            // request: the browser stays on auth.
            Some(_) if unverified => (self.signed_out_page()?, None),
            Some(uri) => {
                let named = q
                    .client_id
                    .as_deref()
                    .or(hint.as_ref().map(|hint| hint.client.as_str()));
                let (url, client) = self.post_logout(uri, named, q.state.as_deref()).await?;
                (url, Some(client))
            }
            None => (
                self.signed_out_page()?,
                hint.as_ref().map(|hint| hint.client.clone()),
            ),
        };
        Ok(LogoutRequest {
            client,
            hint,
            unverified,
            destination,
        })
    }

    /// The registered post-logout `uri` of the client `named`, with `state`, and
    /// that client.
    async fn post_logout(
        &self,
        uri: &str,
        named: Option<&str>,
        state: Option<&str>,
    ) -> Result<(Url, ClientId), OAuthError> {
        let id = named.ok_or_else(|| {
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
        if !client
            .post_logout_uris
            .iter()
            .any(|registered| registered == uri)
        {
            return Err(OAuthCode::InvalidRequest.reject(
                "post_logout_redirect_uri is not registered for this client; it must match exactly",
            ));
        }
        let mut url = Url::parse(uri).map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with("post_logout_redirect_uri is not a valid URL", error)
        })?;
        if let Some(state) = state {
            url.query_pairs_mut().append_pair("state", state);
        }
        Ok((url, client.id))
    }

    /// Auth's sign-in page, where a logout that goes back to no application ends.
    fn signed_out_page(&self) -> Result<Url, OAuthError> {
        self.page(routes::page::LOGIN, &LoginQuery::default())
    }

    /// The logout request `q`, validated, as the logout page shows it to the
    /// browser whose request `headers` are.
    pub(crate) async fn logout_request(
        &self,
        headers: &HeaderMap,
        q: &LogoutQuery,
    ) -> Result<LogoutView, OAuthError> {
        let request = self.validate_logout(q).await?;
        let hinted = request.hint.as_ref().and_then(|hint| hint.user);
        let signed_in = match hinted {
            Some(_) => Session::optional(&self.database, headers).await?,
            None => None,
        };
        Ok(LogoutView {
            unverified: request.unverified,
            another_account: hinted
                .zip(signed_in)
                .is_some_and(|(hinted, session)| hinted != session.user_id),
            destination: request.destination,
        })
    }

    /// Ends the browser's session, once the logout page's form confirmed `q`,
    /// validated again, and the session the application's hint names, if it is the
    /// hinted account's sign-in on that application's own page: such a session has
    /// no cookie, so no browser can end it. A session with a cookie ends only
    /// through its own browser: an ID token alone ends only the sign-in on the
    /// app's page it was issued for. Answers where the browser goes next, with the
    /// sign-out its response applies.
    pub(crate) async fn end_session(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
        q: &LogoutQuery,
    ) -> Result<(Url, SignedOut), OAuthError> {
        let request = self.validate_logout(q).await?;
        let reason = request
            .client
            .clone()
            .map_or(RevocationReason::Logout, |client_id| {
                RevocationReason::RelyingPartyLogout { client_id }
            });
        let signed_out = AccountService::new(self.database.clone())
            .sign_out(context, headers, reason.clone())
            .await?;
        if let Some(Hint {
            client,
            user: Some(user),
            session: Some(session),
        }) = &request.hint
        {
            let mut tx = self.database.begin().await?;
            if tx.sessions().is_inline_for(*session, client).await? {
                tx.revoke_sessions(
                    &context.client(client),
                    *user,
                    SessionScope::One(*session),
                    &reason,
                )
                .await?;
            }
            tx.commit().await?;
        }
        Ok((request.destination, signed_out))
    }
}
