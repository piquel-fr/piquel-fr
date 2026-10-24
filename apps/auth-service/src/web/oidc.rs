//! The consent page and the confirmation of an application's logout request. Both
//! complete an OAuth flow in-process, then send the browser on.

use super::{Failure, WebApplication};
use crate::{
    oidc::{AuthorizationDecision, LogoutQuery, OAuthError, TransactionQuery},
    routes,
    security::{BrowserCookie, RequestContext},
};
use topcoat::{
    Error,
    context::{Cx, app_context},
    router::{
        Body, StatusCode,
        request::{extensions, headers},
        response::Response,
    },
    view::view,
};
use url::{Url, form_urlencoded};

/// The consent page's title.
pub(super) const CONSENT: &str = "Authorize application";
/// The logout page's title.
pub(super) const LOGOUT: &str = "Sign out";

impl WebApplication {
    /// `GET /authorize?transaction=…`: what the application asks to receive, and the
    /// buttons deciding on it.
    pub(super) async fn consent(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let TransactionQuery { transaction } = Self::query(cx)?;
        let request = web
            .oidc
            .consent(headers(cx), &transaction)
            .await
            .map_err(|error| Failure::signing_in(error, &transaction))?;
        let redirect = Url::parse(&request.redirect_uri).map_err(OAuthError::from)?;
        let page = view! { cx =>
            piquel_ui::consent(
                client: &request.client_display_name,
                scopes: &request.scopes,
                action: routes::page::CONSENT,
                transaction: &transaction,
            )
        };
        Ok(web
            .render(cx, StatusCode::OK, CONSENT, Some(&redirect), page)
            .await?)
    }

    /// `POST /authorize`: records the decision and sends the browser to the
    /// application, with a code or the refusal.
    pub(super) async fn decide(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let context = RequestContext::of(extensions(cx)).map_err(Error::from)?;
        let decision: AuthorizationDecision = Self::form(cx, body).await?;
        let transaction = decision.transaction().to_owned();
        let redirect = web
            .oidc
            .decide(headers(cx), decision, Some(context))
            .await
            .map_err(|error| Failure::signing_in(error, &transaction))?;
        Ok(web.onward(cx, CONSENT, &redirect).await?)
    }

    /// `GET /logout?…`: asks to confirm an application's logout request, which
    /// `GET /oidc/logout` sends here once it is valid.
    pub(super) async fn logout(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let request: LogoutQuery = Self::query(cx)?;
        let (destination, _) = web.oidc.logout_destination(&request).await?;
        let fields: Vec<_> = request.fields().collect();
        let page = view! { cx =>
            piquel_ui::logout(action: routes::page::LOGOUT, fields: &fields, keep: routes::page::LOGIN)
        };
        Ok(web
            .render(cx, StatusCode::OK, LOGOUT, Some(&destination), page)
            .await?)
    }

    /// `POST /logout`: ends the session and sends the browser where the application
    /// asked, or to sign-in.
    pub(super) async fn end_session(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let context = RequestContext::of(extensions(cx)).map_err(Error::from)?;
        let request: LogoutQuery = Self::form(cx, body).await?;
        let destination = web.oidc.end_session(context, headers(cx), &request).await?;
        let mut response = web.onward(cx, LOGOUT, &destination).await?;
        BrowserCookie::Session
            .clear_on(&mut response)
            .map_err(Error::from)?;
        Ok(response)
    }
}

impl Failure {
    /// Explains `error` with a link to sign in again, which then continues the
    /// pending authorization `transaction`.
    fn signing_in(error: OAuthError, transaction: &str) -> Self {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("transaction", transaction)
            .finish();
        Self::Explained {
            error,
            link: Some(("Sign in again", format!("{}?{query}", routes::page::LOGIN))),
        }
    }
}
