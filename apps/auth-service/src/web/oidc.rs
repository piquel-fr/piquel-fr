//! The consent page and the confirmation of an application's logout request. Both
//! complete an OAuth flow in-process, then send the browser on.

use super::{Failure, WebApplication};
use crate::{
    oidc::{AuthorizationDecision, LogoutQuery, OAuthError, TransactionQuery},
    routes,
};
use piquel_ui::{Area, LoginQuery, Query, Title};
use std::slice;
use topcoat::{
    Error,
    context::{Cx, app_context},
    router::{Body, StatusCode, request::headers, response::Response},
    view::view,
};
use url::Url;

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
            .render(
                cx,
                StatusCode::OK,
                Title::Consent.as_str(),
                Area::SignIn,
                slice::from_ref(&redirect),
                page,
            )
            .await?)
    }

    /// `POST /authorize`: records the decision and sends the browser to the
    /// application, with a code or the refusal.
    pub(super) async fn decide(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let context = Self::context(cx)?;
        let decision: AuthorizationDecision = Self::form(cx, body).await?;
        let transaction = decision.transaction().to_owned();
        let redirect = web
            .oidc
            .decide(headers(cx), decision, Some(context))
            .await
            .map_err(|error| Failure::signing_in(error, &transaction))?;
        Ok(web.onward(cx, Title::Consent.as_str(), &redirect).await?)
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
            .render(
                cx,
                StatusCode::OK,
                Title::Logout.as_str(),
                Area::SignIn,
                slice::from_ref(&destination),
                page,
            )
            .await?)
    }

    /// `POST /logout`: ends the session and sends the browser where the application
    /// asked, or to sign-in.
    pub(super) async fn end_session(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let context = Self::context(cx)?;
        let request: LogoutQuery = Self::form(cx, body).await?;
        let (destination, signed_out) =
            web.oidc.end_session(context, headers(cx), &request).await?;
        let mut response = web.onward(cx, Title::Logout.as_str(), &destination).await?;
        signed_out.clear_on(&mut response).map_err(Error::from)?;
        Ok(response)
    }
}

impl Failure {
    /// Explains `error` with a link to sign in again, which then continues the
    /// pending authorization `transaction`.
    fn signing_in(error: OAuthError, transaction: &str) -> Self {
        let query = LoginQuery {
            transaction: Some(transaction.to_owned()),
            ..LoginQuery::default()
        };
        match query.on(routes::page::LOGIN) {
            Ok(sign_in) => Self::Explained {
                error,
                link: Some(("Sign in again", sign_in)),
            },
            Err(unwritten) => unwritten.into(),
        }
    }
}
