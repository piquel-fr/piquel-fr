//! `/admin`: hands an administrator's passkey session off to the admin dashboard,
//! which sent the browser here (see [`DashboardSignIn`]).
//!
//! Its `GET` goes on to the dashboard at once, unless the dashboard asked for a
//! confirmation: then it asks for a passkey, in a ceremony started for this
//! handoff only, which its form posts. A browser that is not signed in with a
//! passkey signs in first, and comes back. An account that does not administer
//! Piquel is told it has no access, and nothing is handed off.

use crate::web::{Failure, WebApplication};
use crate::{
    AdminError,
    account::Owner,
    admin::DashboardSignIn,
    oidc::{OAuthCode, Reject},
    routes,
    security::ApiError,
};
use piquel_common::protocol::claims::Acr;
use piquel_ui::{Area, Checkbox, HandoffProof, HandoffQuery, LoginQuery, Query, Title};
use topcoat::{
    context::{Cx, app_context},
    router::{
        Body, StatusCode,
        error::see_other,
        request::{headers, uri},
        response::{IntoResponse, Response},
    },
    view::view,
};

/// Why the handoff page cannot go on to the dashboard.
enum Refusal {
    /// The browser must sign in with a passkey first.
    SignIn,
    /// The account does not administer Piquel.
    NoAccess,
    /// The handoff, or its proof, was refused, saying why.
    Alert(ApiError),
}

impl From<AdminError> for Refusal {
    /// What the handoff page does about `error`, which is logged.
    fn from(error: AdminError) -> Self {
        error.log_refusal();
        match error {
            AdminError::SessionEnded | AdminError::StepUpRequired(_) => Self::SignIn,
            AdminError::NotAdministrator => Self::NoAccess,
            error => Self::Alert(error.into()),
        }
    }
}

impl From<ApiError> for Refusal {
    /// The page says why.
    fn from(error: ApiError) -> Self {
        Self::Alert(error)
    }
}

impl WebApplication {
    /// `GET /admin`: goes on to the dashboard, or asks for the passkey proof the
    /// dashboard asked for.
    pub(in crate::web) async fn admin(cx: &Cx) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let sign_in = web.dashboard_sign_in()?;
        let query: HandoffQuery = Self::query(cx)?;
        let Some(owner) = web.owner(cx).await? else {
            return web
                .answer_handoff(cx, sign_in, &query, Refusal::SignIn)
                .await;
        };
        if query.confirm.0 {
            return web.handoff_page(cx, sign_in, &query, None).await;
        }
        match sign_in.hand_off(&owner, &query, None).await {
            Ok(target) => Ok(see_other(target).into_response(cx)?),
            Err(error) => web.answer_handoff(cx, sign_in, &query, error.into()).await,
        }
    }

    /// `POST /admin`: verifies the passkey proof its form posted, for the browser's
    /// session only, then goes on to the dashboard, confirmed now.
    pub(in crate::web) async fn admin_proof(cx: &Cx, body: Body) -> Result<Response, Failure> {
        let web = app_context::<Self>(cx);
        let sign_in = web.dashboard_sign_in()?;
        let posted: HandoffProof = Self::form(cx, body).await?;
        let query = HandoffQuery {
            state: posted.state,
            return_to: posted.return_to,
            confirm: Checkbox(true),
        };
        let Some(owner) = web.owner(cx).await? else {
            return web
                .answer_handoff(cx, sign_in, &query, Refusal::SignIn)
                .await;
        };
        match web
            .prove(cx, sign_in, &owner, &query, &posted.assertion)
            .await
        {
            Ok(target) => Ok(see_other(target).into_response(cx)?),
            Err(refusal) => web.answer_handoff(cx, sign_in, &query, refusal).await,
        }
    }

    /// Verifies `owner`'s passkey `assertion` for the handoff `query` asks for,
    /// and hands off, confirmed: the dashboard URL to go on to.
    async fn prove(
        &self,
        cx: &Cx,
        sign_in: &DashboardSignIn,
        owner: &Owner,
        query: &HandoffQuery,
        assertion: &str,
    ) -> Result<url::Url, Refusal> {
        let proof = self
            .passkeys
            .verify_admin_proof(headers(cx), owner, assertion)
            .await?;
        Ok(sign_in.hand_off(owner, query, Some(proof)).await?)
    }

    /// Answers the handoff `query` that `refusal` stopped: a passkey sign-in that
    /// comes back to it, the account's lack of access, or the page again, saying
    /// why.
    async fn answer_handoff(
        &self,
        cx: &Cx,
        sign_in: &DashboardSignIn,
        query: &HandoffQuery,
        refusal: Refusal,
    ) -> Result<Response, Failure> {
        match refusal {
            Refusal::SignIn => {
                let here = query.on(routes::page::ADMIN)?;
                let login = LoginQuery {
                    return_to: Some(here),
                    acr: Some(Acr::PhishingResistant),
                    ..LoginQuery::default()
                }
                .on(routes::page::LOGIN)?;
                Ok(see_other(login).into_response(cx)?)
            }
            Refusal::NoAccess => {
                let page = view! { cx => piquel_ui::no_access(home: routes::page::settings::HOME) };
                Ok(self
                    .render(
                        cx,
                        StatusCode::FORBIDDEN,
                        Title::Dashboard.as_str(),
                        Area::SignIn,
                        &[],
                        page,
                    )
                    .await?)
            }
            Refusal::Alert(error) => self.handoff_page(cx, sign_in, query, Some(error)).await,
        }
    }

    /// The page asking for the passkey proof of the handoff `query`, at the status
    /// and saying why of `refused`, if anything was. Its form may go on to the
    /// dashboard.
    async fn handoff_page(
        &self,
        cx: &Cx,
        sign_in: &DashboardSignIn,
        query: &HandoffQuery,
        refused: Option<ApiError>,
    ) -> Result<Response, Failure> {
        let (status, alert) = refused.as_ref().map_or((StatusCode::OK, None), |error| {
            let (status, message) = error.public();
            (status, Some(message))
        });
        let action = uri(cx).path();
        let page = view! { cx =>
            piquel_ui::handoff_proof(
                action: action,
                proof: routes::passkey::ADMIN_PROOF,
                query: query,
                alert: alert,
            )
        };
        let dashboard = sign_in.dashboard().as_url().clone();
        Ok(self
            .render(
                cx,
                status,
                Title::Dashboard.as_str(),
                Area::SignIn,
                &[dashboard],
                page,
            )
            .await?)
    }

    /// Signing in to the dashboard, which a deployment without one cannot do.
    fn dashboard_sign_in(&self) -> Result<&DashboardSignIn, Failure> {
        self.dashboard.as_ref().ok_or_else(|| {
            OAuthCode::InvalidRequest
                .reject("this deployment serves no admin dashboard")
                .into()
        })
    }
}
