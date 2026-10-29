//! The admin dashboard at admin.piquel.fr, which auth serves on its admin
//! listener: pages over [`AdminService`], and over [`AccountService`] for the
//! settings administrators share with owners, in-process, for the administrator
//! [`DashboardSignIn`] finds from the dashboard's own session cookie. Each page
//! renders `piquel-ui`'s dashboard components, or the owner's settings sections.
//!
//! The pages declare their own paths, under [`routes::dashboard::PREFIXES`], and
//! the admin listener mounts them there, never as the fallback, so the listener's
//! security layer gives each its request context and rate budget. Every answer
//! carries the dashboard's Content-Security-Policy: no script, the stylesheet
//! alone, and forms posting only to the dashboard, whose answer may go on to
//! auth's handoff page.
//!
//! A browser without a dashboard session goes through auth's handoff page and
//! back. A page that changes something needs the dashboard's own passkey
//! confirmation, recent enough that the service still accepts it once the form
//! is submitted; without one, it sends the browser to confirm on auth's handoff
//! page, and back to the page.

/// The administrators.
mod administrators;
/// Signup invitations.
mod invitations;
/// The OIDC clients and domain events.
mod lists;
/// An account's settings, which administrators change on its owner's behalf.
mod settings;
#[cfg(test)]
mod tests;
/// Account search, one account, and the changes made to it.
mod users;

use crate::{
    AdminError, AdminService, AuthConfig, MAX_REQUEST_BODY_BYTES,
    account::{AccountError, AccountService},
    admin::{AdminOperation, DashboardSignIn, SignedInAdmin},
    assets::EmbeddedAssets,
    config::DashboardConfig,
    recovery::RecoveryLinks,
    routes,
    security::{ApiError, RequestContext},
};
use axum::http::header::InvalidHeaderValue;
use chrono::Duration;
use piquel_common::config::Origin;
use piquel_repository::Database;
use piquel_ui::DashboardTab;
use serde::Deserialize;
use std::{
    future::Future,
    sync::{Mutex, PoisonError},
};
use topcoat::{
    Error, Result,
    context::{Cx, app_context, memoize},
    router::{
        Body, BodyLimit, HeaderValue, Method, Next, OriginPolicy, Route, Router, StatusCode,
        content::Form,
        error::{SeeOther, see_other},
        header, href, layer, parse_query_params,
        request::{extensions, headers, method, uri},
        response::{IntoResponse, Response},
        route,
        tower::TowerService,
    },
    view::{Child, View, ViewExt, view},
};

/// How long an administrator has to fill in and submit a change's form, once
/// shown: showing it asks for a confirmation this much newer than the service
/// needs.
const FORM_TIME: Duration = Duration::minutes(2);

/// The dashboard's pages, and what every one of them needs.
#[derive(Clone)]
pub(crate) struct AdminApplication {
    /// Every administrative operation.
    service: AdminService,
    /// The settings administrators share with owners.
    account: AccountService,
    /// Who is signed in, and signing in through auth.
    sign_in: DashboardSignIn,
    /// Auth's origin: invitations link its registration page, and the dashboard
    /// links the account's settings and signing out of Piquel.
    auth: Origin,
    /// Whether signup needs an invitation, so the dashboard manages them.
    invitations: bool,
    /// Derives the links recoveries mail.
    links: RecoveryLinks,
    /// Every answer's Content-Security-Policy.
    policy: HeaderValue,
}

/// What a page answers in its place, such as the redirect through auth's handoff
/// page, which sets the state cookie. A page fails with it, and [`answers`] sends
/// it.
#[derive(Debug, thiserror::Error)]
#[error("the dashboard answers for the page")]
struct Answer(Mutex<Option<Response>>);

impl Answer {
    /// Fails the page with `response`.
    fn error(response: Response) -> Error {
        Self(Mutex::new(Some(response))).into()
    }

    /// The response, the first time it is asked for.
    fn take(&self) -> Option<Response> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// What the dashboard does about a change the service refused.
enum Refusal {
    /// The change needs a newer confirmation: the browser confirms on auth's
    /// handoff page, and comes back to the form's page.
    Confirm,
    /// The administrator's session ended: the browser signs in again, and comes
    /// back to the form's page.
    SignIn,
    /// The page explains it instead, and logs it: the account administers
    /// nothing.
    Page(AdminError),
    /// The form says why.
    Form(ApiError),
}

impl From<AdminError> for Refusal {
    /// What the dashboard does about `error`, which it logs.
    fn from(error: AdminError) -> Self {
        match error {
            // The page logs it.
            error @ AdminError::NotAdministrator => return Self::Page(error),
            ref error => error.log_refusal(),
        }
        match error {
            AdminError::StepUpRequired(_) => Self::Confirm,
            AdminError::SessionEnded => Self::SignIn,
            error => Self::Form(error.into()),
        }
    }
}

impl From<AccountError> for Refusal {
    /// What the dashboard does about a settings change refused for its
    /// administrator, or for the account's own rules.
    fn from(error: AccountError) -> Self {
        match error {
            AccountError::Operator(error) => error.into(),
            error => Self::Form(error.into()),
        }
    }
}

/// The query auth's handoff sends the browser back with.
#[derive(Deserialize)]
struct SignInQuery {
    /// The handoff code.
    code: String,
}

impl AdminApplication {
    /// Builds the dashboard at `dashboard`'s origin over `database`, signing in
    /// through auth's handoff page, as `config` sets auth up.
    pub(crate) fn new(
        database: Database,
        config: &AuthConfig,
        dashboard: &DashboardConfig,
    ) -> Result<Self, InvalidHeaderValue> {
        let auth = config.passkey.origin.clone();
        // A form's answer may send the browser on to auth's handoff page, to sign
        // in or confirm again: browsers apply `form-action` to its redirects too.
        let policy = format!(
            "default-src 'none'; style-src {}; form-action 'self' {}; \
             frame-ancestors 'none'; base-uri 'none'",
            dashboard.origin.join(&EmbeddedAssets::STYLESHEET.path()),
            auth.join(routes::page::ADMIN),
        );
        Ok(Self {
            service: AdminService::new(database.clone(), config.email.smtp.is_some()),
            account: AccountService::new(database.clone()),
            sign_in: DashboardSignIn::new(database, auth.clone(), dashboard.origin.clone()),
            auth,
            invitations: config.passkey.invite_required,
            links: config.email.recovery_links.clone(),
            policy: HeaderValue::try_from(policy)?,
        })
    }

    /// The dashboard's routes: its pages, mounted on each of their prefixes and
    /// every path below, and its stylesheet.
    pub(crate) fn routes(self) -> axum::Router {
        let pages = Router::builder()
            .app_context(self)
            // The security layer already accepts forms only from the dashboard's own
            // pages, by a stricter rule: Topcoat's also takes `Sec-Fetch-Site: none`.
            .origin_policy(OriginPolicy::dangerous_disable())
            // axum's body limit does not reach Topcoat, whose own default is 2 MiB.
            .layer(BodyLimit::max(MAX_REQUEST_BODY_BYTES))
            .layer(answers)
            .route(root)
            .route(sign_in)
            .route(sign_out)
            // The settings administrators share with owners, the account
            // service's operations.
            .route(settings::sign_in)
            .route(settings::emails);
        let pages = AdminOperation::ALL
            .iter()
            .filter_map(|operation| Self::page(*operation))
            .fold(pages, topcoat::router::RouterBuilder::route)
            .build();
        let service = TowerService::new(pages);
        let stylesheet = EmbeddedAssets::STYLESHEET.path();
        routes::dashboard::PREFIXES
            .iter()
            .fold(axum::Router::new(), |router, prefix| {
                let router = router.route_service(prefix, service.clone());
                match prefix.trim_end_matches('/') {
                    "" => router,
                    prefix => router.route_service(&format!("{prefix}/{{*rest}}"), service.clone()),
                }
            })
            .route(
                &stylesheet,
                axum::routing::get(|uri: axum::http::Uri| {
                    std::future::ready(EmbeddedAssets::serve(uri.path()))
                }),
            )
    }

    /// The page running `operation`, or `None` when only the CLI runs it, for now.
    fn page(operation: AdminOperation) -> Option<&'static dyn Route> {
        type Op = AdminOperation;
        Some(match operation {
            Op::SearchUsers => &users::search,
            Op::ViewUser => &users::detail,
            Op::DisableUser => &users::disable,
            Op::EnableUser => &users::enable,
            Op::RevokeUserSessions => &users::revoke_sessions,
            Op::RevokeSession => &users::revoke_session,
            Op::RenameHandle => &settings::handle,
            Op::RecoverAccount => &users::recover,
            Op::UndoRecovery => &users::undo_recovery,
            Op::ListInvitations => &invitations::list,
            Op::CreateInvitation => &invitations::create,
            Op::RevokeInvitation => &invitations::revoke,
            Op::ListClients => &lists::clients,
            Op::ListEvents => &lists::events,
            Op::ListAdministrators => &administrators::list,
            Op::GrantAdministrator => &administrators::grant,
            Op::RevokeAdministrator => &administrators::revoke,
            Op::ViewClient
            | Op::CreateClient
            | Op::ApplyClient
            | Op::UpdateClient
            | Op::EnableClient
            | Op::DisableClient
            | Op::SuspendClient
            | Op::UnsuspendClient
            | Op::DeleteClient
            | Op::RotateClientSecret
            | Op::CheckHandles
            | Op::ReleaseHandle
            | Op::ListDeliveries
            | Op::RetryDelivery
            | Op::CancelDelivery => return None,
        })
    }

    /// The dashboard's application context.
    fn of(cx: &Cx) -> &Self {
        app_context::<Self>(cx)
    }

    /// The administrator signed in to the dashboard. A browser without a session
    /// goes through auth's handoff page, and comes back to the page.
    async fn admin(cx: &Cx) -> Result<&SignedInAdmin> {
        Self::signed_in(cx).await.map_err(Error::clone)
    }

    /// Finds the administrator once per request, so the frame and the page share
    /// one check of their rights.
    #[memoize(as_ref)]
    async fn signed_in(cx: &Cx) -> Result<SignedInAdmin> {
        let app = Self::of(cx);
        let context = RequestContext::of(extensions(cx))?;
        match app.sign_in.signed_in(context, headers(cx)).await {
            Ok(Some(admin)) => Ok(admin),
            Ok(None) => Err(app.hand_off(cx, false)),
            Err(error) => Err(error.into()),
        }
    }

    /// Requires the dashboard's passkey confirmation recent enough for a change:
    /// still for [`FORM_TIME`] when a page shows its form, and now when it takes
    /// the form posted. Without one, the browser confirms on auth's handoff page,
    /// and comes back to the page, where the administrator submits again.
    fn confirm(cx: &Cx, admin: &SignedInAdmin) -> Result<()> {
        let ahead = if method(cx) == Method::POST {
            Duration::zero()
        } else {
            FORM_TIME
        };
        if admin.operator.is_confirmed(ahead) {
            Ok(())
        } else {
            Err(Self::of(cx).hand_off(cx, true))
        }
    }

    /// Sends the browser through auth's handoff page, confirming with a passkey if
    /// `confirm`, and back to the page.
    fn hand_off(&self, cx: &Cx, confirm: bool) -> Error {
        let page = uri(cx).path_and_query().map_or("/", |page| page.as_str());
        let started = self
            .sign_in
            .start(page, confirm)
            .map_err(Error::from)
            .and_then(|(to, cookie)| {
                let mut response = see_other(to).into_response(cx)?;
                cookie.set_on(&mut response)?;
                Ok(response)
            });
        match started {
            Ok(response) => Answer::error(response),
            Err(error) => error,
        }
    }

    /// Makes the change a posted `form` asks for, with `call`. Returns nothing for
    /// a `GET`, which only shows the form: a link, even with a query, never changes
    /// anything. A refusal comes back as the message the form shows. When the
    /// change needs a newer confirmation, or the session ended meanwhile, the
    /// browser goes through auth's handoff page and back to the form's page.
    async fn change<I, T, E, F, Fut>(
        cx: &Cx,
        form: Option<Form<I>>,
        call: F,
    ) -> Result<Option<Result<T, String>>>
    where
        E: Into<Refusal>,
        F: FnOnce(I) -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let Some(Form(input)) = form.filter(|_| method(cx) == Method::POST) else {
            return Ok(None);
        };
        let refused = match call(input).await {
            Ok(value) => return Ok(Some(Ok(value))),
            Err(refused) => refused.into(),
        };
        match refused {
            Refusal::Confirm => Err(Self::of(cx).hand_off(cx, true)),
            Refusal::SignIn => Err(Self::of(cx).hand_off(cx, false)),
            Refusal::Page(error) => Err(error.into()),
            Refusal::Form(refusal) => match refusal.public() {
                (status, _) if status.is_server_error() => {
                    Err(Error::msg("an admin change failed"))
                }
                (_, message) => Ok(Some(Err(message.to_owned()))),
            },
        }
    }

    /// Like [`Self::change`], then goes to `done` once the change is made.
    async fn submit<I, E, F, Fut>(
        cx: &Cx,
        form: Option<Form<I>>,
        done: String,
        call: F,
    ) -> Result<Option<String>>
    where
        E: Into<Refusal>,
        F: FnOnce(I) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        match Self::change(cx, form, call).await? {
            Some(Ok(())) => Err(see_other(done).into()),
            Some(Err(refused)) => Ok(Some(refused)),
            None => Ok(None),
        }
    }
}

/// Answers a page that failed with an [`Answer`] with it, and one the service
/// refused with what the refusal means, and gives every answer the dashboard's
/// Content-Security-Policy.
#[layer("/")]
async fn answers(cx: &Cx, body: Body, next: Next<'_>) -> Result<Response> {
    let mut response = match next.run(cx, body).await {
        Ok(response) => response,
        Err(error) => AdminApplication::failed(cx, error).await?,
    };
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        AdminApplication::of(cx).policy.clone(),
    );
    Ok(response)
}

impl AdminApplication {
    /// Answers with `page`, at `status`, in the document every page shares: the
    /// tabs, the signed-in administrator's handle and signing out.
    async fn render(cx: &Cx, status: StatusCode, page: impl View) -> Result<Response> {
        // A browser that is not signed in is sent on by the page itself.
        let admin = Self::admin(cx).await.ok();
        let tabs = [
            (DashboardTab::Users, href!(users::search).resolve(cx)),
            (
                DashboardTab::Administrators,
                href!(administrators::list).resolve(cx),
            ),
            (
                DashboardTab::Invitations,
                href!(invitations::list).resolve(cx),
            ),
            (DashboardTab::Clients, href!(lists::clients).resolve(cx)),
            (DashboardTab::Events, href!(lists::events).resolve(cx)),
        ];
        let path = uri(cx).path();
        let current = tabs
            .iter()
            .find(|(_, link)| path.starts_with(link.as_str()))
            .map(|(tab, _)| *tab);
        let links: &Vec<_> = &tabs
            .iter()
            .map(|(tab, link)| (*tab, link.as_str()))
            .collect();
        let (stylesheet, home, leave) = (
            &EmbeddedAssets::STYLESHEET.path(),
            &href!(users::search).resolve(cx),
            &href!(sign_out).resolve(cx),
        );
        let administrator = admin.map(|admin| admin.handle.as_str());
        let page = Child::new(page);
        let html = view! { cx =>
            piquel_ui::dashboard_frame(
                title: "Admin",
                stylesheet: stylesheet,
                home: home,
                administrator: administrator,
                tabs: links,
                current: current,
                sign_out: leave,
                (page)
            )
        }
        .single()
        .await?
        .render(cx);
        (
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            html,
        )
            .into_response(cx)
    }

    /// What a page that failed with `error` answers: the [`Answer`] it carries,
    /// that an account which does not administer Piquel has no access, or why the
    /// admin or account service refused. Other failures fail the page.
    async fn failed(cx: &Cx, error: Error) -> Result<Response> {
        if let Some(response) = error.downcast_ref::<Answer>().and_then(Answer::take) {
            return Ok(response);
        }
        // The administrator's own refusal, from either service.
        let administrator = error.downcast_ref::<AdminError>().or_else(|| {
            match error.downcast_ref::<AccountError>() {
                Some(AccountError::Operator(refused)) => Some(refused),
                _ => None,
            }
        });
        if let Some(refused) = administrator {
            refused.log_refusal();
            if let AdminError::NotAdministrator = refused {
                let home = &Self::of(cx).auth.join(routes::page::settings::HOME);
                let page = view! { cx => piquel_ui::no_access(home: home.as_str()) };
                return Self::render(cx, StatusCode::FORBIDDEN, page).await;
            }
        }
        // A refusal shared with another handle, such as the memoized sign-in's,
        // fails the page.
        let refused = match error.downcast::<AdminError>() {
            Ok(refused) => ApiError::from(refused),
            Err(failed) => ApiError::from(
                failed
                    .into_error()
                    .downcast::<AccountError>()
                    .map_err(topcoat::core::DowncastError::into_error)?,
            ),
        };
        let (status, detail) = refused.public();
        let page = view! { cx =>
            piquel_ui::dashboard_failure(title: "That did not work", detail: detail)
        };
        Self::render(cx, status, page).await
    }
}

/// `/`: the account search.
#[route(GET "/")]
async fn root(cx: &Cx) -> Result<SeeOther> {
    Ok(see_other(href!(users::search).resolve(cx)))
}

/// `/sign-in`: redeems auth's handoff code, and goes on to the page the sign-in
/// started from. A code that does not work explains itself.
#[route(GET "/sign-in")]
async fn sign_in(cx: &Cx) -> Result<Response> {
    let app = AdminApplication::of(cx);
    let code = parse_query_params::<SignInQuery>(cx)
        .map(|query| query.code)
        .unwrap_or_default();
    match app.sign_in.finish(headers(cx), &code).await {
        Ok((return_to, cookie)) => {
            let mut response = see_other(return_to.as_str()).into_response(cx)?;
            cookie.set_on(&mut response)?;
            Ok(response)
        }
        Err(refused @ AdminError::InvalidHandoff) => {
            refused.log_refusal();
            let retry = href!(root).resolve(cx);
            let page = view! { cx =>
                piquel_ui::dashboard_failure(
                    title: "Sign-in did not work",
                    detail: "The sign-in link expired, was used already, or was opened in another browser.",
                    retry: retry,
                )
            };
            AdminApplication::render(cx, StatusCode::BAD_REQUEST, page).await
        }
        Err(error) => Err(error.into()),
    }
}

/// `/sign-out`: ends the dashboard's session, by `POST`, then says so, by `GET`.
/// The administrator stays signed in to Piquel, which the page links to sign out
/// of.
#[route([GET, POST] "/sign-out")]
async fn sign_out(cx: &Cx) -> Result<Response> {
    let app = AdminApplication::of(cx);
    if method(cx) == Method::POST {
        let cookie = app.sign_in.sign_out(headers(cx)).await?;
        let mut response = see_other(href!(sign_out).resolve(cx)).into_response(cx)?;
        cookie.set_on(&mut response)?;
        return Ok(response);
    }
    let (again, auth_sign_out) = (
        &href!(root).resolve(cx),
        &app.auth.join(routes::page::LOGOUT),
    );
    let page = view! { cx =>
        piquel_ui::dashboard_signed_out(sign_in: again, auth_sign_out: auth_sign_out)
    };
    AdminApplication::render(cx, StatusCode::OK, page).await
}
