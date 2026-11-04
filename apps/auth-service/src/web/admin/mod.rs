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
/// The audit chain's state, and the checkpoints it may be pruned through.
mod audit;
/// The OIDC clients, one client, and the changes made to them.
mod clients;
/// The outbound delivery queue.
mod deliveries;
/// The reserved and released handles, and the accounts holding a reserved one.
mod handles;
/// Signup invitations.
mod invitations;
/// Signing keys.
mod keys;
/// Domain events.
mod lists;
/// The origins approved for clients' pages to sign users in with passkeys.
mod origins;
/// What needs attention, and what the service is doing now.
mod overview;
/// What a change makes and its page shows once, across the change's redirect.
mod reveal;
/// An account's settings, which administrators change on its owner's behalf.
mod settings;
#[cfg(test)]
mod tests;
/// Account search, one account, and the changes made to it.
mod users;

use crate::{
    AdminError, AdminService, AuthConfig, KeyStore, MAX_REQUEST_BODY_BYTES,
    account::{AccountError, AccountService},
    admin::{AdminOperation, DashboardSignIn, SignedInAdmin},
    assets::EmbeddedAssets,
    config::{DashboardConfig, PolicyLinks},
    federation::ReturnTo,
    recovery::RecoveryLinks,
    routes,
    security::{ApiError, BrowserCookie, RequestContext},
};
use axum::http::header::InvalidHeaderValue;
use chrono::Duration;
use piquel_common::{ErrorChain, config::Origin};
use piquel_crypto::{KeyEncryptionKey, NoteVerifier};
use piquel_repository::Database;
use piquel_telemetry::HttpTelemetry;
use piquel_ui::{Dashboard, DashboardTab, Health, PreferenceChange, Search, Who};
use serde::Deserialize;
use std::{
    future::Future,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration as StdDuration, Instant},
};
use topcoat::{
    Error, Result,
    context::{Cx, app_context, memoize},
    router::{
        Body, BodyLimit, HeaderValue, Method, Next, OriginPolicy, Route, Router, StatusCode,
        content::Form,
        error::see_other,
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
/// How long every page shows the health the overview last found, before a page
/// reads it again: the status bar must not cost each page the overview's queries.
const HEALTH_FOR: StdDuration = StdDuration::from_secs(60);

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
    /// The server's own audit key, which the audit page verifies with when none
    /// is committed for this environment.
    audit_key: NoteVerifier,
    /// Seals what a change shows once, across its redirect.
    kek: Arc<KeyEncryptionKey>,
    /// The signing keys, which the signing keys page rotates and revokes.
    keys: KeyStore,
    /// Every answer's Content-Security-Policy.
    policy: HeaderValue,
    /// Piquel's policies on piquel.fr, which every page's footer links.
    policies: PolicyLinks,
    /// The health the overview last found, and when, shared by every page.
    health: Arc<Mutex<Option<(Instant, Health)>>>,
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
            "default-src 'none'; style-src {}; font-src 'self'; form-action 'self' {}; \
             frame-ancestors 'none'; base-uri 'none'",
            dashboard.origin.join(&EmbeddedAssets::STYLESHEET.path()),
            auth.join(routes::page::ADMIN),
        );
        Ok(Self {
            service: AdminService::new(database.clone(), config.email.smtp.is_some()),
            account: AccountService::new(database.clone()),
            keys: KeyStore::new(database.clone(), Arc::clone(&config.key_encryption_key)),
            sign_in: DashboardSignIn::new(database, auth.clone(), dashboard.origin.clone()),
            auth,
            invitations: config.passkey.invite_required,
            links: config.email.recovery_links.clone(),
            audit_key: config.audit.verifier().clone(),
            kek: config.key_encryption_key.clone(),
            policy: HeaderValue::try_from(policy)?,
            policies: config.oidc.policies.clone(),
            health: Arc::default(),
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
            .route(overview::overview)
            .route(preferences)
            .route(sign_in)
            .route(sign_out)
            // The settings administrators share with owners, the account
            // service's operations.
            .route(settings::sign_in)
            .route(settings::emails)
            .route(settings::apps)
            .route(settings::history);
        let pages = AdminOperation::ALL
            .iter()
            .filter_map(|operation| Self::page(*operation))
            .fold(pages, topcoat::router::RouterBuilder::route)
            .build();
        let service = TowerService::new(pages);
        let router =
            routes::dashboard::PREFIXES
                .iter()
                .fold(axum::Router::new(), |router, prefix| {
                    let router = router.route_service(prefix, service.clone());
                    match prefix.trim_end_matches('/') {
                        "" => router,
                        prefix => {
                            router.route_service(&format!("{prefix}/{{*rest}}"), service.clone())
                        }
                    }
                });
        // The stylesheet and the fonts it links, the dashboard's only files.
        EmbeddedAssets::SHARED.iter().fold(router, |router, asset| {
            router.route(
                &asset.path(),
                axum::routing::get(|uri: axum::http::Uri| {
                    std::future::ready(EmbeddedAssets::serve(uri.path()))
                }),
            )
        })
    }

    /// The page running `operation`, or `None` when only the CLI runs it, for the
    /// reason next to its arm.
    fn page(operation: AdminOperation) -> Option<&'static dyn Route> {
        type Op = AdminOperation;
        Some(match operation {
            Op::SearchUsers => &users::search,
            Op::ViewUser => &users::detail,
            Op::DisableUser => &users::disable,
            Op::EnableUser => &users::enable,
            Op::ScheduleDeletion => &users::delete,
            Op::RestoreUser => &users::restore,
            Op::RevokeUserSessions => &users::revoke_sessions,
            Op::RevokeSession => &users::revoke_session,
            Op::RenameHandle => &settings::handle,
            Op::RecoverAccount => &users::recover,
            Op::UndoRecovery => &users::undo_recovery,
            Op::ListInvitations => &invitations::list,
            Op::CreateInvitation => &invitations::create,
            Op::RevokeInvitation => &invitations::revoke,
            Op::ListClients => &clients::list,
            Op::ViewClient => &clients::detail,
            Op::CreateClient => &clients::create,
            Op::UpdateClient => &clients::edit,
            Op::EnableClient => &clients::enable,
            Op::DisableClient => &clients::disable,
            Op::SuspendClient => &clients::suspend,
            Op::UnsuspendClient => &clients::unsuspend,
            Op::DeleteClient => &clients::delete,
            Op::RotateClientSecret => &clients::rotate,
            Op::ListEvents => &lists::events,
            Op::VerifyAuditChain => &audit::verify,
            Op::ListAdministrators => &administrators::list,
            Op::GrantAdministrator => &administrators::grant,
            Op::RevokeAdministrator => &administrators::revoke,
            Op::ApproveRelatedOrigin => &origins::approve,
            Op::RemoveRelatedOrigin => &origins::remove,
            Op::CheckHandles => &handles::check,
            Op::ReleaseHandle => &handles::release,
            Op::ReserveHandle => &handles::reserve,
            Op::UnreserveHandle => &handles::unreserve,
            Op::ListDeliveries => &deliveries::list,
            Op::RetryDelivery => &deliveries::retry,
            Op::CancelDelivery => &deliveries::cancel,
            Op::ListSigningKeys => &keys::list,
            Op::RotateSigningKey => &keys::rotate,
            Op::RevokeSigningKey => &keys::revoke,
            // Purging at once cannot be undone, so only the terminal offers it.
            Op::PurgeUser
            // Importing takes the deployment's PEM private key, which must never
            // pass through a browser: the terminal reads it from a file or the
            // environment, into an empty key set only.
            | Op::ImportSigningKey
            // A deployment applies its own clients, with the secret it generated:
            // only the terminal takes a secret. The dashboard registers clients
            // with `CreateClient`, and Piquel makes their secrets.
            | Op::ApplyClient
            // Pruning needs the schema owner, which auth never holds: the audit page
            // shows the command instead.
            | Op::PruneAuditChain => return None,
        })
    }

    /// `message` as the dashboard shows it, starting with a capital when it starts
    /// with a plain word: admin refusals are worded to follow `error: ` at the
    /// terminal. One starting with a name, such as `redirect_uris`, keeps it.
    fn sentence(message: &str) -> String {
        let plain = message
            .split_whitespace()
            .next()
            .is_some_and(|word| word.bytes().all(|byte| byte.is_ascii_lowercase()));
        let mut chars = message.chars();
        match chars.next() {
            Some(first) if plain => first.to_ascii_uppercase().to_string() + chars.as_str(),
            _ => message.to_owned(),
        }
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
    /// anything. A refusal comes back with the message the form shows and the form
    /// as posted, so the page keeps what was typed. When the change needs a newer
    /// confirmation, or the session ended meanwhile, the browser goes through
    /// auth's handoff page and back to the form's page.
    async fn change<I, T, E, F, Fut>(
        cx: &Cx,
        form: Option<Form<I>>,
        call: F,
    ) -> Result<Option<Result<T, Refused<I>>>>
    where
        I: Clone,
        E: Into<Refusal>,
        F: FnOnce(I) -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let Some(Form(input)) = form.filter(|_| method(cx) == Method::POST) else {
            return Ok(None);
        };
        let refused = match call(input.clone()).await {
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
                (_, message) => Ok(Some(Err(Refused {
                    message: Self::sentence(message),
                    form: input,
                }))),
            },
        }
    }

    /// Like [`Self::change`], then goes to `done` once the change is made.
    async fn submit<I, E, F, Fut>(
        cx: &Cx,
        form: Option<Form<I>>,
        done: String,
        call: F,
    ) -> Result<Option<Refused<I>>>
    where
        I: Clone,
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

/// A change the service refused: why, and the form as it was posted, which the
/// page shows again so nothing typed is lost. It reads as its message.
struct Refused<I> {
    /// Why, as the form says it.
    message: String,
    /// The form, as posted.
    form: I,
}

impl<I> std::ops::Deref for Refused<I> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.message
    }
}

/// Answers a page that failed with an [`Answer`] with it, and one the service
/// refused with what the refusal means, and gives every answer the dashboard's
/// Content-Security-Policy. A `GET`'s answer deletes what a change sealed for its
/// page to show, which shows once.
#[layer("/")]
async fn answers(cx: &Cx, body: Body, next: Next<'_>) -> Result<Response> {
    let mut response = match next.run(cx, body).await {
        Ok(response) => response,
        Err(error) => AdminApplication::failed(cx, error).await?,
    };
    if method(cx) == Method::GET && BrowserCookie::DashboardReveal.value(headers(cx)).is_some() {
        BrowserCookie::DashboardReveal.clear_on(&mut response)?;
    }
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        AdminApplication::of(cx).policy.clone(),
    );
    Ok(response)
}

/// The query any dashboard page may carry: what the top bar's search box holds.
#[derive(Deserialize)]
struct SearchQuery {
    /// What was searched for, on the users page.
    q: Option<String>,
}

impl AdminApplication {
    /// Whether the service needs attention, as the overview last found, read
    /// again once that is [`HEALTH_FOR`] old. A browser that is not signed in
    /// learns nothing, and neither does a page whose read fails: the status bar
    /// never costs the page, so a failed read is logged and shows as normal.
    async fn health(cx: &Cx) -> Health {
        let app = Self::of(cx);
        let Ok(admin) = Self::admin(cx).await else {
            return Health::Normal;
        };
        let cached = app
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .filter(|(read, _)| read.elapsed() < HEALTH_FOR)
            .map(|(_, health)| health);
        if let Some(health) = cached {
            return health;
        }
        match app.service.overview(&admin.operator).await {
            Ok(overview) => Self::remember_health(cx, &overview),
            Err(error) => {
                tracing::warn!(error = %ErrorChain(&error), "the health check failed");
                Health::Normal
            }
        }
    }

    /// Keeps what `overview` found as the health every page shows for the next
    /// [`HEALTH_FOR`], and says what that is.
    pub(super) fn remember_health(cx: &Cx, overview: &crate::admin::Overview) -> Health {
        let health = match u32::try_from(overview.problems().len()).unwrap_or(u32::MAX) {
            0 => Health::Normal,
            count => Health::Warnings(count),
        };
        *Self::of(cx)
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((Instant::now(), health));
        health
    }

    /// Each tab's page, in the sidebar's order.
    fn tabs(cx: &Cx) -> [(DashboardTab, String); 10] {
        [
            (
                DashboardTab::Overview,
                href!(overview::overview).resolve(cx),
            ),
            (DashboardTab::Users, href!(users::search).resolve(cx)),
            (
                DashboardTab::Administrators,
                href!(administrators::list).resolve(cx),
            ),
            (
                DashboardTab::Invitations,
                href!(invitations::list).resolve(cx),
            ),
            (DashboardTab::Handles, href!(handles::check).resolve(cx)),
            (DashboardTab::Clients, href!(clients::list).resolve(cx)),
            (DashboardTab::Events, href!(lists::events).resolve(cx)),
            (
                DashboardTab::Deliveries,
                href!(deliveries::list).resolve(cx),
            ),
            (DashboardTab::SigningKeys, href!(keys::list).resolve(cx)),
            (DashboardTab::Audit, href!(audit::verify).resolve(cx)),
        ]
    }

    /// The tab the request's page belongs to, among `tabs`: the one whose page
    /// the path starts with, or the overview for its own path alone.
    fn current_tab(cx: &Cx, tabs: &[(DashboardTab, String)]) -> Option<DashboardTab> {
        let path = uri(cx).path();
        tabs.iter()
            .skip(1)
            .find(|(_, link)| path.starts_with(link.as_str()))
            .map(|(tab, _)| *tab)
            .or_else(|| (path == tabs[0].1).then_some(DashboardTab::Overview))
    }

    /// Answers with the page named `title` and `page`, at `status`, in the shell
    /// every page shares: the sidebar of tabs, the signed-in administrator and
    /// signing out, the account search, the service's health, and the trace ID
    /// of a server error.
    async fn render(cx: &Cx, status: StatusCode, title: &str, page: impl View) -> Result<Response> {
        // A browser that is not signed in is sent on by the page itself.
        let admin = Self::admin(cx).await.ok();
        let app = Self::of(cx);
        let tabs = Self::tabs(cx);
        let current = Self::current_tab(cx, &tabs);
        let links: &Vec<_> = &tabs
            .iter()
            .map(|(tab, link)| (*tab, link.as_str()))
            .collect();
        let (stylesheet, home, leave, search, prefer) = (
            &EmbeddedAssets::STYLESHEET.path(),
            &tabs[0].1,
            &href!(sign_out).resolve(cx),
            &href!(users::search).resolve(cx),
            &href!(preferences).resolve(cx),
        );
        // The preference forms come back here by GET, which a page answering a
        // POST cannot show again, so those come back to the overview.
        let here = if method(cx) == Method::POST {
            home.as_str()
        } else {
            uri(cx).path_and_query().map_or("/", |path| path.as_str())
        };
        let searched = parse_query_params::<SearchQuery>(cx)
            .ok()
            .and_then(|query| query.q)
            .unwrap_or_default();
        let administrator = admin.map(|admin| Who {
            user: None,
            name: admin.handle.as_str(),
            handle: admin.handle.as_str(),
            administrator: true,
        });
        // The avatar leads to the administrator's own settings, on auth.
        let me = app.auth.join(routes::page::settings::HOME);
        let health = Self::health(cx).await;
        let environment = app.auth.host();
        let dashboard = Dashboard {
            title,
            home,
            administrator,
            me: &me,
            tabs: links,
            current,
            sign_out: leave,
            preferences: BrowserCookie::read_preferences(headers(cx)),
            preferences_action: prefer,
            here,
            health: Some(health),
            environment,
            policies: app.policies.links(),
            search: Search {
                action: search,
                name: "q",
                placeholder: "Search by handle, name, email or ID",
                value: &searched,
            },
            reference: HttpTelemetry::trace_id(status),
        };
        let page = Child::new(page);
        let html = view! { cx =>
            piquel_ui::document(
                title: title,
                stylesheet: stylesheet,
                preferences: dashboard.preferences,
                admin: true,
                piquel_ui::dashboard_frame(dashboard: &dashboard, (page))
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
    /// admin or account service refused. Other failures answer as Topcoat does,
    /// such as a redirect, except that a server error is logged, since Topcoat logs
    /// none, and its page shows its trace ID.
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
                return Self::render(cx, StatusCode::FORBIDDEN, "No access", page).await;
            }
        }
        // A refusal shared with another handle, such as the memoized sign-in's,
        // fails the page.
        let refused = match error.downcast::<AdminError>() {
            Ok(refused) => ApiError::from(refused),
            Err(failed) => match failed.into_error().downcast::<AccountError>() {
                Ok(refused) => ApiError::from(refused),
                Err(failed) => return Self::unexplained(cx, failed.into_error()).await,
            },
        };
        let (status, detail) = refused.public();
        let page = view! { cx =>
            piquel_ui::dashboard_failure(title: "That did not work", detail: Self::sentence(detail))
        };
        Self::render(cx, status, "Refused", page).await
    }

    /// What a page that failed with `error`, which neither service explains,
    /// answers: Topcoat's answer, unless it is a server error, which is logged and
    /// said on the dashboard's page.
    async fn unexplained(cx: &Cx, error: Error) -> Result<Response> {
        let answered = error.clone().into_response(cx)?;
        let status = answered.status();
        if !status.is_server_error() {
            return Ok(answered);
        }
        ApiError::log_error(&*error);
        let page = view! { cx =>
            piquel_ui::dashboard_failure(
                title: "That did not work",
                detail: "Something went wrong on our side. Please try again.",
            )
        };
        Self::render(cx, status, "Error", page).await
    }
}

/// `/preferences`: keeps the theme or sidebar width a page's form chose, in
/// cookies on the dashboard's origin, and goes back to the page, by `POST`; a
/// `GET` goes to the overview.
#[route([GET, POST] "/preferences")]
async fn preferences(cx: &Cx, form: Option<Form<PreferenceChange>>) -> Result<Response> {
    let home = href!(overview::overview).resolve(cx);
    let Some(Form(change)) = form.filter(|_| method(cx) == Method::POST) else {
        return see_other(home).into_response(cx);
    };
    // The dashboard's pages send paths; anything else goes to the overview.
    let back =
        ReturnTo::parse(Some(&change.return_to)).map_or(home, |back| back.as_str().to_owned());
    let mut response = see_other(back).into_response(cx)?;
    BrowserCookie::set_preferences_on(&mut response, &change)?;
    Ok(response)
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
            let retry = href!(overview::overview).resolve(cx);
            let page = view! { cx =>
                piquel_ui::dashboard_failure(
                    title: "Sign-in did not work",
                    detail: "The sign-in link expired, was used already, or was opened in another browser.",
                    retry: retry,
                )
            };
            AdminApplication::render(cx, StatusCode::BAD_REQUEST, "Sign in", page).await
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
        &href!(overview::overview).resolve(cx),
        &app.auth.join(routes::page::LOGOUT),
    );
    let page = view! { cx =>
        piquel_ui::dashboard_signed_out(sign_in: again, auth_sign_out: auth_sign_out)
    };
    AdminApplication::render(cx, StatusCode::OK, "Signed out", page).await
}
