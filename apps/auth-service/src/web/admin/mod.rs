//! The admin dashboard at admin.sourceorigin.dev, which auth serves on its admin
//! listener: pages over [`AdminService`], and over [`AccountService`] for the
//! settings administrators share with owners, in-process, for the administrator
//! [`DashboardSignIn`] finds from the dashboard's own session cookie. Each page
//! renders `sourceorigin-ui`'s dashboard components, or the owner's settings sections.
//!
//! The pages declare their own paths, under [`routes::dashboard::PREFIXES`], and
//! the admin listener mounts them there, never as the fallback, so the listener's
//! security layer gives each its request context and rate budget. Every answer
//! carries the dashboard's Content-Security-Policy: its own script and
//! stylesheet alone, with auth's profile pictures, fetching from the dashboard
//! only, and forms posting only to the dashboard, whose answer may go on to
//! auth's handoff page.
//!
//! A browser without a dashboard session, or whose session timed out, goes
//! through auth's handoff page, which asks for a passkey, and back. A page that
//! changes something needs the dashboard's own passkey
//! confirmation, recent enough that the service still accepts it once the form
//! is submitted; without one, it sends the browser to confirm on auth's handoff
//! page, and back to the page. The dashboard's script spares the page that trip:
//! before following a link to such a page or posting a change, as the frame says
//! it must (see `sourceorigin_ui::DashboardConfirmation`), it asks for a passkey in a
//! dialog on the page itself, [`start_confirmation`] and [`finish_confirmation`]
//! running the ceremony for the dashboard's origin, which auth lists as a related
//! origin of its RP ID. Every page still works without it.

/// The administrators.
mod administrators;
/// The alerts administrators are shown, and the updates they post on them.
mod alerts;
/// Announcements to accounts.
mod announcements;
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
    AdminError, AdminService, AuthConfig, KeyStore, MAX_DASHBOARD_BODY_BYTES,
    account::{AccountError, AccountService},
    admin::{AdminOperation, DashboardSignIn, Overview, Problem, SignedInAdmin},
    assets::EmbeddedAssets,
    config::{DashboardConfig, PolicyLinks},
    federation::ReturnTo,
    passkey::{AuthenticationFinish, PasskeyApplication},
    recovery::RecoveryLinks,
    routes,
    security::{ApiError, BrowserCookie, RequestContext},
};
use axum::http::header::InvalidHeaderValue;
use chrono::Duration;
use serde::Deserialize;
use sourceorigin_common::{ClientId, ErrorChain, UserId, config::Origin};
use sourceorigin_crypto::{KeyEncryptionKey, NoteVerifier};
use sourceorigin_repository::Database;
use sourceorigin_telemetry::HttpTelemetry;
use sourceorigin_ui::{
    Crumb, Dashboard, DashboardConfirmation, DashboardTab, Health, PreferenceChange, Search, Who,
};
use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration as StdDuration, Instant},
};
use topcoat::{
    Error, Result,
    context::{Cx, app_context, memoize},
    router::{
        Body, BodyLimit, HeaderValue, Method, Next, OriginPolicy, Route, Router, StatusCode,
        content::{Form, Json},
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
/// How long every page shows what the overview last found, before a page
/// reads it again: the status bar must not cost each page the overview's queries.
const ATTENTION_FOR: StdDuration = StdDuration::from_secs(60);

/// What the overview last found, as every page shows it: the status bar's
/// count, and the tabs the sidebar marks.
#[derive(Clone, Copy, Default)]
pub(super) struct Attention {
    /// How many things need attention: each open alert, and each other problem.
    count: u32,
    /// Whether alerts are open, which marks the Alerts tab.
    alerts: bool,
    /// Whether the overview found another problem, which marks its own tab.
    overview: bool,
}

impl Attention {
    /// What `overview` found.
    fn of(overview: &Overview) -> Self {
        let others = overview
            .problems()
            .iter()
            .filter(|problem| !matches!(problem, Problem::OpenAlerts(_)))
            .count();
        let count = u32::try_from(overview.open_alerts)
            .unwrap_or(u32::MAX)
            .saturating_add(u32::try_from(others).unwrap_or(u32::MAX));
        Self {
            count,
            alerts: overview.open_alerts > 0,
            overview: others > 0,
        }
    }

    /// The status bar's health.
    const fn health(self) -> Health {
        match self.count {
            0 => Health::Normal,
            count => Health::Warnings(count),
        }
    }

    /// The tabs the sidebar marks.
    fn tabs(self) -> Vec<DashboardTab> {
        [
            (self.overview, DashboardTab::Overview),
            (self.alerts, DashboardTab::Alerts),
        ]
        .into_iter()
        .filter_map(|(marked, tab)| marked.then_some(tab))
        .collect()
    }
}

/// What the overview last found, and when, as every page shows it. A read that
/// started before the cache was last forgotten is not kept: it may predate the
/// change that forgot it.
#[derive(Default)]
struct AttentionCache {
    /// Counts the times it was forgotten.
    generation: u64,
    /// What was found, and when.
    found: Option<(Instant, Attention)>,
}

impl AttentionCache {
    /// What was found, if less than [`ATTENTION_FOR`] ago, or else the
    /// generation a fresh read starts in.
    fn fresh(&self) -> Result<Attention, u64> {
        self.found
            .filter(|(read, _)| read.elapsed() < ATTENTION_FOR)
            .map(|(_, attention)| attention)
            .ok_or(self.generation)
    }

    /// Keeps `attention`, read from `generation` on, unless it was forgotten
    /// since.
    fn keep(&mut self, generation: u64, attention: Attention) {
        if generation == self.generation {
            self.found = Some((Instant::now(), attention));
        }
    }

    /// Forgets what was found, and any read already under way.
    fn forget(&mut self) {
        self.generation += 1;
        self.found = None;
    }
}

/// The dashboard's pages, and what every one of them needs.
#[derive(Clone)]
pub(crate) struct AdminApplication {
    /// Every administrative operation.
    service: AdminService,
    /// The settings administrators share with owners.
    account: AccountService,
    /// Who is signed in, and signing in through auth.
    sign_in: DashboardSignIn,
    /// The passkey ceremonies that confirm the dashboard on its own pages.
    passkeys: PasskeyApplication,
    /// Auth's origin: invitations link its registration page, and the dashboard
    /// links the account's settings and signing out of Origin Auth.
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
    /// SourceOrigin's policies on sourceorigin.dev, which every page's footer links.
    policies: PolicyLinks,
    /// What the overview last found, and when, shared by every page.
    attention: Arc<Mutex<AttentionCache>>,
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
    /// The change needs a newer confirmation, or the administrator's session
    /// ended: the browser proves a passkey on auth's handoff page, and comes back
    /// to the form's page.
    HandOff,
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
            AdminError::StepUpRequired(_) | AdminError::SessionEnded => Self::HandOff,
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
    /// through auth's handoff page, as `config` sets auth up, and confirming with
    /// `passkeys` on its own pages.
    pub(crate) fn new(
        database: Database,
        config: &AuthConfig,
        dashboard: &DashboardConfig,
        passkeys: PasskeyApplication,
    ) -> Result<Self, InvalidHeaderValue> {
        let auth = config.passkey.origin.clone();
        // A form's answer may send the browser on to auth's handoff page, to sign
        // in or confirm again: browsers apply `form-action` to its redirects too.
        // The script fetches only the passkey ceremonies of the dashboard's own.
        // Profile pictures are served by auth.
        let policy = format!(
            "default-src 'none'; script-src {}; style-src {}; font-src 'self'; img-src {}; \
             connect-src 'self'; form-action 'self' {}; frame-ancestors 'none'; \
             base-uri 'none'",
            dashboard
                .origin
                .join(&EmbeddedAssets::DASHBOARD_SCRIPT.path()),
            dashboard.origin.join(&EmbeddedAssets::STYLESHEET.path()),
            auth.serialized(),
            auth.join(routes::page::ADMIN),
        );
        Ok(Self {
            service: AdminService::new(database.clone(), config.email.smtp.is_some()),
            account: AccountService::new(database.clone()),
            keys: KeyStore::new(database.clone(), Arc::clone(&config.key_encryption_key)),
            sign_in: DashboardSignIn::new(database, auth.clone(), dashboard.origin.clone()),
            passkeys,
            auth,
            invitations: config.passkey.invite_required,
            links: config.email.recovery_links.clone(),
            audit_key: config.audit.verifier().clone(),
            kek: config.key_encryption_key.clone(),
            policy: HeaderValue::try_from(policy)?,
            policies: config.oidc.policies.clone(),
            attention: Arc::default(),
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
            .layer(BodyLimit::max(MAX_DASHBOARD_BODY_BYTES))
            .layer(answers)
            .route(overview::overview)
            .route(preferences)
            .route(sign_in)
            .route(start_confirmation)
            .route(finish_confirmation)
            .route(sign_out)
            // The settings administrators share with owners, the account
            // service's operations.
            .route(settings::sign_in)
            .route(settings::profile)
            .route(settings::emails)
            .route(settings::apps)
            .route(settings::history)
            .route(settings::notifications)
            .route(settings::display_name)
            // `ListAlerts` lists the alerts that cleared on a page of their own.
            .route(alerts::previous);
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
        // The stylesheet, the fonts it links and the script, the dashboard's
        // only files.
        let assets = EmbeddedAssets::SHARED
            .iter()
            .chain([&EmbeddedAssets::DASHBOARD_SCRIPT]);
        assets.fold(router, |router, asset| {
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
            Op::ListAnnouncements => &announcements::list,
            Op::ViewAnnouncement => &announcements::show,
            Op::DraftAnnouncement => &announcements::draft,
            Op::EditAnnouncement => &announcements::edit,
            Op::DiscardAnnouncement => &announcements::discard,
            Op::SendAnnouncement => &announcements::send,
            Op::ListAlerts => &alerts::list,
            Op::UpdateAlert => &alerts::update,
            // Purging at once cannot be undone, so only the terminal offers it.
            Op::PurgeUser
            // Importing takes the deployment's PEM private key, which must never
            // pass through a browser: the terminal reads it from a file or the
            // environment, into an empty key set only.
            | Op::ImportSigningKey
            // A deployment applies its own clients, with the secret it generated:
            // only the terminal takes a secret. The dashboard registers clients
            // with `CreateClient`, and Origin Auth makes their secrets.
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
            Ok(None) => Err(app.hand_off(cx)),
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
            Err(Self::of(cx).hand_off(cx))
        }
    }

    /// Sends the browser through auth's handoff page, which signs it in or
    /// confirms its session with a passkey, and back to the page.
    fn hand_off(&self, cx: &Cx) -> Error {
        let page = uri(cx).path_and_query().map_or("/", |page| page.as_str());
        let started = self
            .sign_in
            .start(page)
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
            Refusal::HandOff => Err(Self::of(cx).hand_off(cx)),
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

    /// The answer of a JSON route the dashboard's script calls: `answered`, or its
    /// refusal in JSON, as auth's own JSON routes answer.
    fn json(answered: Result<axum::response::Response, ApiError>) -> Response {
        answered
            .unwrap_or_else(axum::response::IntoResponse::into_response)
            .map(Body::new)
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
    /// again once that is [`ATTENTION_FOR`] old. A browser that is not signed in
    /// learns nothing, and neither does a page whose read fails: the status bar
    /// never costs the page, so a failed read is logged and shows as normal.
    async fn attention(cx: &Cx) -> Attention {
        let app = Self::of(cx);
        let Ok(admin) = Self::admin(cx).await else {
            return Attention::default();
        };
        let generation = match Self::attention_cache(cx).fresh() {
            Ok(attention) => return attention,
            Err(generation) => generation,
        };
        match app.service.overview(&admin.operator).await {
            Ok(overview) => Self::remember_attention(cx, generation, &overview),
            Err(error) => {
                tracing::warn!(error = %ErrorChain(&error), "the health check failed");
                Attention::default()
            }
        }
    }

    /// The cache of what every page shows.
    fn attention_cache(cx: &Cx) -> MutexGuard<'_, AttentionCache> {
        Self::of(cx)
            .attention
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The generation a read of the overview starts in, which
    /// [`Self::remember_attention`] takes once it is done.
    pub(super) fn attention_generation(cx: &Cx) -> u64 {
        Self::attention_cache(cx).generation
    }

    /// Keeps what `overview`, read from `generation` on, found as what every
    /// page shows for the next [`ATTENTION_FOR`], and says what that is.
    pub(super) fn remember_attention(cx: &Cx, generation: u64, overview: &Overview) -> Attention {
        let attention = Attention::of(overview);
        Self::attention_cache(cx).keep(generation, attention);
        attention
    }

    /// Forgets what every page shows, so the next page reads it again: an
    /// administrator's own change, such as an update on an alert, shows at once.
    pub(super) fn forget_attention(cx: &Cx) {
        Self::attention_cache(cx).forget();
    }

    /// Each tab's page, in the sidebar's order.
    fn tabs(cx: &Cx) -> [(DashboardTab, String); 12] {
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
            (
                DashboardTab::Announcements,
                href!(announcements::list).resolve(cx),
            ),
            (DashboardTab::Alerts, href!(alerts::list).resolve(cx)),
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

    /// The page the request's page is under, inside `current`, among `tabs`, if
    /// any, named and linked in the crumb: the account under Users or
    /// Administrators, or the client under Clients, which a page such as
    /// `/users/{account}/disable` changes. The account's or client's own page,
    /// and a tab's other pages, have none. A parent that cannot be read, such as
    /// on the error page of an account that does not exist, is left out: the
    /// page itself says what went wrong.
    async fn parent(
        cx: &Cx,
        admin: Option<&SignedInAdmin>,
        tabs: &[(DashboardTab, String)],
        current: Option<DashboardTab>,
    ) -> Option<(String, String)> {
        let (admin, current) = (admin?, current?);
        let path = uri(cx).path();
        let (_, tab) = tabs.iter().find(|(tab, _)| *tab == current)?;
        // Only a page below the account's or client's has one: `/clients/new`
        // names no client, whatever its registry holds.
        let below = path.strip_prefix(tab.as_str())?.strip_prefix('/')?;
        let (id, _) = below.split_once('/')?;
        let service = &Self::of(cx).service;
        match current {
            // An administrator's page is their account's, under Users.
            DashboardTab::Users | DashboardTab::Administrators => {
                let id: UserId = id.parse().ok()?;
                let handle = service.user_handle(&admin.operator, id).await.ok()?;
                Some((handle.to_string(), Self::account(cx, id)))
            }
            DashboardTab::Clients => {
                let id: ClientId = id.parse().ok()?;
                let href = href!(clients::detail, clients::Client(id.clone())).resolve(cx);
                if path == href {
                    return None;
                }
                let details = service.client_details(&admin.operator, &id).await.ok()?;
                Some((Self::title(&details.client).to_owned(), href))
            }
            _ => None,
        }
    }

    /// Answers with the page named `title` and `page`, at `status`, in the shell
    /// every page shares: the sidebar of tabs, the signed-in administrator and
    /// signing out, the account search, the service's health, and the trace ID
    /// of a server error.
    async fn render<'a>(
        cx: &Cx,
        status: StatusCode,
        title: impl Into<Crumb<'a>>,
        page: impl View,
    ) -> Result<Response> {
        let title = title.into();
        // A browser that is not signed in is sent on by the page itself.
        let admin = Self::admin(cx).await.ok();
        let app = Self::of(cx);
        let tabs = Self::tabs(cx);
        let current = Self::current_tab(cx, &tabs);
        let parent = Self::parent(cx, admin, &tabs, current).await;
        let links: &Vec<_> = &tabs
            .iter()
            .map(|(tab, link)| (*tab, link.as_str()))
            .collect();
        let (stylesheet, script, home, leave, search, prefer) = (
            &EmbeddedAssets::STYLESHEET.path(),
            &EmbeddedAssets::DASHBOARD_SCRIPT.path(),
            &tabs[0].1,
            &href!(sign_out).resolve(cx),
            &href!(users::search).resolve(cx),
            &href!(preferences).resolve(cx),
        );
        let (start, finish) = (
            &href!(start_confirmation).resolve(cx),
            &href!(finish_confirmation).resolve(cx),
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
        let picture = admin.and_then(|admin| Self::picture(cx, admin.picture));
        let administrator = admin.map(|admin| Who {
            name: admin.handle.as_str(),
            handle: admin.handle.as_str(),
            picture: picture.as_deref(),
            administrator: true,
        });
        // The avatar leads to the administrator's own settings, on auth.
        let me = app.auth.join(routes::page::settings::HOME);
        let attention = Self::attention(cx).await;
        let marked = attention.tabs();
        let environment = app.auth.host();
        let dashboard = Dashboard {
            title,
            home,
            administrator,
            me: &me,
            tabs: links,
            current,
            parent: parent
                .as_ref()
                .map(|(name, href)| (name.as_str(), href.as_str())),
            sign_out: leave,
            preferences: BrowserCookie::read_preferences(headers(cx)),
            preferences_action: prefer,
            here,
            health: Some(attention.health()),
            attention: &marked,
            environment,
            policies: app.policies.links(),
            search: Search {
                action: search,
                name: "q",
                placeholder: "Search by handle, name, email or ID",
                value: &searched,
            },
            reference: HttpTelemetry::trace_id(status),
            confirmation: admin.map(|admin| DashboardConfirmation {
                start,
                finish,
                left: admin.operator.confirmation_left().num_seconds(),
                form_time: FORM_TIME.num_seconds(),
            }),
        };
        let page = Child::new(page);
        let scripts = [script.as_str()];
        let html = view! { cx =>
            sourceorigin_ui::document(
                title: title.as_str(),
                stylesheet: stylesheet,
                scripts: &scripts,
                preferences: dashboard.preferences,
                admin: true,
                sourceorigin_ui::dashboard_frame(dashboard: &dashboard, (page))
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
    /// that an account which does not administer Origin Auth has no access, or why the
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
                let page = view! { cx => sourceorigin_ui::no_access(home: home.as_str()) };
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
            sourceorigin_ui::dashboard_failure(title: "That did not work", detail: Self::sentence(detail))
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
            sourceorigin_ui::dashboard_failure(
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
    let context = RequestContext::of(extensions(cx))?;
    match app.sign_in.finish(context, headers(cx), &code).await {
        Ok((return_to, cookie)) => {
            let mut response = see_other(return_to.as_str()).into_response(cx)?;
            cookie.set_on(&mut response)?;
            Ok(response)
        }
        Err(refused @ AdminError::InvalidHandoff) => {
            refused.log_refusal();
            let retry = href!(overview::overview).resolve(cx);
            let page = view! { cx =>
                sourceorigin_ui::dashboard_failure(
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

/// `POST /confirm/start`: starts the passkey ceremony the dashboard's script runs,
/// in its dialog, to confirm the dashboard on the page itself, for the auth
/// session it rests on. It answers as auth's own ceremonies do, in JSON.
#[route(POST "/confirm/start")]
async fn start_confirmation(cx: &Cx) -> Result<Response> {
    let admin = AdminApplication::admin(cx).await?;
    let app = AdminApplication::of(cx);
    let started = app
        .passkeys
        .start_proof(headers(cx), admin.user_id, admin.session_id)
        .await;
    Ok(AdminApplication::json(started))
}

/// `POST /confirm/finish`: verifies the passkey assertion the dashboard's script
/// posts, signed for the dashboard's origin in the ceremony
/// [`start_confirmation`] started, and confirms the dashboard's session with it.
/// The script then goes on to the change it was for.
#[route(POST "/confirm/finish")]
async fn finish_confirmation(cx: &Cx, Json(input): Json<AuthenticationFinish>) -> Result<Response> {
    let admin = AdminApplication::admin(cx).await?;
    let app = AdminApplication::of(cx);
    let context = RequestContext::of(extensions(cx))?;
    let confirmed = async {
        let proof = app
            .passkeys
            .verify_dashboard_proof(
                headers(cx),
                context,
                admin.user_id,
                admin.session_id,
                &input,
            )
            .await?;
        app.sign_in.confirm(headers(cx), &proof).await?;
        Ok(axum::response::IntoResponse::into_response(
            StatusCode::NO_CONTENT,
        ))
    };
    Ok(AdminApplication::json(confirmed.await))
}

/// `/sign-out`: ends the dashboard's session, by `POST`, then says so, by `GET`.
/// The administrator stays signed in to Origin Auth, which the page links to sign out
/// of.
#[route([GET, POST] "/sign-out")]
async fn sign_out(cx: &Cx) -> Result<Response> {
    let app = AdminApplication::of(cx);
    if method(cx) == Method::POST {
        let context = RequestContext::of(extensions(cx))?;
        let cookie = app.sign_in.sign_out(context, headers(cx)).await?;
        let mut response = see_other(href!(sign_out).resolve(cx)).into_response(cx)?;
        cookie.set_on(&mut response)?;
        return Ok(response);
    }
    let (again, auth_sign_out) = (
        &href!(overview::overview).resolve(cx),
        &app.auth.join(routes::page::LOGOUT),
    );
    let page = view! { cx =>
        sourceorigin_ui::dashboard_signed_out(sign_in: again, auth_sign_out: auth_sign_out)
    };
    AdminApplication::render(cx, StatusCode::OK, "Signed out", page).await
}
