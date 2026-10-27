//! Account search, one account's page, and the changes made to an account.

use super::{AdminApplication as App, lists};
use crate::Reason;
use piquel_admin_api::{DisableUser, EventSearch, UserSearch};
use piquel_common::{AccountStatus, SessionId, UserId};
use piquel_ui::{Query, SessionRow, UserRow};
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{
        StatusCode, content::Form, href, path_param, query_params, response::Response, route,
    },
    view::view,
};

path_param!(pub account: UserId, error = not_found);
path_param!(pub session: SessionId, error = not_found);

/// Why the dashboard changes no administrator's account.
const ADMINISTRATOR_TARGET: &str =
    "Administrator accounts can only be changed after revoking their rights.";
/// How many of an account's events its page shows.
const RECENT_EVENTS: usize = 10;

/// The query of [`search`].
#[query_params(error = bad_request)]
struct SearchQuery {
    /// What to search for.
    q: Option<String>,
    /// Where the page starts.
    cursor: Option<UserId>,
}

/// `/users`: searches accounts by username, display name, email or ID.
#[route(GET "/users")]
pub(super) async fn search(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let query = query_params::<SearchQuery>(cx)?;
    let q = query.q.clone().unwrap_or_default();
    let found = App::of(cx)
        .service
        .search_users(&admin.operator, &q, query.cursor)
        .await?;
    let action = href!(search).resolve(cx);
    let rows: Vec<_> = found
        .users
        .iter()
        .map(|user| UserRow {
            user,
            href: App::account(cx, user.id),
        })
        .collect();
    let next = match found.next {
        Some(cursor) => Some(
            UserSearch {
                q: q.clone(),
                cursor: Some(cursor),
            }
            .on(&action)?,
        ),
        None => None,
    };
    let (action, q, rows) = (&action, &q, &rows);
    let page = view! { cx =>
        piquel_ui::user_search(action: action.as_str(), q: q.as_str(), rows: rows, next: next)
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/users/{account}`: everything about one account, and the changes the
/// dashboard may make to it.
#[route(GET "/users/{account}")]
pub(super) async fn detail(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let service = &App::of(cx).service;
    let id = *path_param::<Account>(cx)?;
    let detail = service.view_user(&admin.operator, id).await?;
    let filter = EventSearch {
        user: Some(id),
        ..EventSearch::default()
    };
    let mut recent = service.events(&admin.operator, filter.clone()).await?;
    recent.events.truncate(RECENT_EVENTS);
    let changeable = !detail.administrator;
    let status_link = match detail.user.status {
        AccountStatus::Active => href!(disable, Account(id)).resolve(cx),
        AccountStatus::Disabled | AccountStatus::Deleting => href!(enable, Account(id)).resolve(cx),
    };
    let revoke_all = href!(revoke_sessions, Account(id)).resolve(cx);
    let sessions: Vec<_> = detail
        .sessions
        .iter()
        .map(|session| SessionRow {
            session,
            revoke: changeable
                .then(|| href!(revoke_session, Account(id), Session(session.id)).resolve(cx)),
        })
        .collect();
    let events = App::event_rows(cx, &recent.events);
    let all_events = filter.on(&href!(lists::events).resolve(cx))?;
    let (status, revoke_all) = if changeable {
        (Ok(status_link.as_str()), Ok(revoke_all.as_str()))
    } else {
        (Err(ADMINISTRATOR_TARGET), Err(ADMINISTRATOR_TARGET))
    };
    // The page names only references: a view moves what it names.
    let (detail, sessions, events, all_events) = (&detail, &sessions, &events, &all_events);
    let page = view! { cx =>
        piquel_ui::user_page(
            detail: detail,
            status: status,
            sessions: sessions,
            revoke_sessions: revoke_all,
            recent: events,
            all_events: all_events.as_str(),
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/users/{account}/disable`: disables the account with a reason, ending its
/// sessions.
#[route([GET, POST] "/users/{account}/disable")]
pub(super) async fn disable(cx: &Cx, form: Option<Form<DisableUser>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Account>(cx)?;
    let back = App::account(cx, id);
    // Kept to fill in again after a refusal, never from a link's query string.
    let reason = form.as_ref().map(|Form(input)| input.reason.clone());
    let refusal = App::submit(cx, form, back.clone(), |input: DisableUser| async move {
        service
            .disable_user(&admin.operator, id, Reason::parse(input.reason)?)
            .await
    })
    .await?;
    let reason = refusal.as_ref().and(reason);
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Disable this account",
            description: "The account can no longer sign in, and every session and refresh grant ends now.",
            button: "Disable",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            danger: true,
            <label>
                "Reason"
                <input name="reason" required="" maxlength="500" value=(reason)>
            </label>
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/users/{account}/enable`: reactivates a disabled account.
#[route([GET, POST] "/users/{account}/enable")]
pub(super) async fn enable(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Account>(cx)?;
    let back = App::account(cx, id);
    let refusal = App::submit(cx, form, back.clone(), |_| {
        service.enable_user(&admin.operator, id)
    })
    .await?;
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Enable this account",
            description: "The account can sign in again with its passkeys.",
            button: "Enable",
            back: back.as_str(),
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/users/{account}/sessions/revoke`: ends every session of the account.
#[route([GET, POST] "/users/{account}/sessions/revoke")]
pub(super) async fn revoke_sessions(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Account>(cx)?;
    let back = App::account(cx, id);
    let refusal = App::submit(cx, form, back.clone(), |_| {
        service.revoke_user_sessions(&admin.operator, id)
    })
    .await?;
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Revoke every session",
            description: "Every browser signed in to this account is signed out, and its applications lose their refresh grants.",
            button: "Revoke all",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            danger: true,
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/users/{account}/sessions/{session}/revoke`: ends one session.
#[route([GET, POST] "/users/{account}/sessions/{session}/revoke")]
pub(super) async fn revoke_session(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Account>(cx)?;
    let session = *path_param::<Session>(cx)?;
    let back = App::account(cx, id);
    let refusal = App::submit(cx, form, back.clone(), |_| {
        service.revoke_session(&admin.operator, session)
    })
    .await?;
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Revoke this session",
            description: "The browser is signed out, and applications signed in through it lose their refresh grants.",
            button: "Revoke",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            danger: true,
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

impl App {
    /// The page of the account `id`.
    pub(super) fn account(cx: &Cx, id: UserId) -> String {
        href!(detail, Account(id)).resolve(cx)
    }
}
