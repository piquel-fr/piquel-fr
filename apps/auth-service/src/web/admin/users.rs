//! Account search, one account's page, and the changes made to an account.

use super::{AdminApplication as App, invitations, lists, settings};
use crate::Reason;
use piquel_common::{
    AccountStatus, SessionId, UserId,
    admin::{DisableUser, EventSearch, UserSearch},
};
use piquel_repository::{RecentRecovery, RecoveryState};
use piquel_ui::{
    AccountPages, Action, Change, Pager, Query, RecoveryKey, RecoveryRow, RecoveryStanding,
    SessionRow, UserRow,
};
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
    /// The page wanted, counting from 1.
    page: Option<u32>,
}

/// `/users`: searches accounts by handle, display name, email or ID.
#[route(GET "/users")]
pub(super) async fn search(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let query = query_params::<SearchQuery>(cx)?;
    let q = query.q.clone().unwrap_or_default();
    let found = app
        .service
        .search_users(&admin.operator, &q, query.page)
        .await?;
    let administrators: Vec<_> = app
        .service
        .list_administrators(&admin.operator)
        .await?
        .into_iter()
        .map(|administrator| administrator.user_id)
        .collect();
    let action = href!(search).resolve(cx);
    let rows: Vec<_> = found
        .users
        .iter()
        .map(|user| UserRow {
            user,
            administrator: administrators.contains(&user.id),
            href: App::account(cx, user.id),
        })
        .collect();
    let pager = Pager::of(found.paging, |page| {
        UserSearch {
            q: q.clone(),
            page: Some(page),
        }
        .on(&action)
    })?;
    let invite = app
        .invitations
        .then(|| href!(invitations::create).resolve(cx));
    let (q, rows, pager, invite) = (&q, &rows, &pager, invite.as_deref());
    let page = view! { cx =>
        piquel_ui::user_search(q: q.as_str(), rows: rows, pages: pager, invite: invite)
    };
    App::render(cx, StatusCode::OK, "Users", page).await
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
    // A confirmed dashboard shows each change's form on the page itself; one that
    // is not links the change's page, which confirms first.
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let action = |href: String| Action { href, inline };
    let links = [
        href!(recover, Account(id)).resolve(cx),
        href!(undo_recovery, Account(id)).resolve(cx),
        href!(settings::sign_in, Account(id)).resolve(cx),
        href!(settings::emails, Account(id)).resolve(cx),
        href!(settings::apps, Account(id)).resolve(cx),
        href!(settings::history, Account(id)).resolve(cx),
        href!(settings::handle, Account(id)).resolve(cx),
    ];
    let [
        recovering,
        undoing,
        signing_in,
        addresses,
        connected,
        happened,
        renaming,
    ] = links.each_ref().map(String::as_str);
    let status = action(match detail.user.status {
        AccountStatus::Active => href!(disable, Account(id)).resolve(cx),
        AccountStatus::Disabled => href!(enable, Account(id)).resolve(cx),
        AccountStatus::Deleting => href!(restore, Account(id)).resolve(cx),
    });
    let deleting = action(href!(delete, Account(id)).resolve(cx));
    let revoking = action(href!(revoke_sessions, Account(id)).resolve(cx));
    let pages = if changeable {
        Ok(AccountPages {
            status: &status,
            delete: &deleting,
            revoke_sessions: &revoking,
            recover: recovering,
            undo_recovery: undoing,
            sign_in: signing_in,
            emails: addresses,
            apps: connected,
            history: happened,
            handle: renaming,
        })
    } else {
        Err(ADMINISTRATOR_TARGET)
    };
    let sessions: Vec<_> = detail
        .sessions
        .iter()
        .map(|session| SessionRow {
            session,
            revoke: changeable.then(|| {
                action(href!(revoke_session, Account(id), Session(session.id)).resolve(cx))
            }),
        })
        .collect();
    let events = App::event_rows(cx, &recent.events);
    let all_events = filter.on(&href!(lists::events).resolve(cx))?;
    // The page names only references: a view moves what it names.
    let (detail, sessions, events, all_events) = (&detail, &sessions, &events, &all_events);
    let page = view! { cx =>
        piquel_ui::user_page(
            detail: detail,
            pages: pages,
            sessions: sessions,
            recent: events,
            all_events: all_events.as_str(),
        )
    };
    // The dashboard's largest page: its future is boxed, off the handler's stack.
    Box::pin(App::render(
        cx,
        StatusCode::OK,
        detail.user.display_name.as_str(),
        page,
    ))
    .await
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
    let refusal = App::submit(cx, form, back.clone(), |input: DisableUser| async move {
        service
            .disable_user(&admin.operator, id, Reason::parse(input.reason)?)
            .await
    })
    .await?;
    let reason = refusal.as_ref().map(|refused| refused.form.reason.as_str());
    let refusal = refusal.as_deref();
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::Disable,
            back: back.as_str(),
            refusal: refusal,
            reason: reason,
        )
    };
    App::render(cx, StatusCode::OK, "Disable", page).await
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
            change: Change::Enable,
            back: back.as_str(),
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, "Enable", page).await
}

/// `/users/{account}/delete`: schedules the active account's deletion, with a
/// reason the owner sees. Purging it at once is left to the terminal: it cannot
/// be undone.
#[route([GET, POST] "/users/{account}/delete")]
pub(super) async fn delete(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Account>(cx)?;
    let back = App::account(cx, id);
    let refusal = App::submit(cx, form, back.clone(), |input: ReasonForm| async move {
        service
            .schedule_deletion(&admin.operator, id, Reason::parse(input.reason)?)
            .await
    })
    .await?;
    let reason = refusal.as_ref().map(|refused| refused.form.reason.as_str());
    let refusal = refusal.as_deref();
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::Delete,
            back: back.as_str(),
            refusal: refusal,
            reason: reason,
        )
    };
    App::render(cx, StatusCode::OK, "Delete", page).await
}

/// `/users/{account}/restore`: restores an account scheduled for deletion, with a
/// reason the owner sees.
#[route([GET, POST] "/users/{account}/restore")]
pub(super) async fn restore(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Account>(cx)?;
    let back = App::account(cx, id);
    let refusal = App::submit(cx, form, back.clone(), |input: ReasonForm| async move {
        service
            .restore_user(&admin.operator, id, Reason::parse(input.reason)?)
            .await
    })
    .await?;
    let reason = refusal.as_ref().map(|refused| refused.form.reason.as_str());
    let refusal = refusal.as_deref();
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::Restore,
            back: back.as_str(),
            refusal: refusal,
            reason: reason,
        )
    };
    App::render(cx, StatusCode::OK, "Restore", page).await
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
            change: Change::RevokeSessions,
            back: back.as_str(),
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, "Revoke sessions", page).await
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
            change: Change::RevokeSession,
            back: back.as_str(),
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, "Revoke a session", page).await
}

/// The form of a change whose reason the owner sees in their history: starting
/// or undoing a recovery, scheduling a deletion or restoring the account.
#[derive(Clone, serde::Deserialize)]
pub(super) struct ReasonForm {
    /// Why, recorded with the change and shown to the owner in their history.
    reason: String,
}

/// `/users/{account}/recover`: the account's recent recoveries, then starts one,
/// whose link only its primary verified address is mailed, and goes on to the
/// account's page. An account that was in someone else's hands needs `user
/// recover --revoke`, at the terminal, and so does every account while email is
/// disabled.
#[route([GET, POST] "/users/{account}/recover")]
pub(super) async fn recover(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let app = App::of(cx);
    let id = *path_param::<Account>(cx)?;
    let back = App::account(cx, id);
    let refusal = App::submit(cx, form, back.clone(), |input: ReasonForm| async move {
        let reason = Reason::parse(input.reason)?;
        app.service
            .recover_account(&admin.operator, id, reason, &app.links, None)
            .await
            .map(drop)
    })
    .await?;
    let recent = app.service.recent_recoveries(&admin.operator, id).await?;
    let reason = refusal.as_ref().map(|refused| refused.form.reason.as_str());
    let refusal = refusal.as_deref();
    let rows = &App::recovery_rows(&recent);
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::Recover,
            back: back.as_str(),
            refusal: refusal,
            reason: reason,
            piquel_ui::recovery_list(rows: rows)
        )
    };
    App::render(cx, StatusCode::OK, "Recover", page).await
}

/// `/users/{account}/undo-recovery`: the account's recent recoveries, then undoes
/// the one that can still be undone, for an owner support has confirmed, and goes
/// on to the account's page: in probation, it removes its passkey, withdraws
/// every consent and ends every session; its link unused, it cancels the link.
#[route([GET, POST] "/users/{account}/undo-recovery")]
pub(super) async fn undo_recovery(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let app = App::of(cx);
    let id = *path_param::<Account>(cx)?;
    let back = App::account(cx, id);
    let refusal = App::submit(cx, form, back.clone(), |input: ReasonForm| async move {
        let reason = Reason::parse(input.reason)?;
        app.service.undo_recovery(&admin.operator, id, reason).await
    })
    .await?;
    let recent = app.service.recent_recoveries(&admin.operator, id).await?;
    let reason = refusal.as_ref().map(|refused| refused.form.reason.as_str());
    let refusal = refusal.as_deref();
    let rows = &App::recovery_rows(&recent);
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::UndoRecovery,
            back: back.as_str(),
            refusal: refusal,
            reason: reason,
            piquel_ui::recovery_list(rows: rows)
        )
    };
    App::render(cx, StatusCode::OK, "Undo a recovery", page).await
}

impl App {
    /// `recent` recoveries as the recovery pages list them.
    fn recovery_rows(recent: &[RecentRecovery]) -> Vec<RecoveryRow> {
        recent
            .iter()
            .map(|recovery| RecoveryRow {
                started_at: recovery.started_at,
                standing: match recovery.state {
                    RecoveryState::Open => RecoveryStanding::Unused,
                    RecoveryState::Probation { settles_at } => {
                        RecoveryStanding::Probation { settles_at }
                    }
                    RecoveryState::Settled => RecoveryStanding::Settled,
                    RecoveryState::Ended => match (recovery.undone_at, recovery.cancelled_at) {
                        (Some(at), _) => RecoveryStanding::Undone(at),
                        (None, Some(at)) => RecoveryStanding::Cancelled(at),
                        (None, None) => RecoveryStanding::Expired,
                    },
                },
                passkey: recovery.passkey.as_ref().zip(recovery.completed_at).map(
                    |(passkey, enrolled_at)| RecoveryKey {
                        id: passkey.id,
                        enrolled_at,
                        active: passkey.active,
                    },
                ),
            })
            .collect()
    }

    /// The page of the account `id`.
    pub(super) fn account(cx: &Cx, id: UserId) -> String {
        href!(detail, Account(id)).resolve(cx)
    }
}
