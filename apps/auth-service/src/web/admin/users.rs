//! Account search, one account's page, and the changes made to an account.

use super::{AdminApplication as App, ReasonForm, Refused, invitations, lists, settings};
use crate::{AdminError, Letter, Reason, admin::SignedInAdmin, deliveries::EmailSender, routes};
use sourceorigin_common::{
    AccountStatus, PictureId, SessionId, UserId,
    admin::{EventSearch, MessageIntent, MessageUser, User, UserSearch},
};
use sourceorigin_repository::{RecentRecovery, RecoveryState};
use sourceorigin_ui::{
    AccountPages, Action, Change, Crumb, MessagePreview, Pager, Query, RecoveryKey, RecoveryRow,
    RecoveryStanding, SessionRow, Target, UserRow,
};
use topcoat::{
    Error, Result,
    context::Cx,
    router::{
        StatusCode, content::Form, error::see_other, href, path_param, query_params,
        response::Response, route,
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
    let rows = App::user_rows(cx, &found.users, &administrators);
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
        sourceorigin_ui::user_search(q: q.as_str(), rows: rows, pages: pager, invite: invite)
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
        href!(settings::profile, Account(id)).resolve(cx),
        href!(settings::emails, Account(id)).resolve(cx),
        href!(settings::apps, Account(id)).resolve(cx),
        href!(settings::history, Account(id)).resolve(cx),
        href!(settings::notifications, Account(id)).resolve(cx),
        href!(settings::handle, Account(id)).resolve(cx),
        href!(settings::display_name, Account(id)).resolve(cx),
        href!(message, Account(id)).resolve(cx),
    ];
    let [
        recovering,
        undoing,
        signing_in,
        picturing,
        addresses,
        connected,
        happened,
        told,
        renaming,
        naming,
        writing,
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
            profile: picturing,
            emails: addresses,
            apps: connected,
            history: happened,
            notifications: told,
            handle: renaming,
            display_name: naming,
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
    let picture = App::picture(cx, detail.user.picture);
    let (detail, sessions, events, all_events) = (&detail, &sessions, &events, &all_events);
    let page = view! { cx =>
        sourceorigin_ui::user_page(
            detail: detail,
            picture: picture.as_deref(),
            pages: pages,
            message: writing,
            sessions: sessions,
            recent: events,
            all_events: all_events.as_str(),
        )
    };
    // The dashboard's largest page: its future is boxed, off the handler's stack.
    Box::pin(App::render(
        cx,
        StatusCode::OK,
        Crumb::Name(detail.user.handle.as_str()),
        page,
    ))
    .await
}

/// `/users/{account}/disable`: disables the account, ending its sessions.
#[route([GET, POST] "/users/{account}/disable")]
pub(super) async fn disable(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    AccountChange::Disable.page(cx, form).await
}

/// `/users/{account}/enable`: reactivates a disabled account.
#[route([GET, POST] "/users/{account}/enable")]
pub(super) async fn enable(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    AccountChange::Enable.page(cx, form).await
}

/// `/users/{account}/delete`: schedules the active account's deletion. Purging
/// it at once is left to the terminal: it cannot be undone.
#[route([GET, POST] "/users/{account}/delete")]
pub(super) async fn delete(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    AccountChange::Delete.page(cx, form).await
}

/// `/users/{account}/restore`: restores an account scheduled for deletion.
#[route([GET, POST] "/users/{account}/restore")]
pub(super) async fn restore(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    AccountChange::Restore.page(cx, form).await
}

/// `/users/{account}/sessions/revoke`: ends every session of the account.
#[route([GET, POST] "/users/{account}/sessions/revoke")]
pub(super) async fn revoke_sessions(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    AccountChange::RevokeSessions.page(cx, form).await
}

/// `/users/{account}/sessions/{session}/revoke`: ends one session of the account;
/// another account's is not found.
#[route([GET, POST] "/users/{account}/sessions/{session}/revoke")]
pub(super) async fn revoke_session(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let session = *path_param::<Session>(cx)?;
    AccountChange::RevokeSession(session).page(cx, form).await
}

/// What a message's form asked for, once it was posted.
enum Composed {
    /// Its text again, to change it.
    Editing(MessageUser),
    /// Its email, as it will be sent.
    Previewing(MessageUser, Letter),
    /// Nothing more: it was sent.
    Sent,
}

/// `/users/{account}/message`: writes a message to the account, shows its email
/// as it will be sent, then sends it and goes on to the account's page. Writing
/// and previewing it need no confirmation, so a long text never outlasts one;
/// sending needs the dashboard's recent one, which its script asks for first.
/// Without the script, a confirmation that ran out goes through auth's handoff
/// page and back to an empty form. An administrator's account takes one too: a
/// message changes nothing about it.
#[route([GET, POST] "/users/{account}/message")]
pub(super) async fn message(cx: &Cx, form: Option<Form<MessageUser>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let id = *path_param::<Account>(cx)?;
    let account = app.service.view_user(&admin.operator, id).await?;
    let back = App::account(cx, id);
    let composed = App::change(cx, form, |input: MessageUser| async move {
        if input.intent == MessageIntent::Edit {
            return Ok(Composed::Editing(input));
        }
        let letter = Letter::try_from(&input)?;
        if input.intent == MessageIntent::Preview {
            return Ok(Composed::Previewing(input, letter));
        }
        app.service
            .message_user(&admin.operator, id, letter)
            .await?;
        Ok::<_, AdminError>(Composed::Sent)
    })
    .await?;
    let (typed, letter, refusal) = match composed {
        None => (MessageUser::default(), None, None),
        Some(Ok(Composed::Sent)) => return Err(see_other(back).into()),
        Some(Ok(Composed::Editing(typed))) => (typed, None, None),
        Some(Ok(Composed::Previewing(typed, letter))) => (typed, Some(letter), None),
        // A send refused shows its email again; a text refused, its form.
        Some(Err(Refused { message, form })) => {
            (form.clone(), Letter::try_from(&form).ok(), Some(message))
        }
    };
    let email = letter
        .map(|letter| EmailSender::preview(&letter, &app.auth))
        .transpose()
        .map_err(|error| Error::msg(format!("could not render a message: {error}")))?;
    let preview = email.as_deref().map(|email| MessagePreview {
        email,
        address: account
            .emails
            .iter()
            .find(|address| address.primary && address.verified_at.is_some())
            .map(|address| address.address.as_str()),
    });
    let (handle, typed) = (account.user.handle.as_str(), &typed);
    let target = App::target(cx).await;
    let page = view! { cx =>
        sourceorigin_ui::message_page(
            handle: handle,
            back: back.as_str(),
            form: typed,
            target: target,
            preview: preview,
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, "Send a message", page).await
}

/// `/users/{account}/recover`: the account's recent recoveries, then starts one,
/// whose link only its primary verified address is mailed, and goes on to the
/// account's page. An account that was in someone else's hands needs `user
/// recover --revoke`, at the terminal, and so does every account while email is
/// disabled.
#[route([GET, POST] "/users/{account}/recover")]
pub(super) async fn recover(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    AccountChange::Recover.page(cx, form).await
}

/// `/users/{account}/undo-recovery`: the account's recent recoveries, then undoes
/// the one that can still be undone, for an owner support has confirmed, and goes
/// on to the account's page: in probation, it removes its passkey, withdraws
/// every consent and ends every session; its link unused, it cancels the link.
#[route([GET, POST] "/users/{account}/undo-recovery")]
pub(super) async fn undo_recovery(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    AccountChange::UndoRecovery.page(cx, form).await
}

/// A change the dashboard makes to the account its path names, each on its own
/// page, for the reason the administrator gives.
#[derive(Clone, Copy)]
enum AccountChange {
    /// `user disable`.
    Disable,
    /// `user enable`.
    Enable,
    /// `user delete`, with a grace period.
    Delete,
    /// `user restore`.
    Restore,
    /// `session revoke-all`.
    RevokeSessions,
    /// `session revoke`, of this session.
    RevokeSession(SessionId),
    /// `user recover`, mailing the link.
    Recover,
    /// `user undo-recovery`.
    UndoRecovery,
}

impl AccountChange {
    /// What it does, in the dashboard's words, and its page's crumb.
    const fn change(self) -> (Change, &'static str) {
        match self {
            Self::Disable => (Change::Disable, "Disable"),
            Self::Enable => (Change::Enable, "Enable"),
            Self::Delete => (Change::Delete, "Delete"),
            Self::Restore => (Change::Restore, "Restore"),
            Self::RevokeSessions => (Change::RevokeSessions, "Revoke sessions"),
            Self::RevokeSession(_) => (Change::RevokeSession, "Revoke a session"),
            Self::Recover => (Change::Recover, "Recover"),
            Self::UndoRecovery => (Change::UndoRecovery, "Undo a recovery"),
        }
    }

    /// Makes it to the account `id`, as `admin`, for `reason`.
    async fn make(
        self,
        app: &App,
        admin: &SignedInAdmin,
        id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let (service, operator) = (&app.service, &admin.operator);
        match self {
            Self::Disable => service.disable_user(operator, id, reason).await,
            Self::Enable => service.enable_user(operator, id, reason).await,
            Self::Delete => service.schedule_deletion(operator, id, reason).await,
            Self::Restore => service.restore_user(operator, id, reason).await,
            Self::RevokeSessions => service.revoke_user_sessions(operator, id, reason).await,
            Self::RevokeSession(session) => {
                service.revoke_session(operator, id, session, reason).await
            }
            Self::Recover => service
                .recover_account(operator, id, reason, &app.links, None)
                .await
                .map(drop),
            Self::UndoRecovery => service.undo_recovery(operator, id, reason).await,
        }
    }

    /// Its page: a `GET` asks for the reason, and a `POST` makes it, then goes
    /// back to the account's page. It names the account the crumb names, or for
    /// one session, that session of it. A recovery's pages list the account's
    /// recent recoveries below the form.
    async fn page(self, cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
        let admin = App::admin(cx).await?;
        App::confirm(cx, admin)?;
        let app = App::of(cx);
        let id = *path_param::<Account>(cx)?;
        let back = App::account(cx, id);
        let refusal = App::submit_reason(cx, form, back.clone(), async |reason| {
            self.make(app, admin, id, reason).await
        })
        .await?;
        let recent = if matches!(self, Self::Recover | Self::UndoRecovery) {
            let recent = app.service.recent_recoveries(&admin.operator, id).await?;
            Some(App::recovery_rows(&recent))
        } else {
            None
        };
        let (change, crumb) = self.change();
        let reason = refusal.as_ref().map(Refused::reason);
        let refusal = refusal.as_deref();
        let account = App::target(cx).await;
        // One session is named as that session of the account the crumb names.
        let session = match self {
            Self::RevokeSession(session) => Some(session.to_string()),
            _ => None,
        };
        let named = session
            .as_ref()
            .zip(account.as_ref())
            .map(|(_, account)| format!("{}, session", account.name));
        let target = match &session {
            Some(session) => named.as_deref().map(|name| Target {
                name,
                id: Some(session),
            }),
            None => account,
        };
        let page = view! { cx =>
            sourceorigin_ui::dashboard_change(
                change: change,
                target: target,
                back: back.as_str(),
                refusal: refusal,
                reason: reason,
                if let Some(rows) = &recent {
                    sourceorigin_ui::recovery_list(rows: rows)
                }
            )
        };
        App::render(cx, StatusCode::OK, crumb, page).await
    }
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

    /// Where auth serves the picture `id`, if any: the dashboard serves none.
    pub(super) fn picture(cx: &Cx, id: Option<PictureId>) -> Option<String> {
        id.map(|id| routes::pictures::url(&Self::of(cx).auth, id))
    }

    /// `users` as a list shows them, those in `administrators` marked.
    pub(super) fn user_rows<'a>(
        cx: &Cx,
        users: &'a [User],
        administrators: &[UserId],
    ) -> Vec<UserRow<'a>> {
        users
            .iter()
            .map(|user| UserRow {
                user,
                administrator: administrators.contains(&user.id),
                href: Self::account(cx, user.id),
                picture: Self::picture(cx, user.picture),
            })
            .collect()
    }
}
