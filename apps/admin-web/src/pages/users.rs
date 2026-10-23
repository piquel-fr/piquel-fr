use super::{change_form, events::event_rows, heading, refused_action, time};
use crate::admin::Admin;
use piquel_admin_api::{DisableUser, Email, EventSearch, Identity, Passkey, UserSearch};
use piquel_common::{AccountStatus, AuthenticationMethod, SessionId, UserId};
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{content::Form, href, page, path_param, query_params},
    view::{View, class, component, view},
};

path_param!(pub account: UserId, error = not_found);
path_param!(pub session: SessionId, error = not_found);

/// Why the API changes no administrator's account.
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
#[page("/users")]
pub async fn search(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    let query = query_params::<SearchQuery>(cx)?;
    let search = UserSearch {
        q: query.q.clone().unwrap_or_default(),
        cursor: query.cursor,
    };
    let page = admin
        .read(|api, token| api.search_users(token, &search))
        .await?;
    let next = page.next.map(|cursor| {
        href!(search).query(UserSearch {
            q: search.q.clone(),
            cursor: Some(cursor),
        })
    });
    Ok(view! {
        heading(title: "Users")
        <form method="get" class="row search" role="search">
            <input
                name="q"
                value=(search.q.clone())
                placeholder="Username, display name, email or account ID"
                aria-label="Search accounts"
            >
            <button>"Search"</button>
        </form>
        <section class="card">
            if page.users.is_empty() {
                <p class="empty">"No account matches."</p>
            } else {
                <table>
                    <thead>
                        <tr><th>"Username"</th><th>"Name"</th><th>"Status"</th><th>"Created"</th></tr>
                    </thead>
                    <tbody>
                        for user in page.users {
                            <tr>
                                <td><a href=(href!(detail, Account(user.id)))>(user.username)</a></td>
                                <td>(user.display_name)</td>
                                <td>account_status(status: user.status)</td>
                                <td>time(at: user.created_at)</td>
                            </tr>
                        }
                    </tbody>
                </table>
            }
        </section>
        if let Some(next) = next {
            <a class="button secondary" href=(next)>"Next page"</a>
        }
    })
}

/// `/users/{account}`: everything about one account, and the changes the API
/// allows to it.
#[page("/users/{account}")]
pub async fn detail(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    let id = *path_param::<Account>(cx)?;
    let detail = admin.read(|api, token| api.user(token, id)).await?;
    let events = EventSearch {
        user: Some(id),
        ..EventSearch::default()
    };
    let mut recent = admin.read(|api, token| api.events(token, &events)).await?;
    recent.events.truncate(RECENT_EVENTS);
    let user = detail.user;
    let changeable = !detail.administrator;
    Ok(view! {
        <div class="row between">
            heading(title: &user.display_name, lead: Some(format!("@{}", user.username)))
            <div class="row">
                account_status(status: user.status)
                if detail.administrator {
                    <span class="badge">"Administrator"</span>
                }
            </div>
        </div>
        <section class="card">
            <dl class="facts">
                <dt>"Account ID"</dt><dd><code>(id.to_string())</code></dd>
                <dt>"Created"</dt><dd>time(at: user.created_at)</dd>
            </dl>
            <div class="row actions">
                if !changeable {
                    refused_action(label: "Disable", reason: ADMINISTRATOR_TARGET)
                } else if user.status == AccountStatus::Active {
                    <a class="button danger" href=(href!(disable, Account(id)))>"Disable"</a>
                    <a class="button danger" href=(href!(delete, Account(id)))>"Delete"</a>
                } else if user.status == AccountStatus::Disabled {
                    <a class="button secondary" href=(href!(enable, Account(id)))>"Enable"</a>
                } else {
                    <a class="button secondary" href=(href!(restore, Account(id)))>"Restore"</a>
                }
            </div>
        </section>
        credentials(emails: detail.emails, passkeys: detail.passkeys, identities: detail.identities)
        session_list(account: id, sessions: detail.sessions, changeable: changeable)
        <section class="card">
            <h2>"Consents"</h2>
            if detail.consents.is_empty() {
                <p class="empty">"No remembered consent."</p>
            } else {
                <ul class="list">
                    for consent in detail.consents {
                        <li class="row between">
                            <span>(consent.client_id)</span>
                            <small>(consent.scopes.join(" "))</small>
                        </li>
                    }
                </ul>
            }
        </section>
        <section class="card">
            <div class="row between">
                <h2>"Recent events"</h2>
                <a href=(href!(super::events::list).query(events))>"All events"</a>
            </div>
            event_rows(events: recent.events)
        </section>
    })
}

/// An account's emails, passkeys and linked identities.
#[component]
async fn credentials(
    emails: Vec<Email>,
    passkeys: Vec<Passkey>,
    identities: Vec<Identity>,
) -> Result<impl View> {
    Ok(view! {
        <section class="card">
            <h2>"Emails"</h2>
            if emails.is_empty() {
                <p class="empty">"No email address."</p>
            } else {
                <ul class="list">
                    for email in emails {
                        <li class="row between">
                            <span>(email.address)</span>
                            <span class="row">
                                if email.primary { <span class="badge">"Primary"</span> }
                                match email.verified_at {
                                    Some(at) => <small>"Verified " time(at: at)</small>,
                                    None => <small>"Unverified"</small>,
                                }
                            </span>
                        </li>
                    }
                </ul>
            }
        </section>
        <section class="card">
            <h2>"Passkeys"</h2>
            if passkeys.is_empty() {
                <p class="empty">"No passkey."</p>
            } else {
                <ul class="list">
                    for passkey in passkeys {
                        <li>(passkey.friendly_name)</li>
                    }
                </ul>
            }
            <h2>"Linked identities"</h2>
            if identities.is_empty() {
                <p class="empty">"No linked identity."</p>
            } else {
                <ul class="list">
                    for identity in identities {
                        <li class="row between">
                            <span>(identity.provider.to_string())</span>
                            <small>(identity.linked_email.unwrap_or_default())</small>
                        </li>
                    }
                </ul>
            }
        </section>
    })
}

/// An account's active sessions, each revocable unless the account is an
/// administrator's.
#[component]
async fn session_list(
    account: UserId,
    sessions: Vec<piquel_admin_api::Session>,
    changeable: bool,
) -> Result<impl View> {
    Ok(view! {
        <section class="card">
            <div class="row between">
                <h2>"Sessions"</h2>
                if !sessions.is_empty() {
                    if changeable {
                        <a class="button danger small" href=(href!(revoke_sessions, Account(account)))>"Revoke all"</a>
                    } else {
                        refused_action(label: "Revoke all", reason: ADMINISTRATOR_TARGET)
                    }
                }
            </div>
            if sessions.is_empty() {
                <p class="empty">"No active session."</p>
            } else {
                <table>
                    <thead>
                        <tr><th>"Signed in"</th><th>"Methods"</th><th>"Last seen"</th><th>"Expires"</th><th></th></tr>
                    </thead>
                    <tbody>
                        for session in sessions {
                            <tr>
                                <td>time(at: session.authenticated_at)</td>
                                <td>
                                    (session.methods.iter().map(|method| match method {
                                        AuthenticationMethod::Passkey => "passkey",
                                        AuthenticationMethod::Federation => "social",
                                    }).collect::<Vec<_>>().join(", "))
                                </td>
                                <td>time(at: session.last_seen_at)</td>
                                <td>time(at: session.expires_at)</td>
                                <td>
                                    if changeable {
                                        <a href=(href!(revoke_session, Account(account), Session(session.id)))>"Revoke"</a>
                                    }
                                </td>
                            </tr>
                        }
                    </tbody>
                </table>
            }
        </section>
    })
}

/// An account's status.
#[component]
async fn account_status(status: AccountStatus) -> Result<impl View> {
    Ok(view! {
        <span class=(class!("badge", "disabled" if status != AccountStatus::Active))>
            (status.to_string())
        </span>
    })
}

/// `/users/{account}/disable`: disables the account with a reason, ending its sessions.
#[page([GET, POST] "/users/{account}/disable")]
pub async fn disable(cx: &Cx, form: Option<Form<DisableUser>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<Account>(cx)?;
    let back = href!(detail, Account(id)).resolve(cx);
    // Kept to fill in again after a refusal, never from a link's query string.
    let reason = form.as_ref().map(|Form(input)| input.reason.clone());
    let refusal = admin
        .submit(
            cx,
            form,
            back.clone(),
            move |api, token, input| async move { api.disable_user(token, id, &input).await },
        )
        .await?;
    let reason = refusal.as_ref().and(reason);
    Ok(view! {
        change_form(
            title: "Disable this account",
            description: "The account can no longer sign in, and every session and refresh grant ends now.",
            button: "Disable",
            back: back,
            refusal: refusal,
            danger: true,
            <label>
                "Reason"
                <input name="reason" required="" maxlength="500" value=(reason)>
            </label>
        )
    })
}

/// `/users/{account}/enable`: reactivates a disabled account.
#[page([GET, POST] "/users/{account}/enable")]
pub async fn enable(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<Account>(cx)?;
    let back = href!(detail, Account(id)).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| {
            api.enable_user(token, id)
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Enable this account",
            description: "The account can sign in again with its passkeys.",
            button: "Enable",
            back: back,
            refusal: refusal,
        )
    })
}

/// `/users/{account}/delete`: schedules the account's deletion.
#[page([GET, POST] "/users/{account}/delete")]
pub async fn delete(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<Account>(cx)?;
    let back = href!(detail, Account(id)).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| {
            api.schedule_deletion(token, id)
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Delete this account",
            description: "The account can no longer sign in, and every session and refresh grant ends now. It is deleted for good after 30 days, unless it is restored first.",
            button: "Delete",
            back: back,
            refusal: refusal,
            danger: true,
        )
    })
}

/// `/users/{account}/restore`: restores an account scheduled for deletion.
#[page([GET, POST] "/users/{account}/restore")]
pub async fn restore(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<Account>(cx)?;
    let back = href!(detail, Account(id)).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| {
            api.restore_user(token, id)
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Restore this account",
            description: "The account is no longer deleted, and can sign in again with its passkeys.",
            button: "Restore",
            back: back,
            refusal: refusal,
        )
    })
}

/// `/users/{account}/sessions/revoke`: ends every session of the account.
#[page([GET, POST] "/users/{account}/sessions/revoke")]
pub async fn revoke_sessions(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<Account>(cx)?;
    let back = href!(detail, Account(id)).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| {
            api.revoke_user_sessions(token, id)
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Revoke every session",
            description: "Every browser signed in to this account is signed out, and its applications lose their refresh grants.",
            button: "Revoke all",
            back: back,
            refusal: refusal,
            danger: true,
        )
    })
}

/// `/users/{account}/sessions/{session}/revoke`: ends one session.
#[page([GET, POST] "/users/{account}/sessions/{session}/revoke")]
pub async fn revoke_session(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<Account>(cx)?;
    let session = *path_param::<Session>(cx)?;
    let back = href!(detail, Account(id)).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| {
            api.revoke_session(token, session)
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Revoke this session",
            description: "The browser is signed out, and applications signed in through it lose their refresh grants.",
            button: "Revoke",
            back: back,
            refusal: refusal,
            danger: true,
        )
    })
}
