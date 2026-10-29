//! Account search and one account's page.

use super::{EventRow, account_status, event_rows, heading, moment, refused_action};
use piquel_common::{
    AccountStatus, AuthenticationMethod,
    admin::{Session, User, UserDetail},
};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// An account found by a search, and the link to its page.
#[derive(Clone, Debug)]
pub struct UserRow<'a> {
    /// The account.
    pub user: &'a User,
    /// Its page.
    pub href: String,
}

/// One of an account's sessions, and the link ending it, unless the account is
/// out of the dashboard's reach.
#[derive(Clone, Debug)]
pub struct SessionRow<'a> {
    /// The session.
    pub session: &'a Session,
    /// The page ending it.
    pub revoke: Option<String>,
}

/// The account search: its form, posting `q` back to `action` by `GET`, the
/// accounts it found, and the `next` page's link, if there is one.
#[component]
pub async fn user_search<'a>(
    action: &'a str,
    q: &'a str,
    rows: &'a [UserRow<'a>],
    #[into]
    #[default]
    next: Option<String>,
) -> Result<impl View> {
    Ok(view! {
        heading(title: "Users")
        <form method="get" action=(action) class="row search" role="search">
            <input
                name="q"
                value=(q)
                placeholder="Username, display name, email or account ID"
                aria-label="Search accounts"
            >
            <button>"Search"</button>
        </form>
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No account matches."</p>
            } else {
                <table>
                    <thead>
                        <tr><th>"Username"</th><th>"Name"</th><th>"Status"</th><th>"Created"</th></tr>
                    </thead>
                    <tbody>
                        for row in rows {
                            <tr>
                                <td><a href=(row.href.as_str())>(row.user.handle.as_str())</a></td>
                                <td>(row.user.display_name.as_str())</td>
                                <td>account_status(status: row.user.status)</td>
                                <td>moment(at: row.user.created_at)</td>
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

/// The pages changing an account, which the dashboard has only for an account
/// that does not administer Piquel.
#[derive(Clone, Copy, Debug)]
pub struct AccountPages<'a> {
    /// Disabling or enabling it, by its status.
    pub status: &'a str,
    /// Ending every session.
    pub revoke_sessions: &'a str,
    /// Starting a recovery.
    pub recover: &'a str,
    /// Undoing its recovery.
    pub undo_recovery: &'a str,
    /// Its passkeys and social sign-in.
    pub sign_in: &'a str,
    /// Its email addresses.
    pub emails: &'a str,
    /// The apps that keep access to it.
    pub apps: &'a str,
    /// Giving it a new handle.
    pub handle: &'a str,
}

/// One account's page: `detail`, with the `pages` changing it, or why there are
/// none, its `sessions`, and its `recent` events, linking `all_events`.
#[component]
pub async fn user_page<'a>(
    detail: &'a UserDetail,
    pages: Result<AccountPages<'a>, &'a str>,
    sessions: &'a [SessionRow<'a>],
    recent: &'a [EventRow<'a>],
    all_events: &'a str,
) -> Result<impl View> {
    let user = &detail.user;
    Ok(view! {
        <div class="row between">
            heading(title: user.display_name.as_str(), lead: format!("@{}", user.handle))
            <div class="row">
                account_status(status: user.status)
                if detail.administrator {
                    <span class="badge">"Administrator"</span>
                }
            </div>
        </div>
        <section class="card">
            <dl class="facts">
                <dt>"Account ID"</dt><dd><code>(user.id.to_string())</code></dd>
                <dt>"Created"</dt><dd>moment(at: user.created_at)</dd>
            </dl>
            account_actions(user: user, pages: pages)
        </section>
        credentials(detail: detail)
        <section class="card">
            <div class="row between">
                <h2>"Sessions"</h2>
                if !sessions.is_empty() {
                    match pages {
                        Ok(pages) => {
                            <a class="button danger small" href=(pages.revoke_sessions)>"Revoke all"</a>
                        },
                        Err(reason) => {
                            refused_action(label: "Revoke all", reason: reason)
                        },
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
                        for row in sessions {
                            <tr>
                                <td>moment(at: row.session.authenticated_at)</td>
                                <td>(row.methods())</td>
                                <td>moment(at: row.session.last_seen_at)</td>
                                <td>moment(at: row.session.expires_at)</td>
                                <td>
                                    if let Some(revoke) = &row.revoke {
                                        <a href=(revoke.as_str())>"Revoke"</a>
                                    }
                                </td>
                            </tr>
                        }
                    </tbody>
                </table>
            }
        </section>
        <section class="card">
            <h2>"Consents"</h2>
            if detail.consents.is_empty() {
                <p class="empty">"No remembered consent."</p>
            } else {
                <ul class="list">
                    for consent in &detail.consents {
                        <li class="row between">
                            <span>(consent.client_id.as_str())</span>
                            <small>(consent.scopes.join(" "))</small>
                        </li>
                    }
                </ul>
            }
        </section>
        <section class="card">
            <div class="row between">
                <h2>"Recent events"</h2>
                <a href=(all_events)>"All events"</a>
            </div>
            event_rows(rows: recent)
        </section>
    })
}

/// What may be done to `user`, by its `pages`, or why nothing may.
#[component]
async fn account_actions<'a>(
    user: &'a User,
    pages: Result<AccountPages<'a>, &'a str>,
) -> Result<impl View> {
    Ok(view! {
        <div class="row actions">
            match pages {
                Ok(pages) => {
                    if user.status == AccountStatus::Active {
                        <a class="button danger" href=(pages.status)>"Disable"</a>
                    } else {
                        <a class="button secondary" href=(pages.status)>"Enable"</a>
                    }
                    <a class="button secondary" href=(pages.recover)>"Recover"</a>
                    <a class="button secondary" href=(pages.undo_recovery)>"Undo recovery"</a>
                    <a class="button secondary" href=(pages.sign_in)>"Sign-in methods"</a>
                    <a class="button secondary" href=(pages.emails)>"Email addresses"</a>
                    <a class="button secondary" href=(pages.apps)>"Connected apps"</a>
                    <a class="button secondary" href=(pages.handle)>"Rename handle"</a>
                },
                Err(reason) => {
                    refused_action(label: "Change", reason: reason)
                },
            }
        </div>
    })
}

/// An account's emails, passkeys and linked identities. Passkeys show by ID and
/// when each was added, never by name: a recovery's passkey was named by whoever
/// used its link.
#[component]
async fn credentials<'a>(detail: &'a UserDetail) -> Result<impl View> {
    Ok(view! {
        <section class="card">
            <h2>"Emails"</h2>
            if detail.emails.is_empty() {
                <p class="empty">"No email address."</p>
            } else {
                <ul class="list">
                    for email in &detail.emails {
                        <li class="row between">
                            <span>(email.address.as_str())</span>
                            <span class="row">
                                if email.primary { <span class="badge">"Primary"</span> }
                                match email.verified_at {
                                    Some(at) => <small>"Verified " moment(at: at)</small>,
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
            if detail.passkeys.is_empty() {
                <p class="empty">"No passkey."</p>
            } else {
                <ul class="list">
                    for passkey in &detail.passkeys {
                        <li class="row between">
                            <code>(passkey.id.to_string())</code>
                            <small>"Added " moment(at: passkey.created_at)</small>
                        </li>
                    }
                </ul>
            }
            <h2>"Linked identities"</h2>
            if detail.identities.is_empty() {
                <p class="empty">"No linked identity."</p>
            } else {
                <ul class="list">
                    for identity in &detail.identities {
                        <li class="row between">
                            <span>(identity.provider.to_string())</span>
                            <small>(identity.linked_email.clone().unwrap_or_default())</small>
                        </li>
                    }
                </ul>
            }
        </section>
    })
}

impl SessionRow<'_> {
    /// How the session signed in, in words.
    fn methods(&self) -> String {
        self.session
            .methods
            .iter()
            .map(|method| match method {
                AuthenticationMethod::Passkey => "passkey",
                AuthenticationMethod::Federation => "social",
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}
