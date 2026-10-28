//! Account search and one account's page.

use super::{EventRow, account_status, event_rows, heading, moment, refused_action};
use piquel_admin_api::{Session, User, UserDetail};
use piquel_common::{AccountStatus, AuthenticationMethod};
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
                                <td><a href=(row.href.as_str())>(row.user.username.as_str())</a></td>
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

/// One account's page: `detail`, with the page changing its status, or why it
/// cannot, its `sessions`, ending them all at `revoke_sessions`, or why not, and
/// its `recent` events, linking `all_events`.
#[component]
pub async fn user_page<'a>(
    detail: &'a UserDetail,
    status: Result<&'a str, &'a str>,
    sessions: &'a [SessionRow<'a>],
    revoke_sessions: Result<&'a str, &'a str>,
    recent: &'a [EventRow<'a>],
    all_events: &'a str,
) -> Result<impl View> {
    let user = &detail.user;
    Ok(view! {
        <div class="row between">
            heading(title: user.display_name.as_str(), lead: format!("@{}", user.username))
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
            <div class="row actions">
                match status {
                    Err(reason) => {
                        refused_action(
                            label: if user.status == AccountStatus::Active { "Disable" } else { "Enable" },
                            reason: reason,
                        )
                    },
                    Ok(href) if user.status == AccountStatus::Active => {
                        <a class="button danger" href=(href)>"Disable"</a>
                    },
                    Ok(href) => {
                        <a class="button secondary" href=(href)>"Enable"</a>
                    },
                }
            </div>
        </section>
        credentials(detail: detail)
        <section class="card">
            <div class="row between">
                <h2>"Sessions"</h2>
                if !sessions.is_empty() {
                    match revoke_sessions {
                        Ok(href) => {
                            <a class="button danger small" href=(href)>"Revoke all"</a>
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
