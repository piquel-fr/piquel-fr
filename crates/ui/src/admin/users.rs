//! Account search and one account's page.

use super::{
    Action, Change, EventRow, account_status, confirm, event_rows, moment, refused_action,
};
use crate::layout::{AvatarSize, Pager, Who, avatar, page_head, pager, private_address};
use piquel_common::{
    AccountStatus, AuthenticationMethod,
    admin::{Session, User, UserDetail},
};
use topcoat::{
    Result,
    context::Cx,
    view::{View, component, view},
};

/// An account found by a search, and the link to its page.
#[derive(Clone, Debug)]
pub struct UserRow<'a> {
    /// The account.
    pub user: &'a User,
    /// Whether it administers Piquel.
    pub administrator: bool,
    /// Its page.
    pub href: String,
    /// Where its profile picture is served, if it has one.
    pub picture: Option<String>,
}

impl UserRow<'_> {
    /// The account, as an avatar shows it.
    pub(crate) fn who(&self) -> Who<'_> {
        Who {
            user: None,
            name: &self.user.display_name,
            handle: self.user.handle.as_str(),
            picture: self.picture.as_deref(),
            administrator: self.administrator,
        }
    }
}

/// One of an account's sessions, and the change ending it, unless the account is
/// out of the dashboard's reach.
#[derive(Clone, Debug)]
pub struct SessionRow<'a> {
    /// The session.
    pub session: &'a Session,
    /// Ending it.
    pub revoke: Option<Action>,
}

/// The account search: the accounts `q` found, by handle, and the `pages`
/// through them. The top bar holds the search form; `invite` links the page
/// inviting someone, while signup needs invitations.
#[component]
pub async fn user_search<'a>(
    cx: &Cx,
    q: &'a str,
    rows: &'a [UserRow<'a>],
    pages: &'a Pager,
    #[into]
    #[default]
    invite: Option<&'a str>,
) -> Result<impl View> {
    let total = pages.paging.total;
    let plural = if total == 1 { "" } else { "s" };
    let lead = if q.is_empty() {
        format!("{total} account{plural}. Search by handle, name, email or ID in the bar above.")
    } else {
        format!("{total} account{plural} matching “{q}”.")
    };
    Ok(view! {
        page_head(
            title: "Users",
            lead: lead,
            actions: view! {
                if let Some(invite) = invite {
                    <a data-confirm-first="" class="button secondary" href=(invite)>"Invite someone"</a>
                }
            },
        )
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No account matches."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr><th>"handle"</th><th>"name"</th><th>"role"</th><th>"status"</th><th>"created"</th></tr>
                        </thead>
                        <tbody>
                            #[key(position)]
                            for (position, row) in rows.into_iter().enumerate() {
                                <tr>
                                    <td><a class="mono" href=(row.href.as_str())>(format!("@{}", row.user.handle))</a></td>
                                    <td>
                                        <span class="row nowrap">
                                            avatar(who: row.who(), size: AvatarSize::Small)
                                            (row.user.display_name.as_str())
                                        </span>
                                    </td>
                                    <td>
                                        if row.administrator {
                                            <span class="badge admin"><span class="dot"></span>"Admin"</span>
                                        } else {
                                            <span class="muted">"User"</span>
                                        }
                                    </td>
                                    <td>account_status(status: row.user.status)</td>
                                    <td>moment(at: row.user.created_at)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
        pager(pages: pages, what: "accounts")
    })
}

/// The changes to an account, which the dashboard has only for an account that
/// does not administer Piquel: the short ones confirm on the account's page, the
/// rest have pages of their own.
#[derive(Clone, Copy, Debug)]
pub struct AccountPages<'a> {
    /// Disabling, enabling or restoring it, by its status.
    pub status: &'a Action,
    /// Scheduling its deletion, while it is active.
    pub delete: &'a Action,
    /// Ending every session.
    pub revoke_sessions: &'a Action,
    /// Starting a recovery.
    pub recover: &'a str,
    /// Undoing its recovery.
    pub undo_recovery: &'a str,
    /// Its passkeys and social sign-in.
    pub sign_in: &'a str,
    /// Its profile picture.
    pub profile: &'a str,
    /// Its email addresses.
    pub emails: &'a str,
    /// The apps that keep access to it.
    pub apps: &'a str,
    /// Its security history, as its owner sees it.
    pub history: &'a str,
    /// Giving it a new handle.
    pub handle: &'a str,
    /// Giving it a new display name.
    pub display_name: &'a str,
}

/// One account's page: `detail`, with its profile picture at `picture`, the
/// `pages` changing it, or why there are none, its `sessions`, and its `recent`
/// events, linking `all_events`.
#[component]
pub async fn user_page<'a>(
    cx: &Cx,
    detail: &'a UserDetail,
    picture: Option<&'a str>,
    pages: Result<AccountPages<'a>, &'a str>,
    sessions: &'a [SessionRow<'a>],
    recent: &'a [EventRow<'a>],
    all_events: &'a str,
) -> Result<impl View> {
    let user = &detail.user;
    let who = Who {
        user: None,
        name: &user.display_name,
        handle: user.handle.as_str(),
        picture,
        administrator: detail.administrator,
    };
    Ok(view! {
        page_head(
            title: user.display_name.as_str(),
            lead: format!("@{}", user.handle),
            actions: view! {
                avatar(who: who)
                account_status(status: user.status)
                if detail.administrator {
                    <span class="badge admin"><span class="dot"></span>"Administrator"</span>
                }
            },
        )
        <section class="card">
            <div class="body">
                <dl class="facts">
                    <dt>"Account ID"</dt><dd><code>(user.id.to_string())</code></dd>
                    <dt>"Created"</dt><dd>moment(at: user.created_at)</dd>
                    if let Some(deletion) = &detail.deletion {
                        <dt>"Purged after"</dt><dd>moment(at: deletion.purge_after)</dd>
                        if let Some(failure) = &deletion.failure {
                            <dt>"Failed purges"</dt><dd>(failure.attempts.to_string())</dd>
                            <dt>"Next attempt"</dt><dd>moment(at: failure.next_attempt_at)</dd>
                            <dt>"Last error"</dt><dd><code>(failure.last_error.as_str())</code></dd>
                        }
                    }
                </dl>
                account_actions(user: user, pages: pages)
            </div>
        </section>
        <div class="two">
            credentials(detail: detail)
        </div>
        session_list(sessions: sessions, pages: pages)
        <section class="card">
            <header><h2>"Consents " <span class="count">(detail.consents.len().to_string())</span></h2></header>
            if detail.consents.is_empty() {
                <p class="empty">"No remembered consent."</p>
            } else {
                <ul class="list">
                    #[key(position)]
                    for (position, consent) in detail.consents.iter().enumerate() {
                        <li>
                            <div class="text">
                                <strong>(consent.client_id.as_str())</strong>
                                <small>(consent.scopes.join(" "))</small>
                            </div>
                        </li>
                    }
                </ul>
            }
        </section>
        <section class="card">
            <header>
                <h2>"Recent events"</h2>
                <a href=(all_events)>"All events"</a>
            </header>
            event_rows(rows: recent)
        </section>
    })
}

/// An account's `sessions`, each with the change ending it, and the one ending
/// them all, or why the `pages` offer none.
#[component]
async fn session_list<'a>(
    cx: &Cx,
    sessions: &'a [SessionRow<'a>],
    pages: Result<AccountPages<'a>, &'a str>,
) -> Result<impl View> {
    Ok(view! {
    <section class="card">
        <header>
            <h2>"Sessions " <span class="count">(sessions.len().to_string())</span></h2>
            if !sessions.is_empty() {
                match pages {
                    Ok(pages) => {
                        confirm(action: pages.revoke_sessions, change: Change::RevokeSessions)
                    },
                    Err(reason) => {
                        refused_action(label: "Revoke all", reason: reason)
                    },
                }
            }
        </header>
        if sessions.is_empty() {
            <p class="empty">"No active session."</p>
        } else {
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr><th>"signed in"</th><th>"methods"</th><th>"last seen"</th><th>"expires"</th><th></th></tr>
                    </thead>
                    <tbody>
                        #[key(position)]
                        for (position, row) in sessions.into_iter().enumerate() {
                            <tr>
                                <td>moment(at: row.session.authenticated_at)</td>
                                <td>(row.methods())</td>
                                <td>moment(at: row.session.last_seen_at)</td>
                                <td>moment(at: row.session.expires_at)</td>
                                <td class="right">
                                    if let Some(revoke) = &row.revoke {
                                        confirm(action: revoke, change: Change::RevokeSession)
                                    }
                                </td>
                            </tr>
                        }
                    </tbody>
                </table>
            </div>
        }
    </section>
        })
}

/// What may be done to `user`, by its `pages`, or why nothing may.
#[component]
async fn account_actions<'a>(
    cx: &Cx,
    user: &'a User,
    pages: Result<AccountPages<'a>, &'a str>,
) -> Result<impl View> {
    Ok(view! {
        <div class="row actions">
            match pages {
                Ok(pages) => {
                    match user.status {
                        AccountStatus::Active => {
                            confirm(action: pages.status, change: Change::Disable)
                            confirm(action: pages.delete, change: Change::Delete)
                        },
                        AccountStatus::Disabled => {
                            confirm(action: pages.status, change: Change::Enable)
                        },
                        AccountStatus::Deleting => {
                            confirm(action: pages.status, change: Change::Restore)
                        },
                    }
                    <a data-confirm-first="" class="button secondary small" href=(pages.recover)>"Recover"</a>
                    <a data-confirm-first="" class="button secondary small" href=(pages.undo_recovery)>"Undo recovery"</a>
                    <a data-confirm-first="" class="button secondary small" href=(pages.sign_in)>"Sign-in methods"</a>
                    <a data-confirm-first="" class="button secondary small" href=(pages.profile)>"Profile"</a>
                    <a data-confirm-first="" class="button secondary small" href=(pages.emails)>"Email addresses"</a>
                    <a data-confirm-first="" class="button secondary small" href=(pages.apps)>"Connected apps"</a>
                    <a class="button secondary small" href=(pages.history)>"Security history"</a>
                    <a data-confirm-first="" class="button secondary small" href=(pages.handle)>"Change handle"</a>
                    <a data-confirm-first="" class="button secondary small" href=(pages.display_name)>"Change display name"</a>
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
async fn credentials<'a>(cx: &Cx, detail: &'a UserDetail) -> Result<impl View> {
    Ok(view! {
        <section class="card">
            <header><h2>"Emails " <span class="count">(detail.emails.len().to_string())</span></h2></header>
            if detail.emails.is_empty() {
                <p class="empty">"No email address."</p>
            } else {
                <ul class="list">
                    #[key(position)]
                    for (position, email) in detail.emails.iter().enumerate() {
                        <li>
                            <div class="text">
                                private_address(address: email.address.as_str())
                                <small>
                                    match email.verified_at {
                                        Some(at) => { "verified " moment(at: at) },
                                        None => "unverified",
                                    }
                                </small>
                            </div>
                            if email.primary { <span class="badge">"Primary"</span> }
                        </li>
                    }
                </ul>
            }
        </section>
        <section class="card">
            <header><h2>"Sign-in methods"</h2></header>
            <ul class="list">
                #[key(position)]
                for (position, passkey) in detail.passkeys.iter().enumerate() {
                    <li>
                        <div class="text">
                            <strong>"Passkey"</strong>
                            <small><code>(passkey.id.to_string())</code> " · added " moment(at: passkey.created_at)</small>
                        </div>
                    </li>
                }
                #[key(position)]
                for (position, identity) in detail.identities.iter().enumerate() {
                    <li>
                        <div class="text">
                            <strong>(identity.provider.to_string())</strong>
                            if let Some(email) = &identity.linked_email {
                                <small>private_address(address: email.as_str())</small>
                            }
                        </div>
                    </li>
                }
            </ul>
            if detail.passkeys.is_empty() && detail.identities.is_empty() {
                <p class="empty">"No passkey and no linked identity."</p>
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
