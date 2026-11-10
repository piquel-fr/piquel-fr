//! Account search and one account's page.

use super::{
    Action, Change, EventRow, Target, account_status, confirm, event_rows, moment, refused_action,
};
use crate::{
    email::{Mail, email_preview},
    icons::Icon,
    layout::{
        AvatarSize, Destination, Group, Pager, Who, avatar, page_head, pager, private_address,
    },
};
use sourceorigin_common::{
    AccountStatus, AuthenticationMethod,
    admin::{MessageUser, Session, User, UserDetail},
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
    /// Whether it administers Origin Auth.
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
            name: &self.user.display_name,
            handle: self.user.handle.as_str(),
            picture: self.picture.as_deref(),
            administrator: self.administrator,
        }
    }
}

impl<'a> From<&'a UserRow<'a>> for Destination<'a> {
    /// The account as the dashboard's search finds it: by its handle, beside its
    /// display name, and by its ID.
    fn from(row: &'a UserRow<'a>) -> Self {
        Self {
            group: Group::Accounts,
            icon: Icon::Profile,
            title: format!("@{}", row.user.handle).into(),
            trail: row.user.display_name.as_str().into(),
            terms: row.user.id.to_string().into(),
            href: row.href.as_str().into(),
            confirms: false,
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
                            for row in rows {
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
/// does not administer Origin Auth: the short ones confirm on the account's page, the
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
    /// Its inbox, as its owner sees it.
    pub notifications: &'a str,
    /// Giving it a new handle.
    pub handle: &'a str,
    /// Giving it a new display name.
    pub display_name: &'a str,
}

/// One account's page: `detail`, with its profile picture at `picture`, the
/// `pages` changing it, or why there are none, the page sending it a `message`,
/// which every account has, its `sessions`, the browsers it knows, and its
/// `recent` events, linking `all_events`.
#[component]
pub async fn user_page<'a>(
    detail: &'a UserDetail,
    picture: Option<&'a str>,
    pages: Result<AccountPages<'a>, &'a str>,
    message: &'a str,
    sessions: &'a [SessionRow<'a>],
    recent: &'a [EventRow<'a>],
    all_events: &'a str,
) -> Result<impl View> {
    let user = &detail.user;
    // The account, as the passkey dialog names it.
    let named = format!("{} ({})", user.handle, user.id);
    let who = Who {
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
                account_actions(user: user, pages: pages, message: message, named: named.as_str())
            </div>
        </section>
        <div class="two">
            credentials(detail: detail)
        </div>
        session_list(sessions: sessions, pages: pages, account: named.as_str(), handle: user.handle.as_str())
        crate::settings::known_devices(known: &detail.known_devices)
        <section class="card">
            <header><h2>"Consents " <span class="count">(detail.consents.len().to_string())</span></h2></header>
            if detail.consents.is_empty() {
                <p class="empty">"No remembered consent."</p>
            } else {
                <ul class="list">
                    for consent in &detail.consents {
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
/// them all, or why the `pages` offer none. The passkey dialog names the
/// `account` when ending them all, and each session by the account's `handle`.
#[component]
async fn session_list<'a>(
    sessions: &'a [SessionRow<'a>],
    pages: Result<AccountPages<'a>, &'a str>,
    account: &'a str,
    handle: &'a str,
) -> Result<impl View> {
    Ok(view! {
    <section class="card">
        <header>
            <h2>"Sessions " <span class="count">(sessions.len().to_string())</span></h2>
            if !sessions.is_empty() {
                match pages {
                    Ok(pages) => {
                        confirm(action: pages.revoke_sessions, change: Change::RevokeSessions, target: account)
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
                        for row in sessions {
                            <tr>
                                <td>moment(at: row.session.authenticated_at)</td>
                                <td>
                                    (row.methods())
                                    // An administrator's sign-in to this dashboard,
                                    // resting on the session.
                                    if let Some(dashboard) = row.session.dashboard.first() {
                                        <br><small>"dashboard, used " moment(at: dashboard.last_used_at)</small>
                                    }
                                </td>
                                <td>moment(at: row.session.last_seen_at)</td>
                                <td>moment(at: row.session.expires_at)</td>
                                <td class="right">
                                    if let Some(revoke) = &row.revoke {
                                        let session = format!("{handle}, session ({})", row.session.id);
                                        confirm(action: revoke, change: Change::RevokeSession, target: session.as_str())
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

/// What may be done to `user`, by its `pages`, or why nothing may, and sending
/// it a `message`, which even an administrator's account takes: it changes
/// nothing. The passkey dialog names the account as `named`.
#[component]
async fn account_actions<'a>(
    user: &'a User,
    pages: Result<AccountPages<'a>, &'a str>,
    message: &'a str,
    named: &'a str,
) -> Result<impl View> {
    let target = Some(named);
    let opening = move |what: &str| format!("{what}: {named}");
    Ok(view! {
        <div class="row actions">
            match pages {
                Ok(pages) => {
                    match user.status {
                        AccountStatus::Active => {
                            confirm(action: pages.status, change: Change::Disable, target: target)
                            confirm(action: pages.delete, change: Change::Delete, target: target)
                        },
                        AccountStatus::Disabled => {
                            confirm(action: pages.status, change: Change::Enable, target: target)
                        },
                        AccountStatus::Deleting => {
                            confirm(action: pages.status, change: Change::Restore, target: target)
                        },
                    }
                    <a data-confirm-first="" data-confirming=(Change::Recover.confirming(target)) class="button secondary small" href=(pages.recover)>"Recover"</a>
                    <a data-confirm-first="" data-confirming=(Change::UndoRecovery.confirming(target)) class="button secondary small" href=(pages.undo_recovery)>"Undo recovery"</a>
                    <a data-confirm-first="" data-confirming=(opening("Sign-in methods")) class="button secondary small" href=(pages.sign_in)>"Sign-in methods"</a>
                    <a data-confirm-first="" data-confirming=(opening("Profile")) class="button secondary small" href=(pages.profile)>"Profile"</a>
                    <a data-confirm-first="" data-confirming=(opening("Email addresses")) class="button secondary small" href=(pages.emails)>"Email addresses"</a>
                    <a data-confirm-first="" data-confirming=(opening("Connected apps")) class="button secondary small" href=(pages.apps)>"Connected apps"</a>
                    <a class="button secondary small" href=(pages.history)>"Security history"</a>
                    <a class="button secondary small" href=(pages.notifications)>"Notifications"</a>
                    <a data-confirm-first="" data-confirming=(Change::ChangeHandle.confirming(target)) class="button secondary small" href=(pages.handle)>"Change handle"</a>
                    <a data-confirm-first="" data-confirming=(Change::ChangeDisplayName.confirming(target)) class="button secondary small" href=(pages.display_name)>"Change display name"</a>
                },
                Err(reason) => {
                    refused_action(label: "Change", reason: reason)
                },
            }
            <a class="button secondary small" href=(message)>"Send a message"</a>
        </div>
    })
}

/// A message's email, as it will be sent.
#[derive(Clone, Copy, Debug)]
pub struct MessagePreview<'a> {
    /// The email.
    pub email: &'a Mail,
    /// The account's primary verified address, which it is emailed to, if the
    /// account has one.
    pub address: Option<&'a str>,
}

/// A message to the account `handle`, `form` as typed, with a link `back` to
/// the account's page and why the last attempt was refused, if it was. Without
/// a `preview`, the form writing it, whose button shows its email; with one,
/// that email, with buttons sending it, which needs the dashboard's passkey
/// confirmation, and changing its text again.
#[component]
pub async fn message_page<'a>(
    handle: &'a str,
    back: &'a str,
    form: &'a MessageUser,
    #[into]
    #[default]
    target: Option<Target<'a>>,
    #[into]
    #[default]
    preview: Option<MessagePreview<'a>>,
    #[into]
    #[default]
    refusal: Option<&'a str>,
) -> Result<impl View> {
    let change = Change::Message;
    // What its Send asks a passkey for: the account, by handle and ID.
    let named = target.map(Target::text);
    let confirming = change.confirming(named.as_deref());
    Ok(view! {
        page_head(title: change.title(), lead: format!("To @{handle}. {}", change.description()))
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        <section class="card">
            <form class="stack" method="post" data-submit-once="" data-unconfirmed="" data-confirming=(confirming.as_str())>
                match preview {
                    None => {
                        <label>
                            "Subject"
                            <input name="subject" required="" maxlength="150" value=(form.subject.as_str()) autofocus="">
                        </label>
                        <label>
                            "Text"
                            <textarea name="body" required="" rows="14" maxlength="20000">(form.body.as_str())</textarea>
                            <small>"The email starts with “Hello,” and ends with “SourceOrigin”. Separate paragraphs with a blank line. Links are written out in full: mail apps make them clickable."</small>
                        </label>
                        <div class="row actions">
                            <button name="intent" value="preview">"Preview the email"</button>
                            <a class="button secondary" href=(back)>"Cancel"</a>
                        </div>
                    },
                    Some(preview) => {
                        <input type="hidden" name="subject" value=(form.subject.as_str())>
                        <input type="hidden" name="body" value=(form.body.as_str())>
                        <dl class="facts">
                            <dt>"To"</dt><dd>(format!("@{handle}"))</dd>
                            <dt>"Subject"</dt><dd>(form.subject.as_str())</dd>
                            <dt>"Emailed to"</dt>
                            <dd>
                                match preview.address {
                                    Some(address) => private_address(address: address),
                                    None => "Nobody: the account has no primary verified address. Its owner finds it in their inbox.",
                                }
                            </dd>
                        </dl>
                        email_preview(mail: preview.email)
                        if let Some(target) = target {
                            <p class="target">
                                <strong>(target.name)</strong>
                                if let Some(id) = target.id {
                                    " " <code>(id)</code>
                                }
                            </p>
                        }
                        <div class="row actions">
                            <button name="intent" value="send" data-confirms="">(change.button())</button>
                            <button class="secondary" name="intent" value="edit">"Edit"</button>
                            <a class="button secondary" href=(back)>"Cancel"</a>
                        </div>
                    },
                }
            </form>
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
            <header><h2>"Emails " <span class="count">(detail.emails.len().to_string())</span></h2></header>
            if detail.emails.is_empty() {
                <p class="empty">"No email address."</p>
            } else {
                <ul class="list">
                    for email in &detail.emails {
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
                for passkey in &detail.passkeys {
                    <li>
                        <div class="text">
                            <strong>"Passkey"</strong>
                            <small><code>(passkey.id.to_string())</code> " · added " moment(at: passkey.created_at)</small>
                        </div>
                    </li>
                }
                for identity in &detail.identities {
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
