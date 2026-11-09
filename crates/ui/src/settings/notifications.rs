//! The inbox: the account's notifications, newest first, and one notification's
//! own page.

use super::{Audience, HistoryRow, Holdings, Tab, timeline::report_form};
use crate::{
    form::{Checkbox, Precision, Query, change_form, open, time},
    icons::{Icon, icon},
    layout::{announcement_text, dialog, page_head},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sourceorigin_common::{
    NotificationId,
    notifications::{EmailCategory, NotificationPreference, SIGN_OUT_LINK_LIFETIME},
};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the inbox posts, named by its `action` field. Read state and email
/// preferences change nothing about the account, so they need no passkey
/// confirmation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum InboxChange {
    /// Marks every notification read.
    ReadAll,
    /// Marks one notification unread, from its own page.
    MarkUnread {
        /// The notification.
        id: NotificationId,
    },
    /// Says the owner recognizes what a security notification tells, from the
    /// settings' banner, which marks it read.
    Recognized {
        /// The notification.
        id: NotificationId,
        /// The settings page the banner was on, which the answer goes back to;
        /// the inbox otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        back: Option<Tab>,
    },
    /// Turns a category's email on, or off.
    Email {
        /// The category.
        category: EmailCategory,
        /// Whether it is emailed from now on.
        #[serde(default, skip_serializing_if = "Checkbox::is_off")]
        email: Checkbox,
    },
}

/// Which page of the inbox shows, and whether its email preferences dialog shows
/// open, as its query names them.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct InboxState {
    /// The notification the page starts after, if not the newest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<NotificationId>,
    /// Whether the email preferences dialog shows open, as after a change in it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub email: bool,
}

/// The element ID of the inbox's email preferences dialog.
const EMAIL_DIALOG: &str = "dialog-email";

impl Query for InboxState {}

/// Whether a notification's page asks to confirm that its event was not the
/// owner's, as its query names it.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct NotificationState {
    /// Whether the confirmation is open.
    #[serde(default)]
    pub reporting: bool,
}

impl Query for NotificationState {}

/// A notification as the inbox lists it.
#[derive(Clone, Copy, Debug)]
pub struct InboxRow<'a> {
    /// Its ID, which its page's path names.
    pub id: NotificationId,
    /// When it was written.
    pub created_at: DateTime<Utc>,
    /// Whether the owner read it.
    pub read: bool,
    /// Its subject.
    pub subject: &'a str,
    /// What it says.
    pub body: &'a str,
}

/// Where the inbox is and which page of it shows.
#[derive(Clone, Copy, Debug)]
pub struct InboxPage<'a> {
    /// The inbox, which its forms post to.
    pub page: &'a str,
    /// A notification's page, with `{id}` for its ID; `None` lists each one's
    /// text in full instead, as an administrator reads them.
    pub item: Option<&'a str>,
    /// Which page of the inbox shows.
    pub shown: InboxState,
    /// The notification after which older ones follow, if any.
    pub next: Option<NotificationId>,
    /// How many notifications are unread.
    pub unread: u64,
    /// Who reads it: the owner opens each notification and marks them read; an
    /// administrator only reads them, which marks nothing.
    pub audience: Audience<'a>,
    /// Whether each category's notifications are emailed, which only the owner
    /// changes.
    pub preferences: &'a [NotificationPreference],
    /// Why a change to them was refused, which their dialog, shown again, says.
    pub alert: Option<&'a str>,
}

impl InboxPage<'_> {
    /// The page of the notification `id`, if notifications have pages.
    fn link(&self, id: NotificationId) -> Option<String> {
        self.item.map(|item| item.replace("{id}", &id.to_string()))
    }
}

/// The inbox: `rows`, newest first, each opening its own page, unread ones
/// marked, with marking every one read; or, for an administrator, each one's
/// text, read or not.
#[component]
pub async fn inbox<'a>(rows: &'a [InboxRow<'a>], page: InboxPage<'a>) -> Result<impl View> {
    let owner = page.audience.owns();
    let before = page.shown.before;
    let older = page
        .next
        .map(|next| {
            InboxState {
                before: Some(next),
                email: false,
            }
            .on(page.page)
        })
        .transpose()?;
    let empty = match (before, owner) {
        (Some(_), _) => "No older notifications.",
        (None, true) => {
            "Nothing to tell you yet. SourceOrigin lets you know here when something important happens to your account."
        }
        (None, false) => "This account has no notifications.",
    };
    Ok(view! {
        if owner {
            page_head(
                title: "Notifications",
                lead: "What SourceOrigin tells you. Opening one marks it read.".to_owned(),
                actions: view! { email_button() },
            )
        }
        <section class="card" aria-labelledby="inbox-heading">
            <header>
                <h2 id="inbox-heading">
                    "Notifications"
                    if page.unread > 0 {
                        " " <span class="count">(format!("{} unread", page.unread))</span>
                    }
                </h2>
                if owner && page.unread > 0 {
                    change_form(
                        action: page.page,
                        change: InboxChange::ReadAll,
                        label: "Mark all as read",
                        class: "secondary small",
                    )
                }
                if !owner {
                    email_button()
                }
            </header>
            <ul class="list inbox">
                for row in rows {
                    <li class=(if row.read { "read" } else { "unread" })>
                        <span class=(if row.read { "dot" } else { "dot accent" }) title=(if row.read { "Read" } else { "Unread" })></span>
                        <div class="text">
                            if let Some(link) = page.link(row.id) {
                                <a href=(link.as_str())>
                                    if row.read { (row.subject) } else { <strong>(row.subject)</strong> }
                                </a>
                            } else {
                                <strong>(row.subject)</strong>
                                announcement_text(body: row.body)
                                <small>(if row.read { "Read by the owner" } else { "Not read yet" })</small>
                            }
                        </div>
                        time(at: row.created_at, precision: Precision::Minute)
                    </li>
                }
            </ul>
            if rows.is_empty() && page.next.is_none() {
                <p class="empty">(empty)</p>
            }
        </section>
        <div class="row">
            if let Some(older) = &older {
                <a class="button secondary" href=(older.as_str())>"Show older notifications"</a>
            }
            if before.is_some() {
                <a class="button secondary" href=(page.page)>"Newest notifications"</a>
            }
        </div>
        email_preferences(page: page)
    })
}

/// The button opening the email preferences dialog: in the page's head for the
/// owner, in the inbox's for an administrator.
#[component]
async fn email_button() -> Result<impl View> {
    Ok(view! {
        <button type="button" class="secondary small" popovertarget=(EMAIL_DIALOG)>
            icon(kind: Icon::Mail)
            "Email preferences"
        </button>
    })
}

/// The dialog saying which categories of notifications are emailed, each with a
/// button turning its email on or off for the owner, read-only for an
/// administrator. A change reopens it, showing what changed.
#[component]
async fn email_preferences<'a>(page: InboxPage<'a>) -> Result<impl View> {
    let owner = page.audience.owns();
    Ok(view! {
        dialog(id: EMAIL_DIALOG, title: "Email preferences", shown: page.shown.email, back: page.page, alert: page.alert, focus_close: true,
            <p class="help">
                (if owner {
                    "SourceOrigin always emails you about your account itself, at your primary address: its addresses, sign-in methods and recovery, and what support changes. Choose what else it emails you."
                } else {
                    "SourceOrigin always emails the owner about their account itself. Only the owner turns the rest on or off."
                })
            </p>
            <ul class="list">
                for preference in page.preferences {
                    <li>
                        <div class="text">
                            <strong>(preference.category.label())</strong>
                            " "
                            if preference.email {
                                <span class="badge ok">"Emailed"</span>
                            } else {
                                <span class="badge">"Not emailed"</span>
                            }
                            <small>(preference.category.description())</small>
                        </div>
                        if owner {
                            change_form(
                                action: page.page,
                                change: InboxChange::Email {
                                    category: preference.category,
                                    email: Checkbox(!preference.email),
                                },
                                label: if preference.email { "Turn off" } else { "Turn on" },
                                class: "secondary small",
                                aria_label: format!(
                                    "Turn {} emails for {}",
                                    if preference.email { "off" } else { "on" },
                                    preference.category.label(),
                                ),
                            )
                        }
                    </li>
                }
            </ul>
        )
    })
}

/// What the unsubscribe page shows.
#[derive(Clone, Copy, Debug)]
pub enum UnsubscribeStep<'a> {
    /// Asks to turn announcements' email off, posting to `action`, the link
    /// itself.
    Confirm {
        /// The link.
        action: &'a str,
    },
    /// It is off; the inbox at `notifications` turns it back on.
    Done {
        /// The inbox.
        notifications: &'a str,
    },
    /// The link is not one Origin Auth made, or not whole.
    Invalid,
}

/// The page an announcement's unsubscribe link opens, at `step`.
#[component]
pub async fn unsubscribe(step: UnsubscribeStep<'_>) -> Result<impl View> {
    Ok(view! {
        match step {
            UnsubscribeStep::Confirm { action } => {
                <h1>"Stop announcement emails?"</h1>
                <p class="lead">
                    "You will still find SourceOrigin’s announcements in your notifications, and receive by email those about a security incident or a change to the privacy policy or terms. Emails about your account itself keep coming."
                </p>
                <form method="post" action=(action) data-submit-once="true">
                    <button type="submit">"Stop announcement emails"</button>
                </form>
            }
            UnsubscribeStep::Done { notifications } => {
                <h1>"Announcement emails stopped"</h1>
                <p class="lead">
                    "SourceOrigin no longer emails you its announcements, except those about a security incident or a change to the privacy policy or terms. Turn them back on from your notifications."
                </p>
                <a class="button secondary" href=(notifications)>"Open your notifications"</a>
            }
            UnsubscribeStep::Invalid => {
                <h1>"This link doesn’t work"</h1>
                <p class="lead">
                    "Open the link from the email again, or turn announcement emails off from your notifications."
                </p>
            }
        }
    })
}

/// What the overview says while `unread` notifications are unread, linking the
/// inbox at `page`; nothing once every one is read.
#[component]
pub(crate) async fn unread_hint(unread: u64, page: &str) -> Result<impl View> {
    let said = match unread {
        1 => "You have an unread notification".to_owned(),
        unread => format!("You have {unread} unread notifications"),
    };
    Ok(view! {
        if unread > 0 {
            <section class="hint">
                icon(kind: Icon::Bell)
                <div class="text">
                    <strong>(said)</strong>
                    <small>"SourceOrigin has something to tell you."</small>
                </div>
                <a class="button small" href=(page)>"Read"</a>
            </section>
        }
    })
}

/// An unread security notification the settings' banner asks about.
#[derive(Clone, Copy, Debug)]
pub struct AlertRow<'a> {
    /// The notification.
    pub row: InboxRow<'a>,
    /// Whether the owner may report its event as not theirs, as its history
    /// entry allows.
    pub reportable: bool,
}

/// Where the settings' banner of unread security notifications leads.
#[derive(Clone, Copy, Debug)]
pub struct AlertBanner<'a> {
    /// The inbox, which "This was me" posts to.
    pub inbox: &'a str,
    /// A notification's page, with `{id}` for its ID.
    pub item: &'a str,
    /// The settings page the banner is on, which "This was me" comes back to.
    pub back: Option<Tab>,
}

/// The banner every settings page shows above itself while security
/// notifications are unread: each one's subject and time, "This was me", which
/// marks it read, and "This wasn't me", which opens its page to report its event,
/// where the history allows a report, or "Review" otherwise.
#[component]
pub async fn security_banner<'a>(
    alerts: &'a [AlertRow<'a>],
    banner: AlertBanner<'a>,
) -> Result<impl View> {
    Ok(view! {
        if !alerts.is_empty() {
            <section class="notice warning stack" aria-label="Unread security notifications">
                for alert in alerts {
                    let page = banner.item.replace("{id}", &alert.row.id.to_string());
                    let report = NotificationState { reporting: true }.on(&page)?;
                    <div class="row">
                        <div class="text">
                            <strong>(alert.row.subject)</strong>
                            " "
                            time(at: alert.row.created_at, precision: Precision::Minute)
                        </div>
                        change_form(
                            action: banner.inbox,
                            change: InboxChange::Recognized { id: alert.row.id, back: banner.back },
                            label: "This was me",
                            class: "secondary small",
                            aria_label: format!("This was me: {}", alert.row.subject),
                        )
                        if alert.reportable {
                            <a class="button danger small" href=(report.as_str())>"This wasn’t me"</a>
                        } else {
                            <a class="button secondary small" href=(page.as_str())>"Review"</a>
                        }
                    </div>
                }
            </section>
        }
    })
}

/// What the page of a security notification's "sign me out everywhere" link
/// shows.
#[derive(Clone, Copy, Debug)]
pub enum SignOutStep<'a> {
    /// Asks to sign out everywhere, posting to `action`, the link itself.
    Confirm {
        /// The link.
        action: &'a str,
    },
    /// Every device and app was signed out; signing in again goes on to the
    /// security history at `history`.
    Done {
        /// The security history.
        history: &'a str,
    },
    /// The link is not one Origin Auth made, or not whole, was used already, or
    /// expired.
    Invalid,
}

/// The page a security notification's email links to sign the account out
/// everywhere, without signing in, at `step`.
#[component]
pub async fn sign_out_everywhere(step: SignOutStep<'_>) -> Result<impl View> {
    Ok(view! {
        match step {
            SignOutStep::Confirm { action } => {
                <h1>"Sign out everywhere?"</h1>
                <p class="lead">
                    "This signs your Origin Account out of every device, and every app you use with it must sign in again. Your passkeys and social sign-ins keep working, so you can sign back in. Anyone else signed in to your account loses access."
                </p>
                <form method="post" action=(action) data-submit-once="true">
                    <button type="submit" class="danger">"Sign out everywhere"</button>
                </form>
            }
            SignOutStep::Done { history } => {
                <h1>"You’re signed out everywhere"</h1>
                <p class="lead">
                    "Every device and app was signed out of your Origin Account. Sign in again with your passkey, then check your security history for anything you don’t recognize."
                </p>
                <a class="button" href=(history)>"Sign in and review your history"</a>
            }
            SignOutStep::Invalid => {
                <h1>"This link doesn’t work"</h1>
                <p class="lead">
                    (format!(
                        "Each link signs you out once, within {} days of its email. Sign in to sign your other devices out from your settings, or use the link of a newer email.",
                        SIGN_OUT_LINK_LIFETIME.num_days()
                    ))
                </p>
            }
        }
    })
}

/// What a notification's page shows besides the notification.
#[derive(Clone, Copy, Debug)]
pub struct NotificationPage<'a> {
    /// The notification's page itself, which its confirmation opens on.
    pub here: &'a str,
    /// The inbox, which marking it unread posts to and goes back to.
    pub inbox: &'a str,
    /// The security history, which a report posts to.
    pub history: &'a str,
    /// The page undoing the account's recovery, while one can still be undone
    /// and the notification is about it.
    pub undo: Option<&'a str>,
    /// The admin dashboard's Alerts tab, for an alert's notification, unless
    /// the dashboard is off.
    pub alerts: Option<&'a str>,
    /// Its event's entry in the security history, while kept.
    pub entry: Option<&'a HistoryRow<'a>>,
    /// What the account holds, to name what the entry refers to.
    pub holds: Holdings<'a>,
    /// Whether the report's confirmation is open.
    pub shown: NotificationState,
}

/// One notification's page: what it says, its security history entry while the
/// history keeps it, which the owner may report as not theirs where the history
/// allows, the recovery's undo page when it is about one, the dashboard's
/// alerts for an alert's, and marking it unread.
#[component]
pub async fn notification<'a>(row: InboxRow<'a>, page: NotificationPage<'a>) -> Result<impl View> {
    let reportable = page.entry.filter(|entry| entry.reportable);
    Ok(view! {
        <article class="card" aria-labelledby="notification-heading">
            <header>
                <h2 id="notification-heading">(row.subject)</h2>
                time(at: row.created_at, precision: Precision::Minute)
            </header>
            <div class="body">
                announcement_text(body: row.body)
                if let Some(undo) = page.undo {
                    <p><a class="button danger" href=(undo)>"Undo the recovery"</a></p>
                }
                if let Some(alerts) = page.alerts {
                    <p><a class="button" href=(alerts)>"See the alerts"</a></p>
                }
            </div>
            if let Some(entry) = page.entry {
                <ul class="events" aria-label="In your security history">
                    <li>
                        time(at: entry.occurred_at, precision: Precision::Minute)
                        <span class=(if entry.worrying() { "dot warning" } else { "dot ok" })></span>
                        <div class="text">
                            (entry.describe(&page.holds))
                            <small class="wrap">(entry.details().join(" · "))</small>
                            if let Some(by) = entry.by() {
                                <small class="wrap">(by)</small>
                            }
                            if let Some(entry) = reportable.filter(|_| page.shown.reporting) {
                                report_form(row: entry, action: page.history, before: None, notification: Some(row.id), cancel: page.here)
                            }
                        </div>
                        if reportable.is_some() && !page.shown.reporting {
                            open(
                                page: page.here,
                                opens: NotificationState { reporting: true },
                                label: "This wasn’t me",
                            )
                        }
                    </li>
                </ul>
            }
            <div class="body">
                change_form(
                    action: page.inbox,
                    change: InboxChange::MarkUnread { id: row.id },
                    label: "Mark as unread",
                    class: "secondary",
                )
            </div>
        </article>
    })
}
