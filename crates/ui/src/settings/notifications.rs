//! The inbox: the account's notifications, newest first, and one notification's
//! own page.

use super::{Audience, HistoryRow, Holdings, timeline::report_form};
use crate::{
    form::{Precision, Query, change_form, open, time},
    icons::{Icon, icon},
    layout::page_head,
};
use chrono::{DateTime, Utc};
use piquel_common::NotificationId;
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the inbox posts, named by its `action` field. Read state changes
/// nothing about the account, so it needs no passkey confirmation.
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
}

/// Which page of the inbox shows, as its query names it.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct InboxState {
    /// The notification the page starts after, if not the newest.
    pub before: Option<NotificationId>,
}

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
        .map(|next| InboxState { before: Some(next) }.on(page.page))
        .transpose()?;
    let empty = match (before, owner) {
        (Some(_), _) => "No older notifications.",
        (None, true) => {
            "Nothing to tell you yet. Piquel lets you know here when something important happens to your account."
        }
        (None, false) => "This account has no notifications.",
    };
    Ok(view! {
        if owner {
            page_head(
                title: "Notifications",
                lead: "What Piquel tells you about your account. Opening one marks it read.".to_owned(),
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
                                <p>(row.body)</p>
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
                    <small>"Piquel told you about something that happened to your account."</small>
                </div>
                <a class="button small" href=(page)>"Read"</a>
            </section>
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
    /// Its event's entry in the security history, while kept.
    pub entry: Option<&'a HistoryRow<'a>>,
    /// What the account holds, to name what the entry refers to.
    pub holds: Holdings<'a>,
    /// Whether the report's confirmation is open.
    pub shown: NotificationState,
}

/// One notification's page: what it says, its security history entry while the
/// history keeps it, which the owner may report as not theirs where the history
/// allows, the recovery's undo page when it is about one, and marking it unread.
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
                <p>(row.body)</p>
                if let Some(undo) = page.undo {
                    <p><a class="button danger" href=(undo)>"Undo the recovery"</a></p>
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
                                report_form(row: entry, action: page.history, before: None, cancel: page.here)
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
