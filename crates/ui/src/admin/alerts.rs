//! The alerts administrators are shown, and the updates they post on them.

use super::{Action, Change, confirm, moment};
use crate::layout::page_head;
use sourceorigin_common::alerts::{
    Alert, AlertAuthor, AlertDetail, AlertState, AlertStatus, AlertUpdate,
};
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// An alert's card, and the change posting an update on it while it is
/// current.
#[derive(Clone, Debug)]
pub struct AlertCard<'a> {
    /// The alert, with its updates.
    pub detail: &'a AlertDetail,
    /// Posting an update, while it is current and this release can read it.
    pub update: Option<Action>,
}

/// Where an alert's handling stands, as a badge's tone and label: monitoring
/// means the fix is in, so it reads as good.
const fn status_badge(status: AlertStatus) -> (&'static str, &'static str) {
    match status {
        AlertStatus::Investigating => ("warning", "Investigating"),
        AlertStatus::Fixing => ("warning", "Fixing"),
        AlertStatus::Monitoring => ("ok", "Monitoring"),
    }
}

/// An alert's badge, as a tone and a label: whether it needs attention, the
/// status its latest update gave, or that it cleared.
fn badge(detail: &AlertDetail) -> (&'static str, &'static str) {
    match (detail.alert.state(), detail.updates.last()) {
        (AlertState::Cleared, _) => ("neutral", "Cleared"),
        (AlertState::Open, _) | (AlertState::Acknowledged, None) => ("danger", "Needs attention"),
        (AlertState::Acknowledged, Some(update)) => status_badge(update.status),
    }
}

/// Who posted `update`, in words.
fn author(update: &AlertUpdate) -> String {
    match &update.author {
        AlertAuthor::Administrator {
            handle: Some(handle),
        } => format!("@{handle}"),
        AlertAuthor::Administrator { handle: None } => "a deleted account".to_owned(),
        AlertAuthor::Operator { os_user, host } => format!("the terminal, {os_user}@{host}"),
    }
}

/// The current alerts, `cards`, newest first, each with posting an update on
/// it, and a link to the alerts that cleared, at `previous`.
#[component]
pub async fn alert_list<'a>(cards: &'a [AlertCard<'a>], previous: &'a str) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Alerts",
            lead: "What needs an administrator's attention now. Post an update to say who is handling an alert and how: the first one acknowledges it, so it stops counting as a warning. An alert clears on its own once its condition no longer holds.".to_owned(),
            actions: view! { <a class="button secondary" href=(previous)>"See previous alerts"</a> },
        )
        if cards.is_empty() {
            <section class="card"><p class="empty">"No alert needs attention."</p></section>
        }
        for card in cards {
            alert_card(card: card)
        }
    })
}

/// The alerts that cleared, `cards`, the most recently cleared first, at most
/// `limit`, and a link back to the current ones, at `current`.
#[component]
pub async fn previous_alerts<'a>(
    cards: &'a [AlertCard<'a>],
    current: &'a str,
    limit: u32,
) -> Result<impl View> {
    let full = u32::try_from(cards.len()).is_ok_and(|shown| shown >= limit);
    Ok(view! {
        page_head(
            title: "Previous alerts",
            lead: "Alerts whose condition no longer holds, the most recently cleared first, with the updates posted while they were current.".to_owned(),
            actions: view! { <a class="button secondary" href=(current)>"Back to current alerts"</a> },
        )
        if cards.is_empty() {
            <section class="card"><p class="empty">"No alert has cleared yet."</p></section>
        }
        for card in cards {
            alert_card(card: card)
        }
        if full {
            <p class="help">(format!("Only the {limit} most recently cleared are shown."))</p>
        }
    })
}

/// One alert: what it says, when it was raised, last seen and cleared, the
/// updates posted on it, newest first, and posting one while it is current.
#[component]
async fn alert_card<'a>(card: &'a AlertCard<'a>) -> Result<impl View> {
    let detail = card.detail;
    let alert = &detail.alert;
    let (tone, label) = badge(detail);
    let subject = alert.alert.as_ref().map_or(Alert::UNKNOWN, Alert::subject);
    Ok(view! {
        <section class="card">
            <header>
                <h2>(subject)</h2>
                <span class=(class!("badge", tone))>(label)</span>
            </header>
            <div class="body">
                if let Some(says) = &alert.alert {
                    <p>(says.body())</p>
                }
                <dl class="facts">
                    <dt>"ID"</dt><dd><code>(alert.id.to_string())</code></dd>
                    <dt>"Raised"</dt><dd>moment(at: alert.raised_at)</dd>
                    <dt>"Last seen"</dt><dd>moment(at: alert.seen_at)</dd>
                    if let Some(cleared) = alert.cleared_at {
                        <dt>"Cleared"</dt><dd>moment(at: cleared)</dd>
                    }
                </dl>
                if let Some(update) = &card.update {
                    <div class="row actions">
                        confirm(action: update, change: Change::UpdateAlert, subject: subject, alert_update_fields())
                    </div>
                }
            </div>
            if !detail.updates.is_empty() {
                <ul class="events">
                    for update in detail.updates.iter().rev() {
                        <li>
                            moment(at: update.posted_at)
                            <span class=(class!("dot", status_badge(update.status).0))></span>
                            <div class="text">
                                <strong>(status_badge(update.status).1)</strong>
                                (format!(" by {}", author(update)))
                                if let Some(note) = &update.note {
                                    <small class="wrap">(note.as_str())</small>
                                }
                            </div>
                        </li>
                    }
                </ul>
            }
        </section>
    })
}

/// The fields of an update: where the alert's handling stands, and a note,
/// holding `status` and `note` as a refused update posted them.
#[component]
pub async fn alert_update_fields<'a>(
    #[into]
    #[default]
    status: Option<AlertStatus>,
    #[default] note: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <label>
            "Status"
            <select name="status" required="">
                for each in AlertStatus::ALL {
                    <option value=(each.as_str()) selected=(status == Some(each))>(status_badge(each).1)</option>
                }
            </select>
        </label>
        <label>
            "Note, such as who is on it (optional)"
            <input name="note" maxlength="500" value=(note)>
        </label>
    })
}
