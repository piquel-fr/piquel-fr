//! The alerts administrators are shown.

use super::{Action, Change, confirm, moment};
use crate::layout::page_head;
use piquel_common::alerts::{AlertState, StoredAlert};
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// An alert, and acknowledging it, while it is open.
#[derive(Clone, Debug)]
pub struct AlertRow<'a> {
    /// The alert.
    pub alert: &'a StoredAlert,
    /// Acknowledging it, while it is open.
    pub acknowledge: Option<Action>,
}

/// An alert's state, as a badge's tone and label.
const fn state_badge(state: AlertState) -> (&'static str, &'static str) {
    match state {
        AlertState::Open => ("danger", "Open"),
        AlertState::Acknowledged => ("warning", "Acknowledged"),
        AlertState::Cleared => ("neutral", "Cleared"),
    }
}

/// The alerts, `rows`: the current ones, then those that cleared, each newest
/// first, at most `limit`.
#[component]
pub async fn alert_list<'a>(rows: &'a [AlertRow<'a>], limit: u32) -> Result<impl View> {
    let full = u32::try_from(rows.len()).is_ok_and(|shown| shown >= limit);
    Ok(view! {
        page_head(
            title: "Alerts",
            lead: "What needs an administrator's attention, such as a broken audit chain. An alert stays current while its condition holds, and clears once it no longer does.".to_owned(),
        )
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No alert."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>"alert"</th>
                                <th>"state"</th>
                                <th>"raised"</th>
                                <th>"last seen"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                let alert = row.alert;
                                let (tone, label) = state_badge(alert.state());
                                let subject = alert.alert.as_ref().map_or("An alert this release cannot show", |alert| alert.subject());
                                <tr>
                                    <td>
                                        <strong>(subject)</strong>
                                        if let Some(says) = &alert.alert {
                                            <br><small class="muted">(says.body())</small>
                                        }
                                    </td>
                                    <td><span class=(class!("badge", tone))>(label)</span></td>
                                    <td>moment(at: alert.raised_at)</td>
                                    <td>moment(at: alert.seen_at)</td>
                                    <td class="right">
                                        if let Some(acknowledge) = &row.acknowledge {
                                            confirm(action: acknowledge, change: Change::AcknowledgeAlert, subject: subject)
                                        }
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
        if full {
            <p class="help">(format!("Only {limit} are shown: the current ones, then the newest that cleared."))</p>
        }
    })
}
