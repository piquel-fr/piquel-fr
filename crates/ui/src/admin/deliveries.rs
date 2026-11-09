//! The outbound delivery queue.

use super::{Action, Change, confirm, moment};
use crate::layout::page_head;
use sourceorigin_common::admin::{DeliveryStatus, DeliverySummary};
use topcoat::{
    Result,
    context::Cx,
    view::{View, class, component, view},
};

/// A delivery, and the changes an administrator may make to it now.
#[derive(Clone, Debug)]
pub struct DeliveryRow<'a> {
    /// The delivery.
    pub delivery: &'a DeliverySummary,
    /// Attempting it again, while it may be.
    pub retry: Option<Action>,
    /// Cancelling it, while it may be.
    pub cancel: Option<Action>,
}

/// A delivery's status, as a badge's tone and label.
const fn status_badge(status: DeliveryStatus) -> (&'static str, &'static str) {
    match status {
        DeliveryStatus::Pending => ("warning", "Pending"),
        DeliveryStatus::Succeeded => ("ok", "Delivered"),
        DeliveryStatus::Failed => ("danger", "Failed"),
        DeliveryStatus::Cancelled => ("neutral", "Cancelled"),
    }
}

/// The newest deliveries, at most `limit`, `rows`, with the `status` and on the
/// `channel` chosen, if any, and the form choosing others, which sends them to
/// `action` by `GET`.
#[component]
pub async fn delivery_list<'a>(
    cx: &Cx,
    action: &'a str,
    #[into]
    #[default]
    status: Option<DeliveryStatus>,
    #[into]
    #[default]
    channel: Option<&'a str>,
    rows: &'a [DeliveryRow<'a>],
    limit: u32,
) -> Result<impl View> {
    let full = u32::try_from(rows.len()).is_ok_and(|shown| shown >= limit);
    Ok(view! {
        page_head(
            title: "Deliveries",
            lead: "Emails and back-channel logouts, newest first. A delivery that failed holds back the ones ordered after it until it is retried or cancelled.".to_owned(),
        )
        <form method="get" action=(action) class="row search">
            <select name="status" aria-label="Status">
                <option value="" selected=(status.is_none())>"Every status"</option>
                for each in DeliveryStatus::ALL {
                    <option value=(each.as_str()) selected=(status == Some(each))>(status_badge(each).1)</option>
                }
            </select>
            <input name="channel" value=(channel) placeholder="Channel, e.g. email" aria-label="Channel">
            <button class="secondary">"Filter"</button>
        </form>
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No delivery."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>"destination"</th>
                                <th>"status"</th>
                                <th>"attempts"</th>
                                <th>"due or finished"</th>
                                <th>"last error"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            #[key(position)]
                            for (position, row) in rows.iter().enumerate() {
                                let delivery = row.delivery;
                                let (tone, label) = status_badge(delivery.status);
                                let subject = delivery.id.to_string();
                                <tr>
                                    <td>
                                        <code>(delivery.channel.as_str())</code> " " (delivery.destination.as_str())
                                        if let Some((key, ordinal)) = &delivery.ordering {
                                            <br><small class="muted">(format!("ordered {key} #{ordinal}"))</small>
                                        }
                                    </td>
                                    <td><span class=(class!("badge", tone))>(label)</span></td>
                                    <td>(delivery.attempts.to_string())</td>
                                    <td>moment(at: delivery.finished_at.unwrap_or(delivery.next_attempt_at))</td>
                                    <td><small>(delivery.last_error.as_deref().unwrap_or("—"))</small></td>
                                    <td class="right">
                                        <span class="row">
                                            if let Some(retry) = &row.retry {
                                                confirm(action: retry, change: Change::RetryDelivery, subject: subject.as_str())
                                            }
                                            if let Some(cancel) = &row.cancel {
                                                confirm(action: cancel, change: Change::CancelDelivery, subject: subject.as_str())
                                            }
                                        </span>
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
        if full {
            <p class="help">(format!("Only the newest {limit} are shown."))</p>
        }
    })
}
