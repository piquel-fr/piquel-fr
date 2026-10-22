use super::{heading, time, users};
use crate::admin::Admin;
use piquel_admin_api::{Event, EventSearch};
use piquel_common::{EventId, UserId};
use serde_json::Value;
use topcoat::{
    Result,
    context::Cx,
    router::{href, page, query_params},
    view::{View, component, view},
};

/// The query of [`list`]: [`EventSearch`]'s filters.
#[query_params(error = bad_request)]
struct EventsQuery {
    /// Only events concerning this account.
    user: Option<UserId>,
    /// Only events of this kind.
    kind: Option<String>,
    /// Where the page starts.
    before: Option<EventId>,
}

/// `/events`: domain events, newest first, filtered by account and kind.
#[page("/events")]
pub async fn list(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    let query = query_params::<EventsQuery>(cx)?;
    let search = EventSearch {
        user: query.user,
        kind: query.kind.clone(),
        before: query.before,
    };
    let page = admin.read(|api, token| api.events(token, &search)).await?;
    let next = page.next.map(|before| {
        href!(list).query(EventSearch {
            before: Some(before),
            ..search.clone()
        })
    });
    Ok(view! {
        heading(title: "Events")
        <form method="get" class="row search">
            <input name="user" value=(search.user.map(|user| user.to_string())) placeholder="Account ID" aria-label="Account ID">
            <input name="kind" value=(search.kind.clone()) placeholder="Kind, e.g. session_revoked" aria-label="Event kind">
            <button>"Filter"</button>
        </form>
        <section class="card">
            event_rows(events: page.events)
        </section>
        if let Some(next) = next {
            <a class="button secondary" href=(next)>"Older events"</a>
        }
    })
}

/// A table of events, each linking to the account it concerns.
#[component]
pub async fn event_rows(events: Vec<Event>) -> Result<impl View> {
    Ok(view! {
        if events.is_empty() {
            <p class="empty">"No event."</p>
        } else {
            <table>
                <thead>
                    <tr><th>"When"</th><th>"Kind"</th><th>"Account"</th><th>"By"</th><th>"Details"</th><th>"Trace"</th></tr>
                </thead>
                <tbody>
                    for event in events {
                        let actor = event.actor.get("type").and_then(Value::as_str).unwrap_or("unknown").to_owned();
                        <tr>
                            <td>time(at: event.occurred_at)</td>
                            <td><code>(event.event.get("kind").and_then(Value::as_str).unwrap_or("unknown").to_owned())</code></td>
                            <td>
                                if let Some(subject) = event.subject {
                                    <a href=(href!(users::detail, users::Account(subject)))>"Account"</a>
                                }
                            </td>
                            <td>(actor)</td>
                            <td><code class="details">(event.event.get("data").map(Value::to_string).unwrap_or_default())</code></td>
                            <td>
                                if let Some(trace_id) = event.trace_id {
                                    <code title="Search Grafana for this trace ID">(trace_id.to_string())</code>
                                }
                            </td>
                        </tr>
                    }
                </tbody>
            </table>
        }
    })
}
