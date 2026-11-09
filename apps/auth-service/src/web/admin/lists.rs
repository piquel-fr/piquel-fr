//! Domain events.

use super::AdminApplication as App;
use sourceorigin_common::{
    UserId,
    admin::{Event, EventSearch},
    events::Actor,
};
use sourceorigin_ui::{Checkbox, EventRow, Pager, Query};
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, href, query_params, response::Response, route},
    view::view,
};

/// The query of [`events`]: [`EventSearch`]'s filters.
#[query_params(error = bad_request)]
struct EventsQuery {
    /// Only events concerning this account.
    user: Option<UserId>,
    /// Only events of this kind.
    kind: Option<String>,
    /// Whether administrators' views of accounts are listed too.
    views: Option<Checkbox>,
    /// The page wanted, counting from 1.
    page: Option<u32>,
}

/// `/events`: domain events, newest first, filtered by account and kind, with
/// administrators' views of accounts only when asked for.
#[route(GET "/events")]
pub(super) async fn events(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let query = query_params::<EventsQuery>(cx)?;
    let filter = EventSearch {
        user: query.user,
        kind: query.kind.clone(),
        views: query.views.is_some(),
        page: query.page,
    };
    let found = App::of(cx)
        .service
        .events(&admin.operator, filter.clone())
        .await?;
    let action = href!(events).resolve(cx);
    let pager = Pager::of(found.paging, |page| {
        EventSearch {
            page: Some(page),
            ..filter.clone()
        }
        .on(&action)
    })?;
    let toggle_views = EventSearch {
        views: !filter.views,
        page: None,
        ..filter.clone()
    }
    .on(&action)?;
    let rows = &App::event_rows(cx, &found.events);
    let (action, toggle_views, user, kind, pager) = (
        &action,
        &toggle_views,
        filter.user.map(|user| user.to_string()),
        filter.kind.as_deref(),
        &pager,
    );
    let page = view! { cx =>
        sourceorigin_ui::event_list(
            action: action.as_str(),
            user: user,
            kind: kind,
            views: filter.views,
            toggle_views: toggle_views.as_str(),
            rows: rows,
            pages: pager,
        )
    };
    App::render(cx, StatusCode::OK, "Events", page).await
}

impl App {
    /// The events `list` holds, as the dashboard lists them, each linking to the
    /// account it concerns, and to the account that caused it, when one did.
    pub(super) fn event_rows<'a>(cx: &Cx, list: &'a [Event]) -> Vec<EventRow<'a>> {
        list.iter()
            .map(|event| {
                let actor = match serde_json::from_value(event.actor.clone()) {
                    Ok(Actor::User { user_id, .. } | Actor::Admin { user_id, .. }) => {
                        Some(App::account(cx, user_id))
                    }
                    _ => None,
                };
                EventRow {
                    event,
                    account: event.subject.map(|subject| App::account(cx, subject)),
                    actor,
                }
            })
            .collect()
    }
}
