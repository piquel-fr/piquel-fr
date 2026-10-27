//! The OIDC clients and domain events.

use super::AdminApplication as App;
use piquel_admin_api::{Event, EventSearch};
use piquel_common::{EventId, UserId};
use piquel_ui::{EventRow, Query};
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
    /// Where the page starts.
    before: Option<EventId>,
}

/// `/clients`: every OIDC client and its settings, read-only.
#[route(GET "/clients")]
pub(super) async fn clients(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let clients = &App::of(cx).service.list_clients(&admin.operator).await?;
    let page = view! { cx => piquel_ui::client_list(clients: clients) };
    App::render(cx, StatusCode::OK, page).await
}

/// `/events`: domain events, newest first, filtered by account and kind.
#[route(GET "/events")]
pub(super) async fn events(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let query = query_params::<EventsQuery>(cx)?;
    let filter = EventSearch {
        user: query.user,
        kind: query.kind.clone(),
        before: query.before,
    };
    let found = App::of(cx)
        .service
        .events(&admin.operator, filter.clone())
        .await?;
    let action = href!(events).resolve(cx);
    let older = match found.next {
        Some(before) => Some(
            EventSearch {
                before: Some(before),
                ..filter.clone()
            }
            .on(&action)?,
        ),
        None => None,
    };
    let rows = &App::event_rows(cx, &found.events);
    let (action, user, kind) = (
        &action,
        filter.user.map(|user| user.to_string()),
        filter.kind.as_deref(),
    );
    let page = view! { cx =>
        piquel_ui::event_list(
            action: action.as_str(),
            user: user,
            kind: kind,
            rows: rows,
            older: older,
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

impl App {
    /// The events `list` holds, as the dashboard lists them, each linking to the account it
    /// concerns.
    pub(super) fn event_rows<'a>(cx: &Cx, list: &'a [Event]) -> Vec<EventRow<'a>> {
        list.iter()
            .map(|event| EventRow {
                event,
                account: event.subject.map(|subject| App::account(cx, subject)),
            })
            .collect()
    }
}
