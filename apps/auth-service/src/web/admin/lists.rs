//! The OIDC clients and domain events.

use super::{
    AdminApplication as App,
    origins::{self, Client, OriginQuery},
};
use piquel_common::{
    UserId,
    admin::{Event, EventSearch},
    events::Actor,
};
use piquel_ui::{AdminClientRow, EventRow, Pager, Query};
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
    /// The page wanted, counting from 1.
    page: Option<u32>,
}

/// `/clients`: every OIDC client and its settings, read-only but for the origins
/// approved for its pages to sign users in with passkeys.
#[route(GET "/clients")]
pub(super) async fn clients(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let service = &App::of(cx).service;
    let clients = service.list_clients(&admin.operator).await?;
    let approved = service.list_related_origins(&admin.operator).await?;
    let rows = clients
        .iter()
        .map(|client| {
            let page = || Client(client.id.clone());
            let origins = approved
                .iter()
                .filter(|approved| approved.client_id == client.id)
                .map(|approved| {
                    let query = OriginQuery {
                        origin: approved.origin.clone(),
                    };
                    let remove = query.on(&href!(origins::remove, page()).resolve(cx))?;
                    Ok((approved.origin.as_str(), remove))
                })
                .collect::<Result<_>>()?;
            let approve = if client.deleted_at.is_some() {
                Err("Deleted clients sign nobody in.")
            } else if client.trusted {
                Ok(href!(origins::approve, page()).resolve(cx))
            } else {
                Err("Only trusted clients' pages sign users in themselves.")
            };
            Ok(AdminClientRow {
                client,
                origins,
                approve,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let rows = &rows;
    let page = view! { cx => piquel_ui::client_list(rows: rows) };
    App::render(cx, StatusCode::OK, "Clients", page).await
}

/// `/events`: domain events, newest first, filtered by account and kind.
#[route(GET "/events")]
pub(super) async fn events(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let query = query_params::<EventsQuery>(cx)?;
    let filter = EventSearch {
        user: query.user,
        kind: query.kind.clone(),
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
    let rows = &App::event_rows(cx, &found.events);
    let (action, user, kind, pager) = (
        &action,
        filter.user.map(|user| user.to_string()),
        filter.kind.as_deref(),
        &pager,
    );
    let page = view! { cx =>
        piquel_ui::event_list(
            action: action.as_str(),
            user: user,
            kind: kind,
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
