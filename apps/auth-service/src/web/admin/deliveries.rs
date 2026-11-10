//! The outbound delivery queue: listing deliveries, retrying and cancelling one.

use super::{AdminApplication as App, ReasonForm, Refused};
use sourceorigin_common::{DeliveryId, admin::DeliveryStatus};
use sourceorigin_ui::{Action, Change, DeliveryRow, Target};
use topcoat::{
    Result,
    context::Cx,
    router::{
        StatusCode, content::Form, error::bad_request, href, path_param, query_params,
        response::Response, route,
    },
    view::view,
};

path_param!(pub delivery: DeliveryId, error = not_found);

/// How many deliveries the list shows, as `auth-service deliveries list` does
/// by default.
const LIMIT: u32 = 100;

/// The query of [`list`], whose form sends each filter empty when unused.
#[query_params(error = bad_request)]
struct DeliveriesQuery {
    /// Only deliveries with this status.
    status: Option<String>,
    /// Only deliveries on this channel.
    channel: Option<String>,
}

/// `/deliveries`: the newest deliveries, with the status and on the channel the
/// query names, if any, each with the change retrying or cancelling it while it
/// may be.
#[route(GET "/deliveries")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let query = query_params::<DeliveriesQuery>(cx)?;
    let status = match query.status.as_deref().filter(|status| !status.is_empty()) {
        Some(status) => Some(
            status
                .parse::<DeliveryStatus>()
                .map_err(|error| bad_request(error.to_string()))?,
        ),
        None => None,
    };
    let channel = query
        .channel
        .as_deref()
        .map(str::trim)
        .filter(|channel| !channel.is_empty());
    let deliveries = App::of(cx)
        .service
        .list_deliveries(&admin.operator, status, channel, LIMIT)
        .await?;
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let action = |href: String| Action { href, inline };
    let rows: Vec<_> = deliveries
        .iter()
        .map(|delivery| DeliveryRow {
            delivery,
            retry: delivery
                .retryable()
                .then(|| action(href!(retry, Delivery(delivery.id)).resolve(cx))),
            cancel: delivery
                .cancellable()
                .then(|| action(href!(cancel, Delivery(delivery.id)).resolve(cx))),
        })
        .collect();
    let (page, rows) = (&href!(list).resolve(cx), &rows);
    let view = view! { cx =>
        sourceorigin_ui::delivery_list(
            action: page.as_str(),
            status: status,
            channel: channel,
            rows: rows,
            limit: LIMIT,
        )
    };
    App::render(cx, StatusCode::OK, "Deliveries", view).await
}

/// `/deliveries/{delivery}/retry`: attempts a failed delivery, or a cancelled
/// unordered one, again now.
#[route([GET, POST] "/deliveries/{delivery}/retry")]
pub(super) async fn retry(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    App::delivery_change(cx, form, Change::RetryDelivery).await
}

/// `/deliveries/{delivery}/cancel`: cancels a pending or failed delivery, which
/// unblocks the deliveries ordered after it.
#[route([GET, POST] "/deliveries/{delivery}/cancel")]
pub(super) async fn cancel(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    App::delivery_change(cx, form, Change::CancelDelivery).await
}

impl App {
    /// The page of `change`, retrying or cancelling the delivery its path names,
    /// which goes back to the list once made.
    async fn delivery_change(
        cx: &Cx,
        form: Option<Form<ReasonForm>>,
        change: Change,
    ) -> Result<Response> {
        let admin = Self::admin(cx).await?;
        Self::confirm(cx, admin)?;
        let service = &Self::of(cx).service;
        let id = *path_param::<Delivery>(cx)?;
        let back = href!(list).resolve(cx);
        let refusal = Self::submit_reason(cx, form, back.clone(), async |reason| {
            if change == Change::CancelDelivery {
                service.cancel_delivery(&admin.operator, id, reason).await
            } else {
                service.retry_delivery(&admin.operator, id, reason).await
            }
        })
        .await?;
        let id = id.to_string();
        let target = Target {
            name: "Delivery",
            id: Some(&id),
        };
        let reason = refusal.as_ref().map(Refused::reason);
        let refusal = refusal.as_deref();
        let page = view! { cx =>
            sourceorigin_ui::dashboard_change(
                change: change,
                target: target,
                back: back.as_str(),
                refusal: refusal,
                reason: reason,
            )
        };
        Self::render(cx, StatusCode::OK, change.title(), page).await
    }
}
