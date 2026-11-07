//! The alerts administrators are shown, and acknowledging one.

use super::{AdminApplication as App, ReasonForm};
use crate::{Reason, admin::ALERTS_SHOWN};
use piquel_common::{AlertId, alerts::AlertState};
use piquel_ui::{AlertRow, Change};
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, path_param, response::Response, route},
    view::view,
};

path_param!(pub alert: AlertId, error = not_found);

/// `/alerts`: the current alerts, then those that cleared, each with the change
/// acknowledging it while it is open.
#[route(GET "/alerts")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let alerts = App::of(cx).service.list_alerts(&admin.operator).await?;
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let rows: Vec<_> = alerts
        .iter()
        .map(|alert| AlertRow {
            alert,
            // A kind this release cannot read, it cannot acknowledge either.
            acknowledge: (alert.state() == AlertState::Open && alert.alert.is_some()).then(|| {
                piquel_ui::Action {
                    href: href!(acknowledge, Alert(alert.id)).resolve(cx),
                    inline,
                }
            }),
        })
        .collect();
    let view = view! { cx => piquel_ui::alert_list(rows: &rows, limit: ALERTS_SHOWN) };
    App::render(cx, StatusCode::OK, "Alerts", view).await
}

/// `/alerts/{alert}/acknowledge`: acknowledges an open alert, with a reason.
#[route([GET, POST] "/alerts/{alert}/acknowledge")]
pub(super) async fn acknowledge(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Alert>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), |input: ReasonForm| async move {
        service
            .acknowledge_alert(&admin.operator, id, Reason::parse(input.reason)?)
            .await
    })
    .await?;
    let reason = refusal.as_ref().map(|refused| refused.form.reason.as_str());
    let refusal = refusal.as_deref();
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::AcknowledgeAlert,
            back: back.as_str(),
            refusal: refusal,
            reason: reason,
        )
    };
    App::render(cx, StatusCode::OK, "Acknowledge", page).await
}
