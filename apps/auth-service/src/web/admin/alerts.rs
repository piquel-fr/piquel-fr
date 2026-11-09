//! The alerts administrators are shown, the ones that cleared, and posting an
//! update on one.

use super::AdminApplication as App;
use crate::{AdminError, Reason, admin::ALERTS_SHOWN};
use sourceorigin_common::{
    AlertId,
    alerts::{AlertStatus, AlertsShown},
};
use sourceorigin_ui::{Action, AlertCard, Change};
use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, path_param, response::Response, route},
    view::view,
};

path_param!(pub alert: AlertId else not_found);

/// The form of [`update`].
#[derive(Clone, Deserialize)]
pub(super) struct UpdateForm {
    /// Where the alert's handling stands.
    status: AlertStatus,
    /// What the administrator adds, if anything.
    #[serde(default)]
    note: String,
}

/// `/alerts`: the current alerts, newest first, each with posting an update on
/// it, and a link to the alerts that cleared.
#[route(GET "/alerts")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let alerts = App::of(cx)
        .service
        .alerts(&admin.operator, AlertsShown::Current)
        .await?;
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let cards: Vec<_> = alerts
        .iter()
        .map(|detail| AlertCard {
            detail,
            // A kind this release cannot read, it cannot update either.
            update: detail.alert.alert.is_some().then(|| Action {
                href: href!(update, Alert(detail.alert.id)).resolve(cx),
                inline,
            }),
        })
        .collect();
    let cleared = href!(previous).resolve(cx);
    let view = view! { sourceorigin_ui::alert_list(cards: &cards, previous: cleared.as_str()) };
    App::render(cx, StatusCode::OK, "Alerts", view).await
}

/// `/alerts/previous`: the alerts that cleared, the most recently cleared first,
/// with the updates posted on them.
#[route(GET "/alerts/previous")]
pub(super) async fn previous(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let alerts = App::of(cx)
        .service
        .alerts(&admin.operator, AlertsShown::Previous)
        .await?;
    // An alert that cleared takes no update.
    let cards: Vec<_> = alerts
        .iter()
        .map(|detail| AlertCard {
            detail,
            update: None,
        })
        .collect();
    let current = href!(list).resolve(cx);
    let view = view! {
        sourceorigin_ui::previous_alerts(cards: &cards, current: current.as_str(), limit: ALERTS_SHOWN)
    };
    App::render(cx, StatusCode::OK, "Previous alerts", view).await
}

/// `/alerts/{alert}/update`: posts an update on a current alert, saying where
/// its handling stands, with an optional note. An alert that is not current is
/// not found.
#[route([GET, POST] "/alerts/{alert}/update")]
pub(super) async fn update(cx: &Cx, form: Option<Form<UpdateForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Alert>(cx)?;
    let alerts = service
        .alerts(&admin.operator, AlertsShown::Current)
        .await?;
    // A kind this release cannot read, it cannot update either.
    let subject = alerts
        .iter()
        .find(|detail| detail.alert.id == id)
        .and_then(|detail| detail.alert.alert.as_ref())
        .ok_or(AdminError::AlertNotFound)?
        .subject();
    let back = href!(list).resolve(cx);
    let refused = App::submit(cx, form, back.clone(), |input: UpdateForm| async move {
        let note = match input.note.trim() {
            "" => None,
            note => Some(Reason::parse(note.to_owned())?),
        };
        service
            .update_alert(&admin.operator, id, input.status, note)
            .await?;
        App::forget_attention(cx);
        Ok::<_, AdminError>(())
    })
    .await?;
    let (status, note) = refused.as_ref().map_or((None, ""), |refused| {
        (Some(refused.form.status), refused.form.note.as_str())
    });
    let refusal = refused.as_deref();
    let page = view! {
        sourceorigin_ui::dashboard_change(
            change: Change::UpdateAlert,
            back: back.as_str(),
            refusal: refusal,
            <p><strong>(subject)</strong></p>
            sourceorigin_ui::alert_update_fields(status: status, note: note)
        )
    };
    App::render(cx, StatusCode::OK, Change::UpdateAlert.title(), page).await
}
