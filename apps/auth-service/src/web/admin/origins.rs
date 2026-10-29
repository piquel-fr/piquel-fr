//! The origins approved for clients' pages to sign users in with passkeys:
//! approving one and removing one, as `client origin add|remove` do. The clients
//! page lists them.

use super::{AdminApplication as App, Refusal, lists};
use crate::{clients::MAX_RELATED_ORIGIN_DOMAINS, security::ApiError};
use piquel_common::{ClientId, admin::ApproveOrigin, clients::RelatedOrigin};
use piquel_ui::Query;
use serde::{Serialize, de::IgnoredAny};
use topcoat::{
    Result,
    context::Cx,
    router::{
        StatusCode, content::Form, href, path_param, query_params, response::Response, route,
    },
    view::view,
};

path_param!(pub client: ClientId, error = not_found);

/// The query of [`remove`]: the approved origin to remove.
#[query_params(error = bad_request)]
#[derive(Serialize)]
pub(super) struct OriginQuery {
    /// The origin, as approved.
    pub(super) origin: RelatedOrigin,
}

impl Query for OriginQuery {}

/// `/clients/{client}/origins/approve`: lets a trusted client's pages on an origin
/// sign users in with their passkeys, without sending them to auth's pages.
#[route([GET, POST] "/clients/{client}/origins/approve")]
pub(super) async fn approve(cx: &Cx, form: Option<Form<ApproveOrigin>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let app = App::of(cx);
    let id = path_param::<Client>(cx)?.clone();
    let back = href!(lists::clients).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), async |input: ApproveOrigin| {
        let origin: RelatedOrigin = input
            .origin
            .trim()
            .parse()
            .map_err(|error| Refusal::Form(ApiError::bad_request(format!("{error}"))))?;
        app.service
            .approve_related_origin(&admin.operator, &id, &origin, app.auth.host())
            .await
            .map_err(Refusal::from)
    })
    .await?;
    let typed = refusal.as_ref().map(|refused| refused.form.origin.clone());
    let description = format!(
        "Pages of {id} on this origin sign users in with their Piquel passkeys. It must be the origin of one of the client's redirect URIs, and browsers honour approved origins on at most {MAX_RELATED_ORIGIN_DOMAINS} domains, across every client."
    );
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Approve an origin",
            description: description.as_str(),
            button: "Approve",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            <label>
                "Origin"
                <input name="origin" required="" autocomplete="off" placeholder="https://notes.example" value=(typed)>
            </label>
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/clients/{client}/origins/remove?origin=…`: stops a client's pages on an
/// origin from signing users in. Auth refuses their sign-ins at once; browsers
/// drop the origin from their copy of the list within five minutes.
#[route([GET, POST] "/clients/{client}/origins/remove")]
pub(super) async fn remove(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = path_param::<Client>(cx)?.clone();
    let origin = query_params::<OriginQuery>(cx)?.origin.clone();
    let back = href!(lists::clients).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), |_| {
        service.remove_related_origin(&admin.operator, &id, &origin)
    })
    .await?;
    let description = format!(
        "Pages of {id} on {origin} stop signing users in, and send them to Piquel's pages instead. Users stay signed in."
    );
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Remove an origin",
            description: description.as_str(),
            button: "Remove",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            danger: true,
        )
    };
    App::render(cx, StatusCode::OK, page).await
}
