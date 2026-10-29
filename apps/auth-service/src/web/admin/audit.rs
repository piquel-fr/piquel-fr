//! The audit chain's state, and the checkpoints it may be pruned through.

use super::AdminApplication as App;
use crate::{AdminError, AuditKeys};
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, href, query_params, response::Response, route},
    view::view,
};

/// The query of [`verify`].
#[query_params(error = bad_request)]
struct AuditQuery {
    /// Where the checkpoints start: after this position, or after the anchor.
    after: Option<u64>,
}

/// `/audit`: the chain verified as `auth-service audit verify` does, and its
/// checkpoints, each with whether the chain may be pruned through it and the
/// command that would. Pruning itself needs the database owner, so the page
/// changes nothing.
#[route(GET "/audit")]
pub(super) async fn verify(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let query = query_params::<AuditQuery>(cx)?;
    let keys = AuditKeys::for_server(&app.auth, &app.audit_key).map_err(AdminError::from)?;
    let page = &app
        .service
        .audit_page(&admin.operator, &keys, query.after)
        .await?;
    let later = page
        .next
        .map(|after| format!("{}?after={after}", href!(verify).resolve(cx)));
    let view = view! { cx => piquel_ui::audit_page(page: page, later: later) };
    App::render(cx, StatusCode::OK, view).await
}
