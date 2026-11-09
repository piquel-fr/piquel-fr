//! The audit chain's state, and the checkpoints it may be pruned through.

use super::AdminApplication as App;
use crate::{AdminError, AuditKeys};
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, query_params, response::Response, route},
    view::view,
};

/// The query of [`verify`].
#[query_params(error = bad_request)]
struct AuditQuery {
    /// Where the checkpoints start: after this position, or after the anchor.
    after: Option<u64>,
}

/// `/audit`: the chain as stored and as its newest recorded verification found
/// it, and its checkpoints, each with whether the chain may be pruned through it
/// and the command that would. Showing it verifies nothing; posting its form
/// verifies the whole chain, as `auth-service audit verify` does, and comes back
/// to the page, which then shows that verification. Pruning itself needs the
/// database owner, so the page never prunes.
#[route([GET, POST] "/audit")]
pub(super) async fn verify(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let query = query_params::<AuditQuery>(cx)?;
    let keys = AuditKeys::for_server(&app.auth, &app.audit_key).map_err(AdminError::from)?;
    let here = href!(verify).resolve(cx);
    let refusal = App::submit(cx, form, here.clone(), |_| async {
        app.service
            .verify_audit_chain(&admin.operator, &keys)
            .await
            .map(drop)
    })
    .await?;
    let page = &app.service.audit_page(&admin.operator, query.after).await?;
    let later = page.next.map(|after| format!("{here}?after={after}"));
    let view = view! {
        sourceorigin_ui::audit_page(
            page: page,
            keys: keys.source,
            refusal: refusal.as_deref(),
            later: later,
        )
    };
    App::render(cx, StatusCode::OK, "Audit", view).await
}
