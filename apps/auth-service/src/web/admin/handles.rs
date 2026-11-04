//! Handles: the accounts whose handle is reserved, and releasing a handle for
//! anyone to claim.

use super::{AdminApplication as App, settings, users::Account};
use crate::handles::HandlesError;
use piquel_common::Handle;
use piquel_ui::{Change, ReservedHandle};
use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, response::Response, route},
    view::view,
};

/// The form releasing a handle.
#[derive(Clone, Deserialize)]
struct Release {
    /// The released handle.
    handle: String,
}

/// `/handles`: the accounts whose current handle is reserved, as `auth-service
/// handle check` lists them, each linking its rename.
#[route(GET "/handles")]
pub(super) async fn check(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let problems = App::of(cx).service.check_handles(&admin.operator).await?;
    let rows: Vec<_> = problems
        .iter()
        .map(|problem| ReservedHandle {
            handle: problem.handle.as_str(),
            why: problem.error.to_string(),
            account: App::account(cx, problem.user_id),
            rename: href!(settings::handle, Account(problem.user_id)).resolve(cx),
        })
        .collect();
    let (rows, releasing) = (&rows, &href!(release).resolve(cx));
    let page = view! { cx => piquel_ui::handle_list(rows: rows, release: releasing.as_str()) };
    App::render(cx, StatusCode::OK, "Handles", page).await
}

/// `/handles/release`: deletes a released handle, or a purged account's last
/// one, so anyone may claim it again.
#[route([GET, POST] "/handles/release")]
pub(super) async fn release(cx: &Cx, form: Option<Form<Release>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let back = href!(check).resolve(cx);
    let refused = App::submit(cx, form, back.clone(), |input: Release| async move {
        let handle = Handle::parse(input.handle.trim()).map_err(HandlesError::from)?;
        service.release_handle(&admin.operator, handle).await
    })
    .await?;
    let typed = refused
        .as_ref()
        .map_or("", |refused| refused.form.handle.as_str());
    let (back, refusal) = (&back, refused.as_deref());
    let page = view! { cx =>
        piquel_ui::handle_release(back: back.as_str(), refused: refusal, typed: typed)
    };
    App::render(cx, StatusCode::OK, Change::ReleaseHandle.title(), page).await
}
