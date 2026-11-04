//! Handles: the reserved list, the accounts holding a reserved handle, and the
//! released handles, with reserving, unreserving and releasing one.

use super::{AdminApplication as App, settings, users::Account};
use crate::{Reason, handles::HandlesError};
use piquel_common::{Handle, handle::RESERVED};
use piquel_ui::{Action, Change, HandlesPage, Query, ReleasedRow, ReservationRow, ReservedHolder};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, query_params, response::Response, route},
    view::view,
};

/// The query of [`release`] and [`unreserve`]: the handle they change.
#[query_params(error = bad_request)]
#[derive(Serialize)]
struct HandleQuery {
    /// The handle.
    handle: Handle,
}

impl Query for HandleQuery {}

/// The form reserving a handle.
#[derive(Clone, Deserialize)]
struct Reservation {
    /// The handle to reserve.
    handle: String,
    /// Who or what it is kept for.
    reason: String,
}

/// `/handles`: the reserved list, with the built-in names; the accounts whose
/// current handle is reserved, as `auth-service handle check` lists them, each
/// linking its change of handle; and the released handles, as `handle released`
/// lists them, each with the change releasing it.
#[route(GET "/handles")]
pub(super) async fn check(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let service = &App::of(cx).service;
    let problems = service.check_handles(&admin.operator).await?;
    let reservations = service.list_reserved_handles(&admin.operator).await?;
    let released = service.list_released_handles(&admin.operator).await?;
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let action = |page: String, handle: &Handle| -> Result<Action> {
        Ok(Action {
            href: HandleQuery {
                handle: handle.clone(),
            }
            .on(&page)?,
            inline,
        })
    };
    let holders: Vec<_> = problems
        .iter()
        .map(|problem| ReservedHolder {
            handle: problem.handle.as_str(),
            why: problem.error.to_string(),
            account: App::account(cx, problem.user_id),
            change: href!(settings::handle, Account(problem.user_id)).resolve(cx),
        })
        .collect();
    let reserved = reservations
        .iter()
        .map(|reservation| {
            Ok(ReservationRow {
                reservation,
                unreserve: action(href!(unreserve).resolve(cx), &reservation.handle)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let released = released
        .iter()
        .map(|released| {
            Ok(ReleasedRow {
                released,
                account: released.user_id.map(|user| App::account(cx, user)),
                release: action(href!(release).resolve(cx), &released.handle)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let reserving = href!(reserve).resolve(cx);
    let page = HandlesPage {
        reserved: &reserved,
        built_in: RESERVED,
        reserve: &reserving,
        holders: &holders,
        released: &released,
    };
    let view = view! { cx => piquel_ui::handle_list(page: page) };
    App::render(cx, StatusCode::OK, "Handles", view).await
}

/// `/handles/reserve`: reserves a handle, saying who or what it is kept for.
#[route([GET, POST] "/handles/reserve")]
pub(super) async fn reserve(cx: &Cx, form: Option<Form<Reservation>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let back = href!(check).resolve(cx);
    let refused = App::submit(cx, form, back.clone(), |input: Reservation| async move {
        let handle = Handle::parse(input.handle.trim()).map_err(HandlesError::from)?;
        let reason = Reason::parse(input.reason)?;
        service
            .reserve_handle(&admin.operator, handle, reason)
            .await
    })
    .await?;
    let (typed, reason) = refused.as_ref().map_or(("", ""), |refused| {
        (refused.form.handle.as_str(), refused.form.reason.as_str())
    });
    let refusal = refused.as_deref();
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::ReserveHandle,
            back: back.as_str(),
            refusal: refusal,
            reason: reason,
            <label>
                "Handle"
                <input name="handle" required="" maxlength="32" autocomplete="off" value=(typed) autofocus="">
            </label>
        )
    };
    App::render(cx, StatusCode::OK, Change::ReserveHandle.title(), page).await
}

/// `/handles/unreserve?handle=…`: removes a handle from the reserved list.
#[route([GET, POST] "/handles/unreserve")]
pub(super) async fn unreserve(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    App::handle_change(cx, form, Change::UnreserveHandle).await
}

/// `/handles/release?handle=…`: deletes a released handle, or a purged account's
/// last one, so anyone may claim it again.
#[route([GET, POST] "/handles/release")]
pub(super) async fn release(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    App::handle_change(cx, form, Change::ReleaseHandle).await
}

impl App {
    /// The page of `change`, releasing or unreserving the handle its query names,
    /// which goes back to the handles page once made.
    async fn handle_change(
        cx: &Cx,
        form: Option<Form<IgnoredAny>>,
        change: Change,
    ) -> Result<Response> {
        let admin = Self::admin(cx).await?;
        Self::confirm(cx, admin)?;
        let service = &Self::of(cx).service;
        let handle = query_params::<HandleQuery>(cx)?.handle.clone();
        let back = href!(check).resolve(cx);
        let shown = format!("@{handle}");
        let refusal = Self::submit(cx, form, back.clone(), |_| async move {
            if change == Change::ReleaseHandle {
                service.release_handle(&admin.operator, handle).await
            } else {
                service.unreserve_handle(&admin.operator, handle).await
            }
        })
        .await?;
        let page = view! { cx =>
            piquel_ui::dashboard_change(
                change: change,
                back: back.as_str(),
                refusal: refusal.as_deref(),
                <p><strong>(shown.as_str())</strong></p>
            )
        };
        Self::render(cx, StatusCode::OK, change.title(), page).await
    }
}
