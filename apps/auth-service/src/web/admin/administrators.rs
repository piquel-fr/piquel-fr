//! Who administers Piquel: the list, granting rights and revoking them.

use super::AdminApplication as App;
use piquel_common::{UserId, admin::GrantAdministrator};
use piquel_ui::AdministratorRow;
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, path_param, response::Response, route},
    view::view,
};

path_param!(pub administrator: UserId, error = not_found);

/// `/administrators`: who administers Piquel.
#[route(GET "/administrators")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let administrators = App::of(cx)
        .service
        .list_administrators(&admin.operator)
        .await?;
    let last = administrators.len() <= 1;
    let rows: Vec<_> = administrators
        .iter()
        .map(|administrator| AdministratorRow {
            administrator,
            account: App::account(cx, administrator.user_id),
            revoke: if administrator.user_id == admin.user_id {
                Err("You cannot change your own rights.")
            } else if last {
                Err("The last administrator's rights stay.")
            } else {
                Ok(href!(revoke, Administrator(administrator.user_id)).resolve(cx))
            },
        })
        .collect();
    let (granting, rows) = (&href!(grant).resolve(cx), &rows);
    let page = view! { cx =>
        piquel_ui::administrator_list(rows: rows, grant: granting.as_str())
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/administrators/grant`: makes an active account an administrator.
#[route([GET, POST] "/administrators/grant")]
pub(super) async fn grant(cx: &Cx, form: Option<Form<GrantAdministrator>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let back = href!(list).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), |input: GrantAdministrator| {
        service.grant_administrator(&admin.operator, input.user_id)
    })
    .await?;
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Grant administrator rights",
            description: "The account can use this dashboard and every admin operation. The dashboard cannot change it afterwards, until its rights are revoked.",
            button: "Grant",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            <label>
                "Account ID"
                <input name="user_id" required="" autocomplete="off" placeholder="From the account's page">
            </label>
        )
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/administrators/{administrator}/revoke`: removes another administrator's
/// rights.
#[route([GET, POST] "/administrators/{administrator}/revoke")]
pub(super) async fn revoke(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Administrator>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), |_| {
        service.revoke_administrator(&admin.operator, id)
    })
    .await?;
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Revoke administrator rights",
            description: "The account keeps its sessions, but can no longer use this dashboard.",
            button: "Revoke",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            danger: true,
        )
    };
    App::render(cx, StatusCode::OK, page).await
}
