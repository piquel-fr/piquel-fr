//! Who administers Piquel: the list, granting rights and revoking them.

use super::AdminApplication as App;
use piquel_common::{UserId, admin::GrantAdministrator};
use piquel_ui::{Action, AdministratorRow, Change};
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
    // The viewer is an active administrator, so revoking anyone else's rights
    // leaves one; the service refuses the last active administrator's anyway.
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let rows: Vec<_> = administrators
        .iter()
        .map(|administrator| AdministratorRow {
            administrator,
            account: App::account(cx, administrator.user_id),
            revoke: if administrator.user_id == admin.user_id {
                Err("You cannot change your own rights.")
            } else {
                Ok(Action {
                    href: href!(revoke, Administrator(administrator.user_id)).resolve(cx),
                    inline,
                })
            },
        })
        .collect();
    let (granting, rows) = (&href!(grant).resolve(cx), &rows);
    let page = view! { cx =>
        piquel_ui::administrator_list(rows: rows, grant: granting.as_str())
    };
    App::render(cx, StatusCode::OK, "Administrators", page).await
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
    let typed = refusal
        .as_ref()
        .map(|refused| refused.form.user_id.to_string());
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            change: Change::GrantAdministrator,
            back: back.as_str(),
            refusal: refusal.as_deref(),
            <label>
                "Account ID"
                <input name="user_id" required="" autocomplete="off" placeholder="From the account's page" value=(typed)>
            </label>
        )
    };
    App::render(cx, StatusCode::OK, "Grant rights", page).await
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
            change: Change::RevokeAdministrator,
            back: back.as_str(),
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, "Revoke rights", page).await
}
