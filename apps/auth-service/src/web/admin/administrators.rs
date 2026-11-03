//! Who administers Piquel: the list, granting rights and revoking them.

use super::AdminApplication as App;
use crate::AdminError;
use piquel_common::{UserId, admin::UserSearch};
use piquel_ui::{Action, AdministratorRow, Change, Pager, Query, UserRow};
use serde::{Deserialize, de::IgnoredAny};
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

/// What [`grant`] takes: by `GET`, the search for the account, from its query;
/// by `POST`, the account to grant, from its form. One type, since the extractor
/// reads a `GET`'s query as its form.
#[derive(Clone, Deserialize)]
pub(super) struct GrantForm {
    /// The account to grant rights, which the button posts.
    user_id: Option<UserId>,
    /// What to search for.
    #[serde(default)]
    q: String,
    /// The page wanted, counting from 1.
    page: Option<u32>,
}

/// `/administrators/grant`: finds the account, by handle, name, email or ID, then
/// makes it an administrator.
#[route([GET, POST] "/administrators/grant")]
pub(super) async fn grant(cx: &Cx, form: Option<Form<GrantForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let back = href!(list).resolve(cx);
    let (q, page) = form
        .as_ref()
        .map(|Form(form)| (form.q.clone(), form.page))
        .unwrap_or_default();
    let refusal = App::submit(cx, form, back.clone(), |input: GrantForm| async move {
        let user_id = input.user_id.ok_or(AdminError::UserNotFound)?;
        service.grant_administrator(&admin.operator, user_id).await
    })
    .await?;
    let found = service.search_users(&admin.operator, &q, page).await?;
    let administrators: Vec<_> = service
        .list_administrators(&admin.operator)
        .await?
        .into_iter()
        .map(|administrator| administrator.user_id)
        .collect();
    let action = href!(grant).resolve(cx);
    let rows: Vec<_> = found
        .users
        .iter()
        .map(|user| UserRow {
            user,
            administrator: administrators.contains(&user.id),
            href: App::account(cx, user.id),
        })
        .collect();
    let pager = Pager::of(found.paging, |page| {
        UserSearch {
            q: q.clone(),
            page: Some(page),
        }
        .on(&action)
    })?;
    let (q, rows, pager, refusal) = (&q, &rows, &pager, refusal.as_deref());
    let page = view! { cx =>
        piquel_ui::grant_search(
            action: action.as_str(),
            q: q.as_str(),
            rows: rows,
            pages: pager,
            back: back.as_str(),
            refusal: refusal,
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
