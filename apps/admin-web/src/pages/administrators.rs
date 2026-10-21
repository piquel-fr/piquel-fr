use super::{change_form, heading, refused_action, time, users};
use crate::admin::Admin;
use piquel_admin_api::AdminClient;
use piquel_admin_api::GrantAdministrator;
use piquel_common::UserId;
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{content::Form, href, page, path_param},
    view::{View, view},
};

path_param!(pub administrator: UserId, error = not_found);

/// `/administrators`: who administers piquel.fr.
#[page("/administrators")]
pub async fn list(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    let administrators = admin.read(AdminClient::administrators).await?;
    let last = administrators.len() <= 1;
    Ok(view! {
        <div class="row between">
            heading(title: "Administrators")
            <a class="button" href=(href!(grant))>"Grant rights"</a>
        </div>
        <section class="card">
            <table>
                <thead>
                    <tr><th>"Username"</th><th>"Since"</th><th></th></tr>
                </thead>
                <tbody>
                    for administrator in administrators {
                        <tr>
                            <td>
                                <a href=(href!(users::detail, users::Account(administrator.user_id)))>
                                    (administrator.username)
                                </a>
                            </td>
                            <td>time(at: administrator.granted_at)</td>
                            <td>
                                if admin.id() == Some(administrator.user_id) {
                                    refused_action(label: "Revoke", reason: "You cannot change your own rights.")
                                } else if last {
                                    refused_action(label: "Revoke", reason: "The last administrator's rights stay.")
                                } else {
                                    <a href=(href!(revoke, Administrator(administrator.user_id)))>"Revoke"</a>
                                }
                            </td>
                        </tr>
                    }
                </tbody>
            </table>
        </section>
    })
}

/// `/administrators/grant`: makes an active account an administrator.
#[page([GET, POST] "/administrators/grant")]
pub async fn grant(cx: &Cx, form: Option<Form<GrantAdministrator>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, input| async move {
            api.grant_administrator(token, &input).await
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Grant administrator rights",
            description: "The account can use this dashboard and every admin operation. The admin API cannot change it afterwards, until its rights are revoked.",
            button: "Grant",
            back: back,
            refusal: refusal,
            <label>
                "Account ID"
                <input name="user_id" required="" autocomplete="off" placeholder="From the account's page">
            </label>
        )
    })
}

/// `/administrators/{administrator}/revoke`: removes another administrator's rights.
#[page([GET, POST] "/administrators/{administrator}/revoke")]
pub async fn revoke(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<Administrator>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| {
            api.revoke_administrator(token, id)
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Revoke administrator rights",
            description: "The account keeps its sessions, but can no longer use this dashboard.",
            button: "Revoke",
            back: back,
            refusal: refusal,
            danger: true,
        )
    })
}
