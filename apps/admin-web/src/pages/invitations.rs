use super::{change_form, heading, time};
use crate::admin::Admin;
use piquel_admin_api::{CreateInvitation, Invitation};
use piquel_common::TokenId;
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, page, path_param},
    view::{View, component, view},
};

path_param!(pub invitation_id: TokenId, error = not_found);

/// `/invitations`: signup invitations, while signup requires one.
#[page("/invitations")]
pub async fn list(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    // Auth serves no invitation routes while signup is open.
    let invitations = admin
        .read(|api, token| async move {
            match api.invitations(token).await {
                Err(error) if error.status() == Some(StatusCode::NOT_FOUND) => Ok(None),
                invitations => invitations.map(Some),
            }
        })
        .await?;
    Ok(view! {
        match invitations {
            None => {
                heading(title: "Invitations")
                <section class="card">
                    <p>"Signup is open: anyone can register without an invitation."</p>
                </section>
            },
            Some(invitations) => {
                <div class="row between">
                    heading(title: "Invitations")
                    <a class="button" href=(href!(create))>"Invite"</a>
                </div>
                <section class="card">
                    if invitations.is_empty() {
                        <p class="empty">"No invitation yet."</p>
                    } else {
                        <table>
                            <thead>
                                <tr><th>"Created"</th><th>"Expires"</th><th>"State"</th><th></th></tr>
                            </thead>
                            <tbody>
                                for invitation in invitations {
                                    <tr>
                                        <td>time(at: invitation.created_at)</td>
                                        <td>time(at: invitation.expires_at)</td>
                                        <td>state(invitation: &invitation)</td>
                                        <td>
                                            if invitation.redeemed_at.is_none() && invitation.revoked_at.is_none() {
                                                <a href=(href!(revoke, InvitationId(invitation.id)))>"Revoke"</a>
                                            }
                                        </td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    }
                </section>
            },
        }
    })
}

/// Whether an invitation can still be used.
#[component]
async fn state(invitation: &Invitation) -> Result<impl View> {
    let state = if invitation.redeemed_at.is_some() {
        "Redeemed"
    } else if invitation.revoked_at.is_some() {
        "Revoked"
    } else if invitation.expires_at <= chrono::Utc::now() {
        "Expired"
    } else {
        "Open"
    };
    Ok(view! { (state) })
}

/// `/invitations/new`: creates an invitation and shows its link, once.
#[page([GET, POST] "/invitations/new")]
pub async fn create(cx: &Cx, form: Option<Form<CreateInvitation>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let back = href!(list).resolve(cx);
    let created = admin
        .change(cx, form, |api, token, input| async move {
            api.create_invitation(token, &input).await
        })
        .await?;
    Ok(view! {
        match created {
            Some(Ok(created)) => {
                <section class="card narrow stack">
                    <h1>"Invitation created"</h1>
                    <p>"Send this link to the person you invite. It is shown only now, and works once."</p>
                    <input readonly="" value=(created.url.to_string()) aria-label="Signup link">
                    <p class="muted">"Expires " time(at: created.expires_at)</p>
                    <a class="button secondary" href=(back)>"Done"</a>
                </section>
            },
            refused => {
                change_form(
                    title: "Invite someone",
                    description: "Creates a single-use signup link.",
                    button: "Create link",
                    back: back,
                    refusal: refused.and_then(Result::err),
                    <label>
                        "Valid for"
                        <input name="expires_in" placeholder="7d" pattern="[0-9]+[hd]">
                        <small>"Hours or days, e.g. 24h or 7d; seven days when empty."</small>
                    </label>
                )
            },
        }
    })
}

/// `/invitations/{invitation_id}/revoke`: revokes an unredeemed invitation.
#[page([GET, POST] "/invitations/{invitation_id}/revoke")]
pub async fn revoke(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = *path_param::<InvitationId>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| {
            api.revoke_invitation(token, id)
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Revoke this invitation",
            description: "Its link stops working.",
            button: "Revoke",
            back: back,
            refusal: refusal,
            danger: true,
        )
    })
}
