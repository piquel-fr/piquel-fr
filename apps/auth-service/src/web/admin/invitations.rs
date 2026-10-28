//! Signup invitations, while signup requires one.

use super::AdminApplication as App;
use crate::{AdminError, InviteExpiry};
use chrono::Utc;
use piquel_admin_api::CreateInvitation;
use piquel_common::TokenId;
use piquel_ui::InvitationRow;
use serde::de::IgnoredAny;
use topcoat::{
    Result,
    context::Cx,
    router::{
        StatusCode, content::Form, error::not_found, href, path_param, response::Response, route,
    },
    view::view,
};

path_param!(pub invitation: TokenId, error = not_found);

impl App {
    /// Requires signup to need invitations, without which there are none to
    /// manage.
    fn invitations(cx: &Cx) -> Result<()> {
        if Self::of(cx).invitations {
            Ok(())
        } else {
            Err(not_found().into())
        }
    }
}

/// `/invitations`: signup invitations, or that signup is open.
#[route(GET "/invitations")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let invitations = if app.invitations {
        Some(app.service.list_invitations(&admin.operator).await?)
    } else {
        None
    };
    let rows: Option<Vec<_>> = invitations.as_ref().map(|invitations| {
        invitations
            .iter()
            .map(|invitation| InvitationRow {
                invitation,
                revoke: (invitation.redeemed_at.is_none() && invitation.revoked_at.is_none())
                    .then(|| href!(revoke, Invitation(invitation.id)).resolve(cx)),
            })
            .collect()
    });
    let (creating, rows) = (&href!(create).resolve(cx), rows.as_deref());
    let page = view! { cx =>
        piquel_ui::invitation_list(rows: rows, create: creating.as_str(), now: Utc::now())
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/invitations/new`: creates an invitation and shows its link, once.
#[route([GET, POST] "/invitations/new")]
pub(super) async fn create(cx: &Cx, form: Option<Form<CreateInvitation>>) -> Result<Response> {
    App::invitations(cx)?;
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let app = App::of(cx);
    let back = href!(list).resolve(cx);
    let created = App::change(cx, form, |input: CreateInvitation| async move {
        let expires_in = match input.expires_in.filter(|value| !value.trim().is_empty()) {
            Some(expires_in) => expires_in
                .trim()
                .parse::<InviteExpiry>()
                .map_err(AdminError::from)?,
            None => InviteExpiry::default(),
        };
        app.service
            .create_invitation(&admin.operator, &app.auth, expires_in)
            .await
    })
    .await?;
    let back = &back;
    let (created, refused) = match created {
        Some(Ok(created)) => (Some(created), None),
        Some(Err(refused)) => (None, Some(refused)),
        None => (None, None),
    };
    let (created, refused) = (&created, refused.as_deref());
    let page = view! { cx =>
        match created {
            Some(created) => {
                piquel_ui::invitation_created(
                    link: created.url.as_str(),
                    expires_at: created.expires_at,
                    back: back.as_str(),
                )
            },
            None => {
                piquel_ui::dashboard_change(
                    title: "Invite someone",
                    description: "Creates a single-use signup link.",
                    button: "Create link",
                    back: back.as_str(),
                    refusal: refused,
                    <label>
                        "Valid for"
                        <input name="expires_in" placeholder="7d" pattern="[0-9]+[hd]">
                        <small>"Hours or days, e.g. 24h or 7d; seven days when empty."</small>
                    </label>
                )
            },
        }
    };
    App::render(cx, StatusCode::OK, page).await
}

/// `/invitations/{invitation}/revoke`: revokes an unredeemed invitation.
#[route([GET, POST] "/invitations/{invitation}/revoke")]
pub(super) async fn revoke(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<Response> {
    App::invitations(cx)?;
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Invitation>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), |_| {
        service.revoke_invitation(&admin.operator, id)
    })
    .await?;
    let page = view! { cx =>
        piquel_ui::dashboard_change(
            title: "Revoke this invitation",
            description: "Its link stops working.",
            button: "Revoke",
            back: back.as_str(),
            refusal: refusal.as_deref(),
            danger: true,
        )
    };
    App::render(cx, StatusCode::OK, page).await
}
