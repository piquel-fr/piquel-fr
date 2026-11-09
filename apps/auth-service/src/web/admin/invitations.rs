//! Signup invitations, while signup requires one.

use super::{AdminApplication as App, NoInput};
use crate::{AdminError, InviteExpiry};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sourceorigin_common::{
    TokenId,
    admin::{CreateInvitation, CreatedInvitation},
};
use sourceorigin_crypto::Secret;
use sourceorigin_ui::{Action, Change, InvitationRow, Target};
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
    /// manage. Pages check it once the administrator is signed in, so the
    /// dashboard says nothing of its configuration to anyone else.
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
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let rows: Option<Vec<_>> = invitations.as_ref().map(|invitations| {
        invitations
            .iter()
            .map(|invitation| InvitationRow {
                invitation,
                revoke: (invitation.redeemed_at.is_none() && invitation.revoked_at.is_none()).then(
                    || Action {
                        href: href!(revoke, Invitation(invitation.id)).resolve(cx),
                        inline,
                    },
                ),
            })
            .collect()
    });
    let (creating, rows) = (&href!(create).resolve(cx), rows.as_deref());
    let page = view! { cx =>
        sourceorigin_ui::invitation_list(rows: rows, create: creating.as_str(), now: Utc::now())
    };
    App::render(cx, StatusCode::OK, "Invitations", page).await
}

/// The form creating an invitation, as the dashboard shows it.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct InvitationForm {
    /// The invitation.
    #[serde(flatten)]
    pub(super) invitation: CreateInvitation,
    /// A random value of the form as shown: inviting two people in a row with
    /// the same validity is two changes, which the dashboard would otherwise
    /// take for one posted twice, while a double click on one form is still one.
    #[serde(default)]
    pub(super) shown: String,
}

/// `/invitations/new`: creates an invitation, then comes back here, which shows
/// its link once.
#[route([GET, POST] "/invitations/new")]
pub(super) async fn create(cx: &Cx, form: Option<Form<InvitationForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::invitations(cx)?;
    // The page showing a new link needs no confirmation: sending the browser to
    // confirm would lose the link.
    let revealed: Option<CreatedInvitation> = App::revealed(cx, admin);
    if revealed.is_none() {
        App::confirm(cx, admin)?;
    }
    let app = App::of(cx);
    let back = href!(list).resolve(cx);
    let created = App::change(cx, form, back.clone(), |input: InvitationForm| async move {
        let expires_in = match input
            .invitation
            .expires_in
            .filter(|value| !value.trim().is_empty())
        {
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
        Some(Ok(created)) => return App::reveal(cx, admin, href!(create).resolve(cx), created),
        Some(Err(refused)) => (None, Some(refused)),
        None => (revealed, None),
    };
    let typed = refused
        .as_ref()
        .and_then(|refused| refused.form.invitation.expires_in.clone());
    // A form posted again keeps its own, so it stays the same change.
    let shown = match &refused {
        Some(refused) => refused.form.shown.clone(),
        None => Secret::generate().map_err(AdminError::from)?.encoded(),
    };
    let (created, refused) = (&created, refused.as_deref());
    let page = view! { cx =>
        match created {
            Some(created) => {
                sourceorigin_ui::invitation_created(
                    link: created.url.as_str(),
                    expires_at: created.expires_at,
                    back: back.as_str(),
                )
            },
            None => {
                sourceorigin_ui::dashboard_change(
                    change: Change::Invite,
                    back: back.as_str(),
                    refusal: refused,
                    <input type="hidden" name="shown" value=(shown.as_str())>
                    <label>
                        "Valid for"
                        <input name="expires_in" placeholder="7d" pattern="[0-9]+[hd]" value=(typed)>
                        <small>"Hours or days, e.g. 24h or 7d; seven days when empty."</small>
                    </label>
                )
            },
        }
    };
    App::render(cx, StatusCode::OK, "Invite someone", page).await
}

/// `/invitations/{invitation}/revoke`: revokes an unredeemed invitation.
#[route([GET, POST] "/invitations/{invitation}/revoke")]
pub(super) async fn revoke(cx: &Cx, form: Option<Form<NoInput>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::invitations(cx)?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Invitation>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = App::submit(cx, form, back.clone(), |_| {
        service.revoke_invitation(&admin.operator, id)
    })
    .await?;
    let shown = id.to_string();
    let target = Target {
        name: "Invitation",
        id: Some(&shown),
    };
    let page = view! { cx =>
        sourceorigin_ui::dashboard_change(
            change: Change::RevokeInvitation,
            target: target,
            back: back.as_str(),
            refusal: refusal.as_deref(),
        )
    };
    App::render(cx, StatusCode::OK, "Revoke an invitation", page).await
}
