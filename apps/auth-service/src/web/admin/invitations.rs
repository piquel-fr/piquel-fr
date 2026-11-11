//! Signup invitations, whatever the signup setting: mailed to an address, or
//! links to pass on.

use super::{AdminApplication as App, ReasonForm, Refused};
use crate::{AdminError, InviteExpiry, Reason};
use chrono::Utc;
use sourceorigin_common::{
    TokenId,
    admin::{CreateInvitation, CreatedInvitation},
    email::NormalizedEmail,
};
use sourceorigin_ui::{Action, Change, InvitationRow, Target};
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, path_param, response::Response, route},
    view::view,
};

path_param!(pub invitation: TokenId, error = not_found);

/// `/invitations`: signup invitations, newest first, with the changes each
/// open one takes.
#[route(GET "/invitations")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let app = App::of(cx);
    let invitations = app.service.list_invitations(&admin.operator).await?;
    let (inline, now) = (admin.operator.is_confirmed(super::FORM_TIME), Utc::now());
    let rows: Vec<_> = invitations
        .iter()
        .map(|invitation| {
            let open = invitation.redeemed_at.is_none() && invitation.revoked_at.is_none();
            let action = |href: String| Action { href, inline };
            InvitationRow {
                invitation,
                resend: (open && invitation.expires_at > now && invitation.email.is_some())
                    .then(|| action(href!(resend, Invitation(invitation.id)).resolve(cx))),
                revoke: open.then(|| action(href!(revoke, Invitation(invitation.id)).resolve(cx))),
            }
        })
        .collect();
    let (creating, rows, required) = (&href!(create).resolve(cx), &rows, app.invite_required);
    let page = view! { cx =>
        sourceorigin_ui::invitation_list(
            rows: rows,
            create: creating.as_str(),
            now: now,
            required: required,
        )
    };
    App::render(cx, StatusCode::OK, "Invitations", page).await
}

/// `/invitations/new`: creates an invitation, mailed to the address given or
/// shown to pass on, then comes back here, which shows its link once, or where
/// it was mailed.
#[route([GET, POST] "/invitations/new")]
pub(super) async fn create(cx: &Cx, form: Option<Form<CreateInvitation>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    // The page showing a new link needs no confirmation: sending the browser to
    // confirm would lose the link.
    let revealed: Option<CreatedInvitation> = App::revealed(cx, admin);
    if revealed.is_none() {
        App::confirm(cx, admin)?;
    }
    let app = App::of(cx);
    let back = href!(list).resolve(cx);
    let created = App::change(cx, form, |input: CreateInvitation| async move {
        let typed = |value: Option<String>| value.filter(|value| !value.trim().is_empty());
        let expires_in = match typed(input.expires_in) {
            Some(expires_in) => expires_in
                .trim()
                .parse::<InviteExpiry>()
                .map_err(AdminError::from)?,
            None => InviteExpiry::default(),
        };
        let email = typed(input.email)
            .map(|email| NormalizedEmail::parse(email.trim()))
            .transpose()
            .map_err(AdminError::from)?;
        let reason = Reason::parse(input.reason)?;
        app.service
            .create_invitation(
                &admin.operator,
                &app.invitation_links,
                expires_in,
                email,
                reason,
            )
            .await
    })
    .await?;
    let back = &back;
    let (created, refused) = match created {
        Some(Ok(created)) => return App::reveal(cx, admin, href!(create).resolve(cx), created),
        Some(Err(refused)) => (None, Some(refused)),
        None => (revealed, None),
    };
    let (email, expires_in, reason) = refused.as_ref().map_or((None, None, None), |refused| {
        (
            refused.form.email.as_deref(),
            refused.form.expires_in.as_deref(),
            Some(refused.form.reason.as_str()),
        )
    });
    let (created, refused) = (&created, refused.as_deref());
    let page = view! { cx =>
        match created {
            Some(created) => {
                sourceorigin_ui::invitation_created(
                    sent: &created.sent,
                    expires_at: created.expires_at,
                    back: back.as_str(),
                )
            },
            None => {
                sourceorigin_ui::dashboard_change(
                    change: Change::Invite,
                    back: back.as_str(),
                    refusal: refused,
                    reason: reason,
                    <label>
                        "Email address"
                        <input name="email" type="email" autocomplete="off" value=(email)>
                        <small>"Origin Auth mails the link here. Leave it empty to get a link to pass on yourself."</small>
                    </label>
                    <label>
                        "Valid for"
                        <input name="expires_in" placeholder="7d" pattern="[0-9]+[hd]" value=(expires_in)>
                        <small>"Hours or days, e.g. 24h or 7d; seven days when empty."</small>
                    </label>
                )
            },
        }
    };
    App::render(cx, StatusCode::OK, "Invite someone", page).await
}

/// `/invitations/{invitation}/resend`: mails an open invitation's link again.
#[route([GET, POST] "/invitations/{invitation}/resend")]
pub(super) async fn resend(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Invitation>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = App::submit_reason(cx, form, back.clone(), async |reason| {
        service.resend_invitation(&admin.operator, id, reason).await
    })
    .await?;
    App::invitation_change(cx, Change::ResendInvitation, id, &back, refusal).await
}

/// `/invitations/{invitation}/revoke`: revokes an unredeemed invitation.
#[route([GET, POST] "/invitations/{invitation}/revoke")]
pub(super) async fn revoke(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let service = &App::of(cx).service;
    let id = *path_param::<Invitation>(cx)?;
    let back = href!(list).resolve(cx);
    let refusal = App::submit_reason(cx, form, back.clone(), async |reason| {
        service.revoke_invitation(&admin.operator, id, reason).await
    })
    .await?;
    App::invitation_change(cx, Change::RevokeInvitation, id, &back, refusal).await
}

impl App {
    /// The page of `change` to the invitation `id`, going back to `back`, with
    /// why its last attempt was refused, if it was.
    async fn invitation_change(
        cx: &Cx,
        change: Change,
        id: TokenId,
        back: &str,
        refusal: Option<Refused<ReasonForm>>,
    ) -> Result<Response> {
        let shown = id.to_string();
        let target = Target {
            name: "Invitation",
            id: Some(&shown),
        };
        let reason = refusal.as_ref().map(Refused::reason);
        let refusal = refusal.as_deref();
        let page = view! { cx =>
            sourceorigin_ui::dashboard_change(
                change: change,
                target: target,
                back: back,
                refusal: refusal,
                reason: reason,
            )
        };
        App::render(cx, StatusCode::OK, change.title(), page).await
    }
}
