//! Signing keys: listing, rotating and revoking them. Importing the
//! deployment's PEM key stays at the terminal.

use super::{AdminApplication as App, ReasonForm, Refused};
use crate::Reason;
use serde::Deserialize;
use sourceorigin_common::protocol::jwt::KeyId;
use sourceorigin_ui::{Action, Change, Checkbox, SigningKeyRow, Target};
use topcoat::{
    Result,
    context::Cx,
    router::{StatusCode, content::Form, href, path_param, response::Response, route},
    view::view,
};

path_param!(pub key: KeyId, error = not_found);

/// The form rotating the signing key.
#[derive(Clone, Deserialize)]
struct Rotation {
    /// Whether the new key signs at once, skipping its day of waiting.
    #[serde(default)]
    now: Checkbox,
    /// Why.
    #[serde(default)]
    reason: String,
}

/// `/keys`: every signing key, oldest first, each with the change revoking it.
#[route(GET "/keys")]
pub(super) async fn list(cx: &Cx) -> Result<Response> {
    let admin = App::admin(cx).await?;
    let keys = App::of(cx)
        .service
        .list_signing_keys(&admin.operator)
        .await?;
    let inline = admin.operator.is_confirmed(super::FORM_TIME);
    let rows: Vec<_> = keys
        .iter()
        .map(|key| SigningKeyRow {
            key,
            revoke: Action {
                href: href!(revoke, Key(key.id.clone())).resolve(cx),
                inline,
            },
        })
        .collect();
    let (rows, rotating) = (&rows, &href!(rotate).resolve(cx));
    let page =
        view! { cx => sourceorigin_ui::signing_key_list(rows: rows, rotate: rotating.as_str()) };
    App::render(cx, StatusCode::OK, "Signing keys", page).await
}

/// `/keys/rotate`: publishes a new signing key, or makes it sign at once.
#[route([GET, POST] "/keys/rotate")]
pub(super) async fn rotate(cx: &Cx, form: Option<Form<Rotation>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let app = App::of(cx);
    let back = href!(list).resolve(cx);
    let refused = App::submit(cx, form, back.clone(), |input: Rotation| async move {
        let reason = Reason::parse(input.reason)?;
        app.service
            .rotate_signing_key(&admin.operator, &app.keys, input.now.0, reason)
            .await
            .map(drop)
    })
    .await?;
    let now = refused.as_ref().is_some_and(|refused| refused.form.now.0);
    let reason = refused.as_ref().map(|refused| refused.form.reason.as_str());
    let (back, refused) = (&back, refused.as_deref());
    let page = view! { cx =>
        sourceorigin_ui::signing_key_rotation(back: back.as_str(), refused: refused, now: now, reason: reason)
    };
    App::render(cx, StatusCode::OK, Change::RotateSigningKey.title(), page).await
}

/// `/keys/{key}/revoke`: deletes the key at once, and when it signs, the keys
/// stored beside it, a new key signing instead.
#[route([GET, POST] "/keys/{key}/revoke")]
pub(super) async fn revoke(cx: &Cx, form: Option<Form<ReasonForm>>) -> Result<Response> {
    let admin = App::admin(cx).await?;
    App::confirm(cx, admin)?;
    let app = App::of(cx);
    let id = path_param::<Key>(cx)?.clone();
    let back = href!(list).resolve(cx);
    let refused = App::submit_reason(cx, form, back.clone(), async |reason| {
        app.service
            .revoke_signing_key(&admin.operator, &app.keys, &id, reason)
            .await
            .map(drop)
    })
    .await?;
    let target = Target {
        name: "Signing key",
        id: Some(id.as_str()),
    };
    let reason = refused.as_ref().map(Refused::reason);
    let refused = refused.as_deref();
    let page = view! { cx =>
        sourceorigin_ui::dashboard_change(
            change: Change::RevokeSigningKey,
            target: target,
            back: back.as_str(),
            refusal: refused,
            reason: reason,
        )
    };
    App::render(cx, StatusCode::OK, Change::RevokeSigningKey.title(), page).await
}
