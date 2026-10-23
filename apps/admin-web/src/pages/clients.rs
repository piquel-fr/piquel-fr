use super::{change_form, heading, refused_action};
use crate::admin::Admin;
use piquel_admin_api::{AdminClient, ApproveOrigin};
use piquel_common::{ClientId, clients::RelatedOrigin};
use serde::{Serialize, de::IgnoredAny};
use topcoat::{
    Result,
    context::Cx,
    router::{content::Form, href, page, path_param, query_params},
    view::{View, view},
};

path_param!(pub client: ClientId, error = not_found);

/// The query of [`remove_origin`]: the approved origin to remove.
#[query_params(error = bad_request)]
#[derive(Serialize)]
struct OriginQuery {
    /// The origin, as approved.
    origin: RelatedOrigin,
}

/// `/clients`: every OIDC client, its settings and the origins whose pages may
/// sign users in with passkeys. Only those origins change here: other settings
/// come from auth's configuration.
#[page("/clients")]
pub async fn list(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    let clients = admin.read(AdminClient::clients).await?;
    let origins = admin.read(AdminClient::related_origins).await?;
    Ok(view! {
        heading(
            title: "Clients",
            lead: Some("Applications that sign users in with auth. Their settings come from auth's deployment; only the origins whose pages sign users in with passkeys change here.".to_owned()),
        )
        if clients.is_empty() {
            <section class="card"><p class="empty">"No client is registered."</p></section>
        }
        for client in clients {
            let approved = origins.iter().filter(|approved| approved.client_id == client.id);
            <section class="card">
                <div class="row between">
                    <h2>(client.display_name) " " <code>(client.id.to_string())</code></h2>
                    <div class="row">
                        if !client.enabled { <span class="badge disabled">"Disabled"</span> }
                        if client.trusted { <span class="badge">"Trusted"</span> }
                    </div>
                </div>
                <dl class="facts">
                    <dt>"Redirect URIs"</dt><dd>(client.redirect_uris.join(", "))</dd>
                    <dt>"After sign-out"</dt><dd>(client.post_logout_uris.join(", "))</dd>
                    <dt>"Back-channel logout"</dt><dd>(client.backchannel_logout_uri.as_deref().unwrap_or("Not told"))</dd>
                    <dt>"Scopes"</dt><dd>(client.allowed_scopes.join(" "))</dd>
                    <dt>"Audiences"</dt><dd>(client.allowed_audiences.join(" "))</dd>
                    <dt>"Refresh tokens"</dt><dd>(if client.allow_refresh { "Allowed" } else { "No" })</dd>
                    <dt>"Pushed requests"</dt><dd>(if client.require_pushed_authorization_requests { "Required" } else { "Optional" })</dd>
                    <dt>"Authentication"</dt><dd><code>(client.token_endpoint_auth_method.to_string())</code></dd>
                    <dt>"Passkey sign-in on"</dt>
                    <dd>
                        for approved in approved {
                            <span class="row">
                                <code>(approved.origin.to_string())</code>
                                <a href=(href!(remove_origin, Client(client.id.clone())).query(OriginQuery { origin: approved.origin.clone() }))>"Remove"</a>
                            </span>
                        }
                        if client.deleted_at.is_none() {
                            if client.trusted {
                                <a href=(href!(approve_origin, Client(client.id.clone())))>"Approve an origin"</a>
                            } else {
                                refused_action(label: "Approve an origin", reason: "Only trusted clients' pages can sign users in themselves.")
                            }
                        }
                    </dd>
                </dl>
            </section>
        }
    })
}

/// `/clients/{client}/origins/approve`: lets a trusted client's pages on an origin
/// sign users in with their passkeys, without sending them to auth's pages.
#[page([GET, POST] "/clients/{client}/origins/approve")]
pub async fn approve_origin(cx: &Cx, form: Option<Form<ApproveOrigin>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = path_param::<Client>(cx)?.clone();
    let back = href!(list).resolve(cx);
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, input| async move {
            api.approve_related_origin(token, &id, &input).await
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Approve an origin",
            description: "Pages on this origin can sign users in with their Piquel passkeys. It must be the origin of one of the client's redirect URIs. Browsers honour approved origins on at most 5 different domains, across every client.",
            button: "Approve",
            back: back,
            refusal: refusal,
            <label>
                "Origin"
                <input name="origin" required="" autocomplete="off" placeholder="https://notes.example">
            </label>
        )
    })
}

/// `/clients/{client}/origins/remove?origin=…`: stops a client's pages on an
/// origin from signing users in. Browsers may keep the origin listed for 5 minutes,
/// but auth refuses its sign-ins at once.
#[page([GET, POST] "/clients/{client}/origins/remove")]
pub async fn remove_origin(cx: &Cx, form: Option<Form<IgnoredAny>>) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    admin.confirm(cx)?;
    let id = path_param::<Client>(cx)?.clone();
    let origin = query_params::<OriginQuery>(cx)?.origin.clone();
    let back = href!(list).resolve(cx);
    let description = format!(
        "Pages on {origin} stop signing users in, and send them to auth's pages instead. Users stay signed in."
    );
    let refusal = admin
        .submit(cx, form, back.clone(), |api, token, _| async move {
            api.remove_related_origin(token, &id, &origin).await
        })
        .await?;
    Ok(view! {
        change_form(
            title: "Remove an origin",
            description: &description,
            button: "Remove",
            back: back,
            refusal: refusal,
            danger: true,
        )
    })
}
