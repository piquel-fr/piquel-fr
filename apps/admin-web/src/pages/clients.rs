use super::heading;
use crate::admin::Admin;
use piquel_admin_api::AdminClient;
use topcoat::{
    Result,
    context::Cx,
    router::page,
    view::{View, view},
};

/// `/clients`: every OIDC client and its settings, read-only while clients come
/// from auth's configuration.
#[page("/clients")]
pub async fn list(cx: &Cx) -> Result<impl View> {
    let admin = Admin::of(cx).await?;
    let clients = admin.read(AdminClient::clients).await?;
    Ok(view! {
        heading(
            title: "Clients",
            lead: Some("Applications that sign users in with auth. They are configured with auth's deployment.".to_owned()),
        )
        if clients.is_empty() {
            <section class="card"><p class="empty">"No client is registered."</p></section>
        }
        for client in clients {
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
                </dl>
            </section>
        }
    })
}
