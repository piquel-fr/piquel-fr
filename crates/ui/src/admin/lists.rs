//! The dashboard's lists: administrators, invitations and OIDC clients.

use super::{Action, Change, confirm, moment, refused_action};
use crate::layout::{Who, avatar, page_head};
use chrono::{DateTime, Utc};
use piquel_common::admin::{Administrator, Client, Invitation};
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// An administrator, the link to their account, and the change revoking their
/// rights, or why the dashboard cannot.
#[derive(Clone, Debug)]
pub struct AdministratorRow<'a> {
    /// The administrator.
    pub administrator: &'a Administrator,
    /// Their account's page.
    pub account: String,
    /// Revoking their rights, or why it cannot be done here.
    pub revoke: Result<Action, &'a str>,
}

/// An OIDC client, the origins approved for its pages to sign users in with
/// passkeys, each with the page removing it, and the page approving another, or
/// why the client cannot have one.
#[derive(Clone, Debug)]
pub struct AdminClientRow<'a> {
    /// The client.
    pub client: &'a Client,
    /// Its approved origins, as browsers send them, and the pages removing them.
    pub origins: Vec<(&'a str, String)>,
    /// The page approving an origin, or why it cannot be done.
    pub approve: Result<String, &'a str>,
}

/// An invitation, and the change revoking it while it can still be used.
#[derive(Clone, Debug)]
pub struct InvitationRow<'a> {
    /// The invitation.
    pub invitation: &'a Invitation,
    /// Revoking it, while it is open.
    pub revoke: Option<Action>,
}

impl InvitationRow<'_> {
    /// Whether it can still be used, as of `now`, as a badge's tone and label.
    fn state(&self, now: DateTime<Utc>) -> (&'static str, &'static str) {
        let invitation = self.invitation;
        if invitation.redeemed_at.is_some() {
            ("ok", "Redeemed")
        } else if invitation.revoked_at.is_some() {
            ("danger", "Revoked")
        } else if invitation.expires_at <= now {
            ("neutral", "Expired")
        } else {
            ("", "Open")
        }
    }
}

/// Who administers Piquel, with the page granting rights at `grant`.
#[component]
pub async fn administrator_list<'a>(
    rows: &'a [AdministratorRow<'a>],
    grant: &'a str,
) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Administrators",
            lead: "The accounts that can use this dashboard and every admin operation.".to_owned(),
            actions: view! { <a class="button" href=(grant)>"Grant rights"</a> },
        )
        <section class="card">
            <ul class="list">
                for row in rows {
                    let who = Who {
                        user: None,
                        name: row.administrator.handle.as_str(),
                        handle: row.administrator.handle.as_str(),
                        administrator: true,
                    };
                    <li>
                        avatar(who: who)
                        <div class="text">
                            <a href=(row.account.as_str())><strong>(format!("@{}", row.administrator.handle))</strong></a>
                            <small>"since " moment(at: row.administrator.granted_at)</small>
                        </div>
                        match &row.revoke {
                            Ok(action) => confirm(action: action, change: Change::RevokeAdministrator),
                            Err(reason) => refused_action(label: "Revoke", reason: reason),
                        }
                    </li>
                }
            </ul>
        </section>
    })
}

/// The signup invitations as of `now`, with the page creating one at `create`, or,
/// with no `rows`, that signup is open.
#[component]
pub async fn invitation_list<'a>(
    #[into] rows: Option<&'a [InvitationRow<'a>]>,
    create: &'a str,
    now: DateTime<Utc>,
) -> Result<impl View> {
    Ok(view! {
        match rows {
            None => {
                page_head(
                    title: "Invitations",
                    lead: "Single-use signup links, while signup needs one.".to_owned(),
                )
                <section class="card">
                    <p class="empty">"Signup is open: anyone can register without an invitation, so there is none to manage."</p>
                </section>
            },
            Some(rows) => {
                page_head(
                    title: "Invitations",
                    lead: "Single-use signup links, while signup needs one.".to_owned(),
                    actions: view! { <a class="button" href=(create)>"Invite someone"</a> },
                )
                <section class="card">
                    if rows.is_empty() {
                        <p class="empty">"No invitation yet."</p>
                    } else {
                        <div class="table-wrap">
                            <table>
                                <thead>
                                    <tr><th>"created"</th><th>"expires"</th><th>"state"</th><th></th></tr>
                                </thead>
                                <tbody>
                                    for row in rows {
                                        let (tone, label) = row.state(now);
                                        <tr>
                                            <td>moment(at: row.invitation.created_at)</td>
                                            <td>moment(at: row.invitation.expires_at)</td>
                                            <td><span class=(class!("badge", tone))>(label)</span></td>
                                            <td class="right">
                                                if let Some(revoke) = &row.revoke {
                                                    confirm(action: revoke, change: Change::RevokeInvitation)
                                                }
                                            </td>
                                        </tr>
                                    }
                                </tbody>
                            </table>
                        </div>
                    }
                </section>
            },
        }
    })
}

/// The page creating an invitation, with why the last attempt was refused, or,
/// once created, its `link`, shown only now, expiring at `expires_at`; both go
/// back to `back`.
#[component]
pub async fn invitation_created<'a>(
    link: &'a str,
    expires_at: DateTime<Utc>,
    back: &'a str,
) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Invitation created",
            lead: "Send this link to the person you invite. It is shown only now, and works once.".to_owned(),
        )
        <section class="card">
            <div class="body">
                <input readonly="" value=(link) aria-label="Signup link">
                <p class="help">"Expires " moment(at: expires_at)</p>
                <div class="row"><a class="button secondary" href=(back)>"Done"</a></div>
            </div>
        </section>
    })
}

/// Every OIDC client and its settings, read-only but for the origins whose pages
/// sign users in with passkeys.
#[component]
pub async fn client_list<'a>(rows: &'a [AdminClientRow<'a>]) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Clients",
            lead: "Applications that sign users in with Piquel.".to_owned(),
        )
        if rows.is_empty() {
            <section class="card"><p class="empty">"No client is registered."</p></section>
        }
        for row in rows {
            let client = row.client;
            <section class="card">
                <header>
                    <h2>(client.display_name.as_str()) " " <code>(client.id.to_string())</code></h2>
                    <span class="row">
                        <span class=(class!("badge", "ok" if client.status() == "Enabled", "warning" if client.status() != "Enabled"))>(client.status())</span>
                        if client.trusted { <span class="badge">"Trusted"</span> }
                    </span>
                </header>
                <div class="body">
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
                        <dd class="stack tight">
                            for (origin, remove) in &row.origins {
                                <span class="row">
                                    <code>(*origin)</code>
                                    <a href=(remove.as_str())>"Remove"</a>
                                </span>
                            }
                            match &row.approve {
                                Ok(href) => <a href=(href.as_str())>"Approve an origin"</a>,
                                Err(reason) => refused_action(label: "Approve an origin", reason: reason),
                            }
                        </dd>
                    </dl>
                </div>
            </section>
        }
    })
}
