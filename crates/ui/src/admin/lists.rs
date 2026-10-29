//! The dashboard's lists: administrators, invitations, OIDC clients and events.

use super::{heading, moment, refused_action};
use chrono::{DateTime, Utc};
use piquel_common::admin::{Administrator, Client, Event, Invitation};
use serde_json::Value;
use topcoat::{
    Result,
    view::{View, component, view},
};

/// An administrator, the link to their account, and the page revoking their
/// rights, or why the dashboard cannot.
#[derive(Clone, Debug)]
pub struct AdministratorRow<'a> {
    /// The administrator.
    pub administrator: &'a Administrator,
    /// Their account's page.
    pub account: String,
    /// The page revoking their rights, or why it cannot be done here.
    pub revoke: Result<String, &'a str>,
}

/// An invitation, and the page revoking it while it can still be used.
#[derive(Clone, Debug)]
pub struct InvitationRow<'a> {
    /// The invitation.
    pub invitation: &'a Invitation,
    /// The page revoking it, while it is open.
    pub revoke: Option<String>,
}

/// An event, and the link to the account it concerns, if any.
#[derive(Clone, Debug)]
pub struct EventRow<'a> {
    /// The event.
    pub event: &'a Event,
    /// The page of the account it concerns.
    pub account: Option<String>,
}

impl EventRow<'_> {
    /// The event's kind, or `unknown`.
    fn kind(&self) -> String {
        Self::text(&self.event.event, "kind")
    }

    /// Who caused it, by type, or `unknown`.
    fn actor(&self) -> String {
        Self::text(&self.event.actor, "type")
    }

    /// The text `value` holds under `key`, or `unknown`.
    fn text(value: &Value, key: &str) -> String {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned()
    }

    /// Its data, as JSON.
    fn data(&self) -> String {
        self.event
            .event
            .get("data")
            .map(Value::to_string)
            .unwrap_or_default()
    }
}

impl InvitationRow<'_> {
    /// Whether it can still be used, as of `now`.
    fn state(&self, now: DateTime<Utc>) -> &'static str {
        let invitation = self.invitation;
        if invitation.redeemed_at.is_some() {
            "Redeemed"
        } else if invitation.revoked_at.is_some() {
            "Revoked"
        } else if invitation.expires_at <= now {
            "Expired"
        } else {
            "Open"
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
        <div class="row between">
            heading(title: "Administrators")
            <a class="button" href=(grant)>"Grant rights"</a>
        </div>
        <section class="card">
            <table>
                <thead>
                    <tr><th>"Username"</th><th>"Since"</th><th></th></tr>
                </thead>
                <tbody>
                    for row in rows {
                        <tr>
                            <td><a href=(row.account.as_str())>(row.administrator.handle.as_str())</a></td>
                            <td>moment(at: row.administrator.granted_at)</td>
                            <td>
                                match &row.revoke {
                                    Ok(href) => <a href=(href.as_str())>"Revoke"</a>,
                                    Err(reason) => refused_action(label: "Revoke", reason: reason),
                                }
                            </td>
                        </tr>
                    }
                </tbody>
            </table>
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
                heading(title: "Invitations")
                <section class="card">
                    <p>"Signup is open: anyone can register without an invitation."</p>
                </section>
            },
            Some(rows) => {
                <div class="row between">
                    heading(title: "Invitations")
                    <a class="button" href=(create)>"Invite"</a>
                </div>
                <section class="card">
                    if rows.is_empty() {
                        <p class="empty">"No invitation yet."</p>
                    } else {
                        <table>
                            <thead>
                                <tr><th>"Created"</th><th>"Expires"</th><th>"State"</th><th></th></tr>
                            </thead>
                            <tbody>
                                for row in rows {
                                    <tr>
                                        <td>moment(at: row.invitation.created_at)</td>
                                        <td>moment(at: row.invitation.expires_at)</td>
                                        <td>(row.state(now))</td>
                                        <td>
                                            if let Some(revoke) = &row.revoke {
                                                <a href=(revoke.as_str())>"Revoke"</a>
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
        <section class="card narrow stack">
            <h1>"Invitation created"</h1>
            <p>"Send this link to the person you invite. It is shown only now, and works once."</p>
            <input readonly="" value=(link) aria-label="Signup link">
            <p class="muted">"Expires " moment(at: expires_at)</p>
            <a class="button secondary" href=(back)>"Done"</a>
        </section>
    })
}

/// Every OIDC client and its settings, read-only.
#[component]
pub async fn client_list<'a>(clients: &'a [Client]) -> Result<impl View> {
    Ok(view! {
        heading(
            title: "Clients",
            lead: "Applications that sign users in with Piquel.".to_owned(),
        )
        if clients.is_empty() {
            <section class="card"><p class="empty">"No client is registered."</p></section>
        }
        for client in clients {
            <section class="card">
                <div class="row between">
                    <h2>(client.display_name.as_str()) " " <code>(client.id.to_string())</code></h2>
                    <div class="row">
                        <span class="badge">(client.status())</span>
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

/// Domain events, newest first: the filter form posting `user` and `kind` back
/// to `action` by `GET`, the events, and the `older` page's link, if there is one.
#[component]
pub async fn event_list<'a>(
    action: &'a str,
    #[into]
    #[default]
    user: Option<String>,
    #[into]
    #[default]
    kind: Option<&'a str>,
    rows: &'a [EventRow<'a>],
    #[into]
    #[default]
    older: Option<String>,
) -> Result<impl View> {
    Ok(view! {
        heading(title: "Events")
        <form method="get" action=(action) class="row search">
            <input name="user" value=(user) placeholder="Account ID" aria-label="Account ID">
            <input name="kind" value=(kind) placeholder="Kind, e.g. session_revoked" aria-label="Event kind">
            <button>"Filter"</button>
        </form>
        <section class="card">
            event_rows(rows: rows)
        </section>
        if let Some(older) = older {
            <a class="button secondary" href=(older)>"Older events"</a>
        }
    })
}

/// A table of events, each linking to the account it concerns.
#[component]
pub async fn event_rows<'a>(rows: &'a [EventRow<'a>]) -> Result<impl View> {
    Ok(view! {
        if rows.is_empty() {
            <p class="empty">"No event."</p>
        } else {
            <table>
                <thead>
                    <tr><th>"When"</th><th>"Kind"</th><th>"Account"</th><th>"By"</th><th>"Details"</th><th>"Trace"</th></tr>
                </thead>
                <tbody>
                    for row in rows {
                        <tr>
                            <td>moment(at: row.event.occurred_at)</td>
                            <td><code>(row.kind())</code></td>
                            <td>
                                if let Some(account) = &row.account {
                                    <a href=(account.as_str())>"Account"</a>
                                }
                            </td>
                            <td>(row.actor())</td>
                            <td><code class="details">(row.data())</code></td>
                            <td>
                                if let Some(trace_id) = row.event.trace_id {
                                    <code title="Search Grafana for this trace ID">(trace_id.to_string())</code>
                                }
                            </td>
                        </tr>
                    }
                </tbody>
            </table>
        }
    })
}
