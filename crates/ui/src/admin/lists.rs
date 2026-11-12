//! The dashboard's lists: administrators and invitations.

use super::{Action, Change, UserRow, account_status, confirm, moment, refused_action};
use crate::{
    clients::copyable,
    icons::{Icon, icon},
    layout::{Pager, Who, avatar, page_head, pager},
};
use chrono::{DateTime, Utc};
use sourceorigin_common::{
    AccountStatus,
    admin::{Administrator, Invitation, InvitationSent},
};
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
    /// Where their profile picture is served, if they have one.
    pub picture: Option<String>,
    /// Revoking their rights, or why it cannot be done here.
    pub revoke: Result<Action, &'a str>,
}

/// An invitation, and the changes it takes while it can still be used.
#[derive(Clone, Debug)]
pub struct InvitationRow<'a> {
    /// The invitation.
    pub invitation: &'a Invitation,
    /// Mailing it again, while it is open and was mailed.
    pub resend: Option<Action>,
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

/// Who administers Origin Auth, with the page granting rights at `grant`.
#[component]
pub async fn administrator_list<'a>(
    rows: &'a [AdministratorRow<'a>],
    grant: &'a str,
) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Administrators",
            lead: "The accounts that can use this dashboard and every admin operation.".to_owned(),
            actions: view! { <a data-confirm-first="" class="button" href=(grant)>"Grant rights"</a> },
        )
        <section class="card">
            <ul class="list">
                for row in rows {
                    let who = Who {
                        name: row.administrator.handle.as_str(),
                        handle: row.administrator.handle.as_str(),
                        picture: row.picture.as_deref(),
                        administrator: true,
                    };
                    <li>
                        avatar(who: who)
                        <div class="text">
                            <a href=(row.account.as_str())><strong>(format!("@{}", row.administrator.handle))</strong></a>
                            <small>"since " moment(at: row.administrator.granted_at)</small>
                        </div>
                        match &row.revoke {
                            Ok(action) => {
                                let named = format!("{} ({})", row.administrator.handle, row.administrator.user_id);
                                confirm(action: action, change: Change::RevokeAdministrator, target: named.as_str())
                            },
                            Err(reason) => refused_action(label: "Revoke", reason: reason),
                        }
                    </li>
                }
            </ul>
        </section>
    })
}

/// The page granting administrator rights: a search of accounts, by handle, name,
/// email or ID, posting `q` back to the page by `GET`, then the accounts `rows`
/// found, with the `pages` through them, each with the button granting it rights,
/// which posts its ID to the page. An account that administers already, or
/// cannot sign in, gets none. `refusal` says why the last grant was refused.
#[component]
pub async fn grant_search<'a>(
    action: &'a str,
    q: &'a str,
    rows: &'a [UserRow<'a>],
    pages: &'a Pager,
    #[into]
    #[default]
    refusal: Option<&'a str>,
) -> Result<impl View> {
    let change = Change::GrantAdministrator;
    // The page is shown only to a confirmed dashboard, so every grant is a dialog.
    let grant = Action {
        href: action.to_owned(),
        inline: true,
    };
    Ok(view! {
        page_head(title: change.title(), lead: change.description().to_owned())
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        <form class="row search" method="get" action=(action) role="search">
            <label class="search-box grow">
                icon(kind: Icon::Search)
                <input
                    type="search"
                    name="q"
                    value=(q)
                    placeholder="Handle, name, email or account ID"
                    aria-label="Search accounts"
                    autocomplete="off"
                    autofocus=""
                    data-live="grant-results"
                >
            </label>
            <button class="secondary">"Search"</button>
        </form>
        // What the search script swaps in as the administrator types.
        <div class="stack" id="grant-results">
            if q.is_empty() {
                <section class="card"><p class="empty">"Search for the account to make an administrator."</p></section>
            } else {
                <section class="card">
                    if rows.is_empty() {
                        <p class="empty">(format!("No account matches “{q}”."))</p>
                    } else {
                        <ul class="list">
                            for row in rows {
                                let subject = format!("@{}", row.user.handle);
                                <li>
                                    avatar(who: row.who())
                                    <div class="text">
                                        <a href=(row.href.as_str())><strong>(format!("@{}", row.user.handle))</strong></a>
                                        <small>(row.user.display_name.as_str()) " · " (row.user.id.to_string())</small>
                                    </div>
                                    if row.administrator {
                                        <span class="badge admin"><span class="dot"></span>"Administrator"</span>
                                    } else if row.user.status != AccountStatus::Active {
                                        account_status(status: row.user.status)
                                    } else {
                                        confirm(
                                            action: &grant,
                                            change: change,
                                            subject: subject.as_str(),
                                            <input type="hidden" name="user_id" value=(row.user.id.to_string())>
                                        )
                                    }
                                </li>
                            }
                        </ul>
                    }
                </section>
                pager(pages: pages, what: "accounts")
            }
        </div>
    })
}

/// The signup invitations as of `now`, with the page creating one at `create`,
/// and whether signup is `required` to start with one.
#[component]
pub async fn invitation_list<'a>(
    rows: &'a [InvitationRow<'a>],
    create: &'a str,
    now: DateTime<Utc>,
    required: bool,
) -> Result<impl View> {
    let lead = if required {
        "Single-use signup links. Signup needs one: each lets one person create an account."
    } else {
        "Single-use signup links. Signup is open, so anyone can sign up: an invitation is a signup link you can follow."
    };
    Ok(view! {
        page_head(
            title: "Invitations",
            lead: lead.to_owned(),
            actions: view! { <a data-confirm-first="" class="button" href=(create)>"Invite someone"</a> },
        )
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No invitation yet."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr><th>"sent to"</th><th>"created"</th><th>"expires"</th><th>"state"</th><th></th></tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                let (tone, label) = row.state(now);
                                let named = format!("Invitation ({})", row.invitation.id);
                                <tr>
                                    <td>
                                        match &row.invitation.email {
                                            Some(email) => (email),
                                            None => <span class="muted">"Link passed on"</span>,
                                        }
                                    </td>
                                    <td>moment(at: row.invitation.created_at)</td>
                                    <td>moment(at: row.invitation.expires_at)</td>
                                    <td><span class=(class!("badge", tone))>(label)</span></td>
                                    <td class="right">
                                        if let Some(resend) = &row.resend {
                                            confirm(action: resend, change: Change::ResendInvitation, target: named.as_str())
                                        }
                                        if let Some(revoke) = &row.revoke {
                                            confirm(action: revoke, change: Change::RevokeInvitation, target: named.as_str())
                                        }
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
    })
}

/// A new invitation, expiring at `expires_at`, as it was `sent`: its link,
/// shown only now, or the address it was mailed to. Both go back to `back`.
#[component]
pub async fn invitation_created<'a>(
    sent: &'a InvitationSent,
    expires_at: DateTime<Utc>,
    back: &'a str,
) -> Result<impl View> {
    let (title, lead) = match sent {
        InvitationSent::Link(_) => (
            "Invitation created",
            "Send this link to the person you invite. It is shown only now, and works once."
                .to_owned(),
        ),
        InvitationSent::Mailed(email) => (
            "Invitation sent",
            format!(
                "Origin Auth mailed the link to {email}. The account created with it starts with this address, verified."
            ),
        ),
    };
    Ok(view! {
        page_head(title: title, lead: lead)
        <section class="card">
            <div class="body">
                if let InvitationSent::Link(link) = sent {
                    copyable(id: "invitation-link", label: "signup link", value: link.as_str())
                }
                <p class="help">"Expires " moment(at: expires_at)</p>
                <div class="row"><a class="button secondary" href=(back)>"Done"</a></div>
            </div>
        </section>
    })
}
