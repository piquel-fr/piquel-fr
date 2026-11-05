//! The OIDC clients: their list, one client's page, the form registering or
//! changing one, and rotating its secret. They build on the
//! developer console's pieces: its settings form, with the inputs only
//! operators fill in added, its status badges, and its secrets.

use super::{Action, Change, confirm, moment, refused_action};
use crate::{
    clients::{
        ClientDraft, ClientRow, ClientStatus, Revealed, SecretRow, choice, client_form,
        client_status, secret_panel, secrets_list,
    },
    developers::{SecretsState, app_secrets},
    form::{Checkbox, Lines},
    layout::page_head,
};
use chrono::{DateTime, Utc};
use piquel_common::{UserId, admin::Client, clients::ClientKind, protocol::oauth::Scope};
use serde::Deserialize;
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// A client in the list, and its page.
#[derive(Clone, Debug)]
pub struct AdminClientRow<'a> {
    /// The client.
    pub client: &'a Client,
    /// Its page.
    pub href: String,
}

/// A client's settings as an operator's form sends them: an owner's, then the
/// scopes beyond the standard ones and its trust, which only operators choose.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct OperatorDraft {
    /// What an owner chooses too.
    #[serde(flatten)]
    pub draft: ClientDraft,
    /// The scopes it may request beyond the standard ones, which have checkboxes.
    #[serde(default)]
    pub other_scopes: Lines,
    /// Whether it skips the consent screen.
    #[serde(default)]
    pub trusted: Checkbox,
}

impl OperatorDraft {
    /// `client`'s settings as they are, `trusted` or not: its standard scopes
    /// checked, and the others typed.
    #[must_use]
    pub fn of(client: &ClientRow<'_>, trusted: bool) -> Self {
        Self {
            draft: ClientDraft::from(client),
            other_scopes: client
                .allowed_scopes
                .iter()
                .filter(|scope| scope.parse::<Scope>().is_err())
                .cloned()
                .collect(),
            trusted: Checkbox(trusted),
        }
    }

    /// Every scope chosen: the standard ones checked, then the others typed.
    #[must_use]
    pub fn scopes(&self) -> Vec<String> {
        let mut scopes = self.draft.scopes.names();
        scopes.extend(Vec::from(self.other_scopes.clone()));
        scopes
    }
}

/// A client an operator registers: the ID they choose, its kind and settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct NewClientForm {
    /// Its ID, as typed.
    pub id: String,
    /// Its kind, which the form's radio group chooses: confidential when the form
    /// sends none, as the group starts there.
    #[serde(default)]
    pub kind: Option<ClientKind>,
    /// Its settings.
    #[serde(flatten)]
    pub settings: OperatorDraft,
}

impl NewClientForm {
    /// The kind the form's radio group starts at.
    pub const DEFAULT_KIND: ClientKind = ClientKind::Confidential;

    /// Its kind.
    #[must_use]
    pub fn kind(&self) -> ClientKind {
        self.kind.unwrap_or(Self::DEFAULT_KIND)
    }
}

/// What a client form registers or changes.
#[derive(Clone, Copy, Debug)]
pub enum Registration<'a> {
    /// A new client, with the ID typed and the kind chosen.
    New {
        /// The ID typed.
        id: &'a str,
        /// The kind chosen.
        kind: ClientKind,
    },
    /// The settings of the client named so.
    Edit {
        /// Its name.
        name: &'a str,
    },
}

impl Registration<'_> {
    /// Its page's title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::New { .. } => "Register a client",
            Self::Edit { .. } => "Client settings",
        }
    }

    /// The page's title, what the form does, and its button.
    fn words(self) -> (&'static str, String, &'static str) {
        match self {
            Self::New { .. } => (
                self.title(),
                "A client operators manage. Its ID can never change or be registered again."
                    .to_owned(),
                "Register",
            ),
            Self::Edit { name } => (self.title(), name.to_owned(), "Save changes"),
        }
    }
}

/// The page registering or changing a client, posting to `action`: the
/// console's settings form showing `settings`, with the ID and kind of a client
/// not registered yet, and the inputs only operators fill in. `refusal` says why
/// the last attempt was refused.
#[component]
pub async fn client_registration<'a>(
    registration: Registration<'a>,
    settings: &'a OperatorDraft,
    action: &'a str,
    #[into]
    #[default]
    refusal: Option<&'a str>,
) -> Result<impl View> {
    let (title, lead, label) = registration.words();
    let (id, kind) = match registration {
        Registration::New { id, kind } => (Some(id), Some(kind)),
        Registration::Edit { .. } => (None, None),
    };
    Ok(view! {
        page_head(title: title, lead: lead)
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        client_form(
            action: action,
            change: (),
            draft: &settings.draft,
            kind: kind,
            label: label,
            head: view! {
                if let Some(id) = id {
                    <label>
                        "Client ID"
                        <input name="id" value=(id) maxlength="64" required="" autocomplete="off" aria-describedby="client-id-help">
                    </label>
                    <small class="field-help" id="client-id-help">
                        "1 to 64 characters from A–Z, a–z, 0–9, “.”, “_” and “-”. It never changes."
                    </small>
                }
            },
            <label>
                "Other scopes"
                <textarea name="other_scopes" rows="2" aria-describedby="other-scopes-help">(settings.other_scopes.text())</textarea>
            </label>
            <small class="field-help" id="other-scopes-help">
                "Optional, one per line: scopes beyond the standard ones above, such as an API's."
            </small>
            choice(
                name: "trusted",
                checked: settings.trusted.0,
                label: view! { "Trusted" },
                detail: view! {
                    "Skips the consent screen, and its pages may sign users in with their passkeys on approved origins. Only for Piquel's own apps."
                },
            )
        )
    })
}

/// The changes the dashboard makes to a client that is not deleted, each by its
/// page.
#[derive(Clone, Debug)]
pub struct ClientChanges {
    /// Its settings.
    pub settings: String,
    /// Disabling or enabling it, by its status; none while it is suspended.
    pub status: Option<Action>,
    /// Suspending it, or lifting its suspension.
    pub suspension: Action,
    /// Deleting it.
    pub delete: Action,
    /// Rotating a confidential client's secret.
    pub secret: Option<String>,
}

/// One client, as its page shows it.
#[derive(Clone, Debug)]
pub struct ClientPage<'a> {
    /// The client, as the console shows it.
    pub client: ClientRow<'a>,
    /// Whether it skips the consent screen.
    pub trusted: bool,
    /// The audiences it may request tokens for.
    pub audiences: &'a [String],
    /// The account that manages it, and its page; none for operators'.
    pub owner: Option<(UserId, String)>,
    /// When it was registered.
    pub created_at: DateTime<Utc>,
    /// When its registration last changed.
    pub updated_at: DateTime<Utc>,
    /// When it was deleted, if it was.
    pub deleted_at: Option<DateTime<Utc>>,
    /// A confidential client's secrets, oldest first.
    pub secrets: &'a [SecretRow],
    /// Its approved origins, as browsers send them, and the pages removing them.
    pub origins: Vec<(&'a str, String)>,
    /// The page approving an origin, or why it cannot be done.
    pub approve: Result<String, &'a str>,
    /// The changes the dashboard makes to it, unless it is deleted.
    pub changes: Option<ClientChanges>,
}

/// The OIDC clients, each linking its page, with the page registering a client
/// at `new`.
#[component]
pub async fn client_list<'a>(rows: &'a [AdminClientRow<'a>], new: &'a str) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Clients",
            lead: "Applications that sign users in with Piquel.".to_owned(),
            actions: view! {
                <a data-confirm-first="" class="button" href=(new)>"Register a client"</a>
            },
        )
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No client is registered."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr><th>"name"</th><th>"ID"</th><th>"managed by"</th><th>"status"</th><th></th></tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                let client = row.client;
                                <tr>
                                    <td>
                                        <a href=(row.href.as_str())>
                                            (if client.display_name.is_empty() { "Deleted client" } else { client.display_name.as_str() })
                                        </a>
                                    </td>
                                    <td><code>(client.id.as_str())</code></td>
                                    <td>(if client.owner_id.is_some() { "An account" } else { "Operators" })</td>
                                    <td>listed_status(client: client)</td>
                                    <td class="right">
                                        if client.trusted { <span class="badge">"Trusted"</span> }
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

/// A listed client's status, as a badge.
#[component]
async fn listed_status<'a>(client: &'a Client) -> Result<impl View> {
    let (tone, label) = match client.status() {
        "enabled" => ("ok", "Enabled"),
        "suspended" => ("danger", "Suspended"),
        "deleted" => ("neutral", "Deleted"),
        _ => ("warning", "Disabled"),
    };
    Ok(view! {
        <span class=(class!("badge", tone))>(label)</span>
    })
}

/// One client's page as of `now`: what it is, why it does not sign users in,
/// if it does not, its changes, a confidential client's secrets, and the
/// origins its pages sign users in on.
#[component]
pub async fn client_page<'a>(page: &'a ClientPage<'a>, now: DateTime<Utc>) -> Result<impl View> {
    let client = page.client;
    let title = if client.name.is_empty() {
        client.id.as_str()
    } else {
        client.name
    };
    Ok(view! {
        page_head(
            title: title,
            lead: client.id.to_string(),
            actions: view! {
                if page.deleted_at.is_some() {
                    <span class="badge neutral">"Deleted"</span>
                } else {
                    client_status(client: client)
                }
                if page.trusted { " " <span class="badge">"Trusted"</span> }
            },
        )
        if let Some(at) = page.deleted_at {
            <p class="notice">"Deleted on " moment(at: at) ". Its ID is never registered again."</p>
        } else if let ClientStatus::Suspended { at } = client.status {
            <p class="notice error">
                "Suspended on " moment(at: at) ": it cannot sign users in, and its owner cannot enable it."
            </p>
        } else if client.status == ClientStatus::Disabled {
            <p class="notice warning">"Disabled: it cannot sign users in until it is enabled."</p>
        }
        <section class="card" aria-labelledby="registration-heading">
            <header><h2 id="registration-heading">"Registration"</h2></header>
            <div class="body">
                client_facts(page: page)
                if let Some(changes) = &page.changes {
                    client_actions(client: client, changes: changes)
                }
            </div>
        </section>
        if client.kind == ClientKind::Confidential {
            <section class="card" aria-labelledby="secrets-heading">
                <header>
                    <h2 id="secrets-heading">"Client secrets " <span class="count">(page.secrets.len().to_string())</span></h2>
                    if let Some(rotate) = page.changes.as_ref().and_then(|changes| changes.secret.as_deref()) {
                        <a data-confirm-first="" class="button secondary small" href=(rotate)>"Rotate the secret"</a>
                    }
                </header>
                secrets_list(secrets: page.secrets, now: now)
            </section>
        }
        <section class="card" aria-labelledby="origins-heading">
            <header>
                <h2 id="origins-heading">"Passkey sign-in"</h2>
                if let Ok(href) = &page.approve {
                    <a data-confirm-first="" class="button secondary small" href=(href.as_str())>(Change::ApproveOrigin.title())</a>
                }
            </header>
            <div class="body">
                <p class="help">
                    "The origins whose pages sign users in with their Piquel passkeys, without sending them to Piquel's pages."
                    if let Err(reason) = &page.approve { " " (*reason) }
                </p>
            </div>
            if page.origins.is_empty() {
                <p class="empty">"No origin is approved."</p>
            } else {
                <ul class="list">
                    for (origin, remove) in &page.origins {
                        <li>
                            <div class="text"><code>(*origin)</code></div>
                            <a data-confirm-first="" class="button secondary small" href=(remove.as_str()) aria-label=(format!("Remove {origin}"))>"Remove"</a>
                        </li>
                    }
                </ul>
            }
        </section>
    })
}

/// A confidential client's secrets on `page`, the client named `name`: the
/// developer console's, the one a rotation just made, once, then the lifetimes
/// of its `secrets` as of `now`, and rotating, with the grace `state` chose.
/// `refusal` says why the last rotation was refused.
#[component]
pub async fn client_secrets<'a>(
    page: &'a str,
    name: &'a str,
    secrets: &'a [SecretRow],
    now: DateTime<Utc>,
    state: &'a SecretsState,
    #[into]
    #[default]
    refusal: Option<&'a str>,
) -> Result<impl View> {
    Ok(view! {
        page_head(title: "Client secrets", lead: name.to_owned())
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        app_secrets(page: page, secrets: secrets, now: now, state: state, confirmed: true)
    })
}

/// A client just registered: its first `secret`, shown once, then its `page`.
#[component]
pub async fn client_created<'a>(secret: &'a Revealed, page: &'a str) -> Result<impl View> {
    Ok(view! {
        secret_panel(secret: secret, page: page, next: page)
    })
}

/// What `page`'s client is: how it signs users in, who manages it, its settings
/// and when it was registered, changed and last used.
#[component]
async fn client_facts<'a>(page: &'a ClientPage<'a>) -> Result<impl View> {
    let client = page.client;
    let yes_no = |yes: bool, said: &'static str| if yes { said } else { "No" };
    Ok(view! {
        <dl class="facts">
            <dt>"Kind"</dt><dd>(client.kind_name())</dd>
            <dt>"Authentication"</dt><dd><code>(client.kind.auth_method().as_str())</code></dd>
            <dt>"Managed by"</dt>
            <dd>
                if let Some((owner, href)) = &page.owner {
                    <a href=(href.as_str())>"Account " <code>(owner.to_string())</code></a>
                } else {
                    "Operators"
                }
            </dd>
            <dt>"Redirect URIs"</dt>
            <dd>
                for uri in client.redirect_uris {
                    <div><code>(uri.as_str())</code></div>
                }
            </dd>
            <dt>"After sign-out"</dt>
            <dd>
                for uri in client.post_logout_uris {
                    <div><code>(uri.as_str())</code></div>
                }
                if client.post_logout_uris.is_empty() { "None" }
            </dd>
            <dt>"Back-channel logout"</dt>
            <dd>
                if let Some(uri) = client.backchannel_logout_uri {
                    <code>(uri)</code>
                } else {
                    "Not told"
                }
            </dd>
            <dt>"Scopes"</dt><dd><code>(client.allowed_scopes.join(" "))</code></dd>
            <dt>"Audiences"</dt><dd><code>(page.audiences.join(" "))</code></dd>
            <dt>"Refresh tokens"</dt><dd>(yes_no(client.allow_refresh, "Allowed"))</dd>
            <dt>"Pushed requests"</dt><dd>(if client.require_pushed_authorization_requests { "Required" } else { "Optional" })</dd>
            <dt>"Consent screen"</dt><dd>(if page.trusted { "Skipped: trusted" } else { "Shown" })</dd>
            <dt>"Registered"</dt><dd>moment(at: page.created_at)</dd>
            <dt>"Changed"</dt><dd>moment(at: page.updated_at)</dd>
            <dt>"Last used"</dt>
            <dd>
                if let Some(at) = client.last_used_at {
                    moment(at: at)
                } else {
                    "Never"
                }
            </dd>
        </dl>
    })
}

/// The `changes` the dashboard makes to `client`: its settings, then disabling
/// or enabling it, suspending it or lifting its suspension, and deleting it.
#[component]
async fn client_actions<'a>(
    client: ClientRow<'a>,
    changes: &'a ClientChanges,
) -> Result<impl View> {
    Ok(view! {
        <div class="row actions">
            <a data-confirm-first="" class="button secondary small" href=(changes.settings.as_str())>"Edit settings"</a>
            match &changes.status {
                Some(action) if client.status == ClientStatus::Enabled => confirm(action: action, change: Change::DisableClient),
                Some(action) => confirm(action: action, change: Change::EnableClient),
                None => refused_action(label: "Enable", reason: "Lift the suspension first."),
            }
            if let ClientStatus::Suspended { .. } = client.status {
                confirm(action: &changes.suspension, change: Change::UnsuspendClient)
            } else {
                confirm(action: &changes.suspension, change: Change::SuspendClient)
            }
            confirm(action: &changes.delete, change: Change::DeleteClient)
        </div>
    })
}
