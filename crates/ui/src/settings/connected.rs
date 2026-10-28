//! Connected apps: the apps that keep access to the account.

use super::Audience;
use crate::form::{Query, change_form, open};
use crate::oidc::scope_label;
use piquel_common::ClientId;
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the connected apps page posts, named by its `action` field. It needs
/// no passkey confirmation: it only takes access away.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ConnectedAppChange {
    /// Removes an app's access.
    Remove {
        /// The app.
        client_id: ClientId,
    },
}

/// Which app's removal awaits confirmation, as the page's query names it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectedAppsState {
    /// The app.
    #[serde(rename = "remove")]
    pub removing: Option<ClientId>,
}

impl Query for ConnectedAppsState {}

/// An app that keeps access to the account.
#[derive(Clone, Copy, Debug)]
pub struct ConnectedAppRow<'a> {
    /// Its client ID, to remove it.
    pub client_id: &'a ClientId,
    /// The name its consent screen shows.
    pub name: &'a str,
    /// Whether Piquel makes it: its next sign-in grants it access again.
    pub first_party: bool,
    /// What it can read.
    pub scopes: &'a [String],
    /// Whether it can act while the user is away.
    pub offline: bool,
}

/// The connected apps page: the apps in `rows`, each removable once confirmed,
/// as `state` opens it, for `audience`. Its changes post to `page`.
#[component]
pub async fn connected_apps<'a>(
    page: &'a str,
    rows: &'a [ConnectedAppRow<'a>],
    state: &'a ConnectedAppsState,
    audience: Audience<'a>,
) -> Result<impl View> {
    Ok(view! {
        <p class="help">
            (if audience.owns() {
                "The apps you sign in to with Piquel that keep access to your account, and what they can see. Remove any you no longer use."
            } else {
                "The apps that keep access to this account, and what they can see."
            })
        </p>
        <section class="card" aria-labelledby="apps-heading">
            <div class="row between">
                <h2 id="apps-heading">"Connected apps"</h2>
                <span class="badge">(format!("{} connected", rows.len()))</span>
            </div>
            <ul class="list">
                for row in rows {
                    <li>
                        app_row(
                            page: page,
                            row: *row,
                            removing: state.removing.as_ref() == Some(row.client_id),
                            audience: audience,
                        )
                    </li>
                }
            </ul>
            if rows.is_empty() {
                <p class="empty">
                    (if audience.owns() { "No apps have access to your account." } else { "No app has access to this account." })
                </p>
            }
        </section>
    })
}

/// One app of [`connected_apps`]: what it can see, and removing it. The open
/// removal row takes the focus.
#[component]
async fn app_row<'a>(
    page: &'a str,
    row: ConnectedAppRow<'a>,
    removing: bool,
    audience: Audience<'a>,
) -> Result<impl View> {
    let name = row.name;
    let away = match (row.offline, audience.owns()) {
        (true, true) => "It can use your account while you’re away.",
        (false, true) => "It can use your account only while you’re signed in to it.",
        (true, false) => "It can use the account while its owner is away.",
        (false, false) => "It can use the account only while its owner is signed in to it.",
    };
    let again = if row.first_party {
        format!("Piquel makes {name}, so signing in to it again gives it access without asking.")
    } else if audience.owns() {
        format!("{name} will need your approval again to use your account.")
    } else {
        format!("{name} will need the owner’s approval again to use the account.")
    };
    Ok(view! {
        <div class="stack">
            <div class="row between">
                <div class="row">
                    <strong>(name)</strong>
                    if row.first_party {
                        <span class="badge">"Made by Piquel"</span>
                    }
                </div>
                if !removing {
                    open(
                        page: page,
                        opens: ConnectedAppsState { removing: Some(row.client_id.clone()) },
                        label: "Remove access",
                        aria_label: format!("Remove access for {name}"),
                    )
                }
            </div>
            <ul>
                for scope in row.scopes {
                    <li>(scope_label(scope))</li>
                }
            </ul>
            <p class="help">(away)</p>
            if removing {
                <div class="notice stack">
                    <strong tabindex="-1" autofocus="">(format!("Remove {name}’s access?"))</strong>
                    <p>(again) " Access it already has can last up to 5 minutes."</p>
                    change_form(
                        action: page,
                        change: ConnectedAppChange::Remove { client_id: row.client_id.clone() },
                        label: "Remove access",
                        class: "danger",
                        reason: audience.asks_reason(),
                        cancel: page.to_owned(),
                    )
                </div>
            }
        </div>
    })
}
