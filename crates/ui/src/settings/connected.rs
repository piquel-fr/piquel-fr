//! Connected apps: the apps that keep access to the account.

use super::Audience;
use crate::{
    form::{Query, change_form, open},
    layout::page_head,
    oidc::scope_label,
};
use serde::{Deserialize, Serialize};
use sourceorigin_common::ClientId;
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
    /// Whether SourceOrigin makes it: its next sign-in grants it access again.
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
        if audience.owns() {
            page_head(
                title: "Connected apps",
                lead: "The apps you sign in to with Origin Auth that keep access to your account, and what they can see. Remove any you no longer use.".to_owned(),
            )
        }
        <section class="card" aria-labelledby="apps-heading">
            <header>
                <h2 id="apps-heading">"Connected apps " <span class="count">(rows.len().to_string())</span></h2>
            </header>
            <ul class="list">
                for row in rows {
                    app_row(
                        page: page,
                        row: *row,
                        removing: state.removing.as_ref() == Some(row.client_id),
                        audience: audience,
                    )
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
        (true, true) => "Can use your account while you’re away.",
        (false, true) => "Can use your account only while you’re signed in to it.",
        (true, false) => "Can use the account while its owner is away.",
        (false, false) => "Can use the account only while its owner is signed in to it.",
    };
    let again = if row.first_party {
        format!(
            "SourceOrigin makes {name}, so signing in to it again gives it access without asking."
        )
    } else if audience.owns() {
        format!("{name} will need your approval again to use your account.")
    } else {
        format!("{name} will need the owner’s approval again to use the account.")
    };
    let sees: Vec<_> = row.scopes.iter().map(|scope| scope_label(scope)).collect();
    Ok(view! {
        <li class=(if removing { "open" } else { "" })>
            <div class="text">
                <strong>(name)</strong>
                if row.first_party {
                    " " <span class="badge">"Made by SourceOrigin"</span>
                }
                <small>(format!("Sees: {}", sees.join(", ")))</small>
                <small>(away)</small>
            </div>
            if removing {
                <strong tabindex="-1" autofocus="">(format!("Remove {name}’s access?"))</strong>
                <p class="help">(again) " Access it already has can last up to 5 minutes."</p>
                change_form(
                    action: page,
                    change: ConnectedAppChange::Remove { client_id: row.client_id.clone() },
                    label: "Remove access",
                    class: "danger",
                    reason: audience.asks_reason(),
                    cancel: page.to_owned(),
                )
            } else {
                open(
                    page: page,
                    opens: ConnectedAppsState { removing: Some(row.client_id.clone()) },
                    label: "Remove access",
                    aria_label: format!("Remove access for {name}"),
                    danger: true,
                )
            }
        </li>
    })
}
