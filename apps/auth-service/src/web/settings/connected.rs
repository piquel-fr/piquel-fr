//! `/settings/apps`: the apps that keep access to the account.

use crate::{
    account::{AccountError, Owner},
    routes::page::settings,
    web::{
        Failure, WebApplication,
        account::{AccountPage, Applied, Reader},
    },
};
use piquel_ui::{
    ConnectedAppChange, ConnectedAppRow, ConnectedAppsState, Messages, Notice, Section, Tab,
};
use topcoat::{
    context::Cx,
    router::{StatusCode, response::Response},
    view::{Child, view},
};

/// The connected apps page.
pub(in crate::web) struct ConnectedApps;

impl ConnectedApps {
    /// Its tab.
    const TAB: Tab = Tab::Apps;
}

impl AccountPage for ConnectedApps {
    const SECTION: Section = Section::Account;
    const PATH: &'static str = settings::APPS;
    const TITLE: &'static str = Self::TAB.label();
    type Change = ConnectedAppChange;
    type Row = ConnectedAppsState;

    fn reopened(change: &ConnectedAppChange) -> ConnectedAppsState {
        match change {
            ConnectedAppChange::Remove { client_id } => ConnectedAppsState {
                removing: Some(client_id.clone()),
            },
        }
    }

    async fn apply(
        web: &WebApplication,
        _: &Cx,
        owner: Owner,
        change: ConnectedAppChange,
    ) -> Result<Applied<ConnectedAppsState>, AccountError> {
        match change {
            ConnectedAppChange::Remove { client_id } => {
                web.account.remove_app(&owner, &client_id).await?;
            }
        }
        Ok(Applied::Done(Notice::AppRemoved))
    }

    async fn render(
        web: &WebApplication,
        cx: &Cx,
        reader: &Reader,
        state: ConnectedAppsState,
        outcome: (StatusCode, Messages<'_>),
    ) -> Result<Response, Failure> {
        let apps = web.account.apps(&reader.viewer()).await?;
        let rows: Vec<_> = apps
            .iter()
            .map(|app| ConnectedAppRow {
                client_id: &app.client_id,
                name: &app.name,
                first_party: app.first_party,
                scopes: &app.scopes,
                offline: app.offline,
            })
            .collect();
        let page = Child::new(view! { cx =>
            piquel_ui::connected_apps(page: settings::APPS, rows: &rows, state: &state)
        });
        web.settings_page(cx, Self::TAB, reader, outcome, &[], page)
            .await
    }
}
