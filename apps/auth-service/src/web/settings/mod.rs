//! The account's settings, at `/settings`: the pages the sidebar lists.
//!
//! Each is an [`AccountPage`](super::account::AccountPage) of the account
//! section, keeping its [`Tab`] to mark it in the sidebar. Confirming an address,
//! from its emailed link, is a page of its own.

/// Connected apps.
mod connected;
/// Downloading the account's data, and deleting the account.
mod data;
/// Email addresses, and confirming one.
mod emails;
/// Security history.
mod history;
/// The inbox, and one notification's page.
mod notifications;
/// The account at a glance.
mod overview;
/// The profile: its handle, display name and picture.
mod profile;
/// Signed-in devices.
mod sessions;
/// Passkeys and social sign-in.
mod sign_in;
#[cfg(test)]
mod tests;

pub(super) use connected::ConnectedApps;
pub(super) use data::AccountData;
pub(super) use emails::Addresses;
pub(super) use history::History;
pub(super) use notifications::{Inbox, NotificationPage};
pub(super) use overview::Overview;
pub(super) use profile::Profile;
pub(super) use sessions::Devices;
pub(super) use sign_in::SignInMethods;

use super::{
    Failure, WebApplication,
    account::{Framed, Reader},
};
use crate::{
    emails::EmailView,
    federation::FederationApplication,
    grants::ConnectedApp,
    history::{HistoryItem, HistoryPage},
    notifications::NotificationItem,
    routes::page::settings,
    sessions::SessionItem,
};
use sourceorigin_common::protocol::api::Identity;
use sourceorigin_ui::{
    ConnectedAppRow, DeviceRow, EmailRow, HistoryRow, InboxRow, Messages, ProviderRow, Section, Tab,
};
use topcoat::{
    context::Cx,
    router::{StatusCode, response::Response},
    view::Child,
};
use url::Url;

/// Each tab and the page it links, in the sidebar's order.
pub(super) const TABS: [(Tab, &str); 9] = [
    (Tab::Overview, settings::HOME),
    (Tab::Notifications, settings::NOTIFICATIONS),
    (Tab::SignIn, settings::SIGN_IN),
    (Tab::Profile, settings::PROFILE),
    (Tab::Emails, settings::EMAILS),
    (Tab::Devices, settings::SESSIONS),
    (Tab::Apps, settings::APPS),
    (Tab::History, settings::HISTORY),
    (Tab::Data, settings::DATA),
];

impl<'a> From<&'a EmailView> for EmailRow<'a> {
    /// The address as a page shows it.
    fn from(email: &'a EmailView) -> Self {
        Self {
            id: email.id,
            address: &email.address,
            verified: email.verified,
            primary: email.primary,
        }
    }
}

impl<'a> From<&'a ConnectedApp> for ConnectedAppRow<'a> {
    /// The app as a page shows it.
    fn from(app: &'a ConnectedApp) -> Self {
        Self {
            client_id: &app.client_id,
            name: &app.name,
            first_party: app.first_party,
            scopes: &app.scopes,
            offline: app.offline,
        }
    }
}

impl<'a> From<&'a SessionItem> for DeviceRow<'a> {
    /// The session as a page shows it.
    fn from(session: &'a SessionItem) -> Self {
        Self {
            id: session.id,
            current: session.current,
            device: session.device,
            ip: session.ip,
            methods: &session.methods,
            authenticated_at: session.authenticated_at,
            last_seen_at: session.last_seen_at,
        }
    }
}

impl<'a> From<&'a HistoryItem> for HistoryRow<'a> {
    /// The entry as a page shows it.
    fn from(item: &'a HistoryItem) -> Self {
        Self {
            id: item.id,
            occurred_at: item.occurred_at,
            entry: &item.entry,
            actor: item.actor,
            reportable: item.reportable(),
            reason: item.reason.as_deref(),
            client: item
                .client
                .as_ref()
                .map(|client| (client.id.as_str(), client.name.as_deref())),
            ip: item.ip,
            device: item.device,
            erased: item.erased,
        }
    }
}

impl<'a> From<&'a NotificationItem> for InboxRow<'a> {
    /// The notification as a page lists it.
    fn from(item: &'a NotificationItem) -> Self {
        Self {
            id: item.id,
            created_at: item.created_at,
            read: item.read(),
            subject: &item.subject,
            body: &item.body,
        }
    }
}

impl HistoryPage {
    /// Its entries as a page shows them.
    pub(super) fn rows(&self) -> Vec<HistoryRow<'_>> {
        self.entries.iter().map(HistoryRow::from).collect()
    }
}

impl FederationApplication {
    /// The social sign-in providers as the pages list them: the enabled ones,
    /// then any linked `identities` since disabled, so they can still be
    /// unlinked.
    pub(super) fn provider_rows<'a>(&self, identities: &'a [Identity]) -> Vec<ProviderRow<'a>> {
        let enabled: Vec<_> = self.enabled().collect();
        let mut providers: Vec<_> = enabled
            .iter()
            .map(|&provider| ProviderRow {
                provider,
                identity: identities
                    .iter()
                    .find(|identity| identity.provider == provider),
                enabled: true,
            })
            .collect();
        providers.extend(
            identities
                .iter()
                .filter(|identity| !enabled.contains(&identity.provider))
                .map(|identity| ProviderRow {
                    provider: identity.provider,
                    identity: Some(identity),
                    enabled: false,
                }),
        );
        providers
    }
}

impl WebApplication {
    /// Answers with the settings tab `tab`, `page`, at the status and with the
    /// messages of `outcome`. Its forms may redirect to `targets`.
    async fn settings_page(
        &self,
        cx: &Cx,
        tab: Tab,
        reader: &Reader,
        outcome: (StatusCode, Messages<'_>),
        targets: &[Url],
        page: Child<'_>,
    ) -> Result<Response, Failure> {
        let framed = Framed {
            section: Section::Account,
            tab: Some(tab),
            trail: &[],
            title: tab.label().into(),
            head: Child::default(),
            page,
        };
        self.account_page(cx, reader, outcome, targets, framed)
            .await
    }
}
