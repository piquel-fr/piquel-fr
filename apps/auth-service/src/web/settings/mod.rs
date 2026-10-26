//! The account's settings, at `/settings`: the tabs every settings page shares.
//!
//! Each tab is an [`AccountPage`](super::account::AccountPage) of the account
//! section, keeping its [`Tab`] to mark it among the tabs. Confirming an address,
//! from its emailed link, is a page of its own.

/// Email addresses, and confirming one.
mod emails;
/// Security history.
mod history;
/// Signed-in devices.
mod sessions;
/// Passkeys and social sign-in.
mod sign_in;
#[cfg(test)]
mod tests;

pub(super) use emails::Addresses;
pub(super) use history::History;
pub(super) use sessions::Devices;
pub(super) use sign_in::SignInMethods;

use super::{
    Failure, WebApplication,
    account::{Framed, Reader},
};
use crate::{emails::EmailView, routes::page::settings};
use piquel_ui::{EmailRow, Messages, Section, Tab};
use topcoat::{
    context::Cx,
    router::{StatusCode, response::Response},
    view::{Child, view},
};
use url::Url;

/// Each tab and the page it links.
const TABS: [(Tab, &str); 4] = [
    (Tab::SignIn, settings::HOME),
    (Tab::Emails, settings::EMAILS),
    (Tab::Devices, settings::SESSIONS),
    (Tab::History, settings::HISTORY),
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

impl WebApplication {
    /// Answers with the settings tab `tab`, `page`, below the tabs, at the status
    /// and with the messages of `outcome`. Its forms may redirect to `targets`.
    async fn settings_page(
        &self,
        cx: &Cx,
        tab: Tab,
        reader: &Reader,
        outcome: (StatusCode, Messages<'_>),
        targets: &[Url],
        page: Child<'_>,
    ) -> Result<Response, Failure> {
        let head = view! { cx => piquel_ui::settings_tabs(tabs: &TABS, current: tab) };
        let framed = Framed {
            section: Section::Account,
            title: tab.label(),
            head: Child::new(head),
            page,
        };
        self.account_page(cx, reader, outcome, targets, framed)
            .await
    }
}
