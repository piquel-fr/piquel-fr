//! The account's settings: the tabs every settings page shares, and each page's
//! sections.

/// Connected apps.
mod connected;
/// Downloading the account's data, and deleting the account.
mod data;
/// Email addresses, and confirming one.
mod emails;
/// Signed-in devices.
mod sessions;
/// The handle, passkeys and social sign-in.
mod sign_in;
/// Security history.
mod timeline;

pub use connected::{ConnectedAppChange, ConnectedAppRow, ConnectedAppsState, connected_apps};
pub use data::{DataChange, DataState, account_data, account_deleted};
pub use emails::{EmailChange, EmailRow, EmailsState, addresses, verified, verify};
pub use sessions::{DeviceChange, DeviceRow, devices};
pub use sign_in::{HandleRow, ProviderRow, SignInChange, SignInState, sign_in_methods};
pub use timeline::{HistoryChange, HistoryPage, HistoryRow, HistoryState, Holdings, history};

use crate::layout::{Label, navigation};
use piquel_common::events::{Browser, Platform, UserAgentFamily};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// Whom a settings section serves, which decides what it offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience<'a> {
    /// The account's owner: every change, those needing a recent passkey
    /// confirmation asking for one first unless the session is `confirmed`, and
    /// adding passkeys, providers and addresses.
    Owner {
        /// Whether the session needs no passkey confirmation now.
        confirmed: bool,
    },
    /// An administrator, on the owner's behalf: only the changes they share with
    /// the owner, each with the reason they give, and nothing that adds a way in
    /// or an address. The dashboard confirmed their passkey before showing it.
    Administrator {
        /// The reason they typed for a change that was refused, which the open
        /// row's form shows again; empty otherwise.
        reason: &'a str,
    },
}

impl<'a> Audience<'a> {
    /// Whether a change needing a recent passkey confirmation asks for one first.
    pub(crate) const fn confirms(self) -> bool {
        matches!(self, Self::Owner { confirmed: false })
    }

    /// The reason every change asks for, as last typed, if every change asks
    /// why.
    pub(crate) const fn asks_reason(self) -> Option<&'a str> {
        match self {
            Self::Administrator { reason } => Some(reason),
            Self::Owner { .. } => None,
        }
    }

    /// Whether it may add a way in, or an address.
    pub(crate) const fn owns(self) -> bool {
        matches!(self, Self::Owner { .. })
    }
}

/// The settings pages, in the order the tabs list them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// The handle, passkeys and social sign-in.
    SignIn,
    /// Email addresses.
    Emails,
    /// Signed-in devices.
    Devices,
    /// Apps that keep access to the account.
    Apps,
    /// Security history.
    History,
    /// Downloading the account's data, and deleting the account.
    Data,
}

impl Tab {
    /// The tab's label, also the page's title in the browser.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SignIn => "Sign-in methods",
            Self::Emails => "Email addresses",
            Self::Devices => "Devices",
            Self::Apps => "Connected apps",
            Self::History => "Security history",
            Self::Data => "Your data",
        }
    }
}

impl Label for Tab {
    /// [`Tab::label`].
    fn label(self) -> &'static str {
        Self::label(self)
    }
}

/// The settings tabs, `current` among them, linking each tab's page in `tabs`.
#[component]
pub async fn settings_tabs<'a>(tabs: &'a [(Tab, &'a str)], current: Tab) -> Result<impl View> {
    Ok(view! {
        navigation(label: "Account settings", class: "tabs", links: tabs, current: current)
    })
}

/// A device's name, from the browser and platform it signed in with, e.g.
/// "Firefox on Linux".
fn device_name(device: UserAgentFamily) -> String {
    let browser = match device.browser {
        Browser::Chrome => "Chrome",
        Browser::Edge => "Edge",
        Browser::Firefox => "Firefox",
        Browser::Opera => "Opera",
        Browser::Safari => "Safari",
        Browser::Other => "Another browser or app",
    };
    let platform = match device.platform {
        Platform::Android => Some("Android"),
        Platform::ChromeOs => Some("ChromeOS"),
        Platform::Ios => Some("iOS"),
        Platform::Linux => Some("Linux"),
        Platform::MacOs => Some("macOS"),
        Platform::Windows => Some("Windows"),
        Platform::Other => None,
    };
    platform.map_or_else(
        || browser.to_owned(),
        |platform| format!("{browser} on {platform}"),
    )
}
