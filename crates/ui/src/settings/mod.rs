//! The account's settings: the pages the sidebar lists, and each page's
//! sections.

/// Connected apps.
mod connected;
/// Choosing which square of a new picture auth keeps.
mod cropper;
/// Downloading the account's data, and deleting the account.
mod data;
/// Email addresses, and confirming one.
mod emails;
/// The account at a glance.
mod overview;
/// The profile: the handle, display name and picture apps see.
mod profile;
/// Signed-in devices.
mod sessions;
/// Passkeys and social sign-in.
mod sign_in;
/// Security history.
mod timeline;

pub use connected::{ConnectedAppChange, ConnectedAppRow, ConnectedAppsState, connected_apps};
pub use data::{DataChange, DataState, account_data, account_deleted};
pub use emails::{EmailChange, EmailRow, EmailsState, addresses, verified, verify};
pub use overview::{AccountOverview, OverviewLinks, account_overview};
pub use profile::{
    CROP_SIZE, CROP_X, CROP_Y, PICTURE_FIELD, PICTURE_TYPES, ProfileChange, ProfileDialog,
    ProfilePages, ProfileState, profile_settings,
};
pub use sessions::{DeviceChange, DeviceRow, devices};
pub use sign_in::{ProviderRow, SignInChange, SignInState, sign_in_methods};
pub use timeline::{HistoryChange, HistoryPage, HistoryRow, HistoryState, Holdings, history};

use crate::{
    icons::Icon,
    layout::{Label, navigation},
};
use piquel_common::events::{Browser, Platform, UserAgentFamily};
use topcoat::{
    Result,
    context::Cx,
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
    /// or an address. The dashboard confirmed their passkey before showing a
    /// change.
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

    /// Whether it is the owner: it may add a way in or an address, and report a
    /// history entry.
    pub(crate) const fn owns(self) -> bool {
        matches!(self, Self::Owner { .. })
    }
}

/// The settings pages, in the order the sidebar lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// The account at a glance.
    Overview,
    /// Passkeys and social sign-in.
    SignIn,
    /// The handle, display name and picture apps see.
    Profile,
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
            Self::Overview => "Overview",
            Self::SignIn => "Sign-in methods",
            Self::Profile => "Profile",
            Self::Emails => "Email addresses",
            Self::Devices => "Devices",
            Self::Apps => "Connected apps",
            Self::History => "Security history",
            Self::Data => "Your data",
        }
    }
}

impl Tab {
    /// Its icon in the sidebar.
    pub(crate) const fn icon(self) -> Icon {
        match self {
            Self::Overview => Icon::Home,
            Self::SignIn => Icon::Key,
            Self::Profile => Icon::Profile,
            Self::Emails => Icon::Mail,
            Self::Devices => Icon::Device,
            Self::Apps => Icon::Grid,
            Self::History => Icon::Clock,
            Self::Data => Icon::Database,
        }
    }
}

impl Label for Tab {
    /// [`Tab::label`].
    fn label(self) -> &'static str {
        Self::label(self)
    }

    /// The tabs an administrator changes, whose pages confirm first: all those
    /// [`settings_tabs`] shows but the history, which they only read.
    fn confirms_first(self) -> bool {
        matches!(
            self,
            Self::SignIn | Self::Profile | Self::Emails | Self::Apps
        )
    }
}

/// The settings pages an administrator changes for an account, as tabs within
/// the account's page: `current` among them, linking each tab's page in `tabs`.
#[component]
pub async fn settings_tabs<'a>(
    cx: &Cx,
    tabs: &'a [(Tab, &'a str)],
    current: Tab,
) -> Result<impl View> {
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
