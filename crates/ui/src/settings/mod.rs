//! The account's settings: the pages the sidebar lists, and each page's
//! sections.

/// Connected apps.
mod connected;
/// Downloading the account's data, and deleting the account.
mod data;
/// Email addresses, and confirming one.
mod emails;

/// The inbox, and one notification's page.
mod notifications;
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
pub use notifications::{
    InboxChange, InboxPage, InboxRow, InboxState, NotificationPage, NotificationState, SignOutStep,
    UnsubscribeStep, inbox, notification, sign_out_everywhere, unsubscribe,
};
pub use overview::{AccountOverview, OverviewLinks, account_overview};
pub use profile::{
    CROP_SIZE, CROP_X, CROP_Y, PICTURE_FIELD, PICTURE_TYPES, ProfileChange, ProfileDialog,
    ProfilePages, ProfileState, profile_settings,
};
pub use sessions::{DeviceChange, DeviceRow, devices, known_devices};
pub use sign_in::{ProviderRow, SignInChange, SignInState, sign_in_methods};
pub use timeline::{HistoryChange, HistoryPage, HistoryRow, HistoryState, Holdings, history};

use crate::{
    form::Query,
    icons::Icon,
    layout::{Destination, Label, Searchable, Spot, navigation},
};
use sourceorigin_common::events::{Browser, Platform, UserAgentFamily};
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
    /// The inbox.
    Notifications,
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
            Self::Notifications => "Notifications",
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
            Self::Notifications => Icon::Bell,
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

impl Searchable for Tab {
    fn icon(self) -> Icon {
        Self::icon(self)
    }

    fn terms(self) -> &'static str {
        match self {
            Self::Overview => "home account summary dashboard",
            Self::Notifications => "inbox messages announcements alerts unread",
            Self::SignIn => {
                "security login log in passkeys webauthn social providers google github password"
            }
            Self::Profile => "handle username display name picture avatar photo",
            Self::Emails => "email addresses mail primary verify",
            Self::Devices => "sessions browsers phones computers signed in sign out log out",
            Self::Apps => "consent authorized third party permissions access oauth",
            Self::History => "security log activity events audit timeline",
            Self::Data => "download export delete account gdpr privacy",
        }
    }
}

impl Tab {
    /// What the top bar's search finds within the settings pages, `tabs` linking
    /// each: every [`Part`], by the ID its page gives it, and every dialog, by the
    /// query opening it.
    pub(crate) fn spots<'a>(tabs: &[(Self, &'a str)]) -> Vec<Destination<'a>> {
        let page = |tab: Self| {
            tabs.iter()
                .find(|(each, _)| *each == tab)
                .map(|(_, href)| *href)
        };
        let spot = |tab: Self, at: String, spot: Spot| {
            page(tab)
                .map(|href| Destination::spot(tab.label(), tab.icon(), format!("{href}{at}"), spot))
        };
        let parts = Part::ALL
            .into_iter()
            .filter_map(|part| spot(part.tab(), format!("#{}", part.id()), part.spot()));
        // A dialog whose query cannot be written is left out; none fails.
        let dialogs = ProfileDialog::ALL.into_iter().filter_map(|dialog| {
            let state = ProfileState {
                open: Some(dialog),
                ..ProfileState::default()
            };
            spot(Self::Profile, state.on("").ok()?, dialog.spot()?)
        });
        let email = InboxState {
            email: true,
            ..InboxState::default()
        };
        let preferences = email.on("").ok().and_then(|at| {
            spot(
                Self::Notifications,
                at,
                Spot::setting(
                    "Email preferences",
                    "announcement emails unsubscribe newsletter mail notifications",
                ),
            )
        });
        parts.chain(dialogs).chain(preferences).collect()
    }
}

/// A part of a settings page, a section or what opens with a link to it: its
/// heading, or its disclosure, takes its ID from here, and the top bar's search
/// finds it by that ID, so a link to it never goes stale. A settings page's
/// every section heading is one, which a test checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    /// The overview's recent security activity.
    Activity,
    /// The inbox.
    Inbox,
    /// The passkeys.
    Passkeys,
    /// Adding a passkey, folded below them.
    AddPasskey,
    /// Social sign-in.
    Social,
    /// The email addresses.
    Addresses,
    /// Adding an address, folded below them.
    AddAddress,
    /// The signed-in devices.
    Devices,
    /// The browsers the account signed in with before, which a new one is not.
    KnownBrowsers,
    /// The connected apps.
    Apps,
    /// Downloading the account's data.
    Export,
    /// Deleting the account.
    Delete,
}

impl Part {
    /// Every part.
    const ALL: [Self; 12] = [
        Self::Activity,
        Self::Inbox,
        Self::Passkeys,
        Self::AddPasskey,
        Self::Social,
        Self::Addresses,
        Self::AddAddress,
        Self::Devices,
        Self::KnownBrowsers,
        Self::Apps,
        Self::Export,
        Self::Delete,
    ];

    /// The ID its heading or disclosure takes, which links it.
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::Activity => "activity-heading",
            Self::Inbox => "inbox-heading",
            Self::Passkeys => "passkeys-heading",
            Self::AddPasskey => "add-passkey",
            Self::Social => "social-heading",
            Self::Addresses => "emails-heading",
            Self::AddAddress => "add-email",
            Self::Devices => "sessions-heading",
            Self::KnownBrowsers => "known-heading",
            Self::Apps => "apps-heading",
            Self::Export => "export-heading",
            Self::Delete => "delete-heading",
        }
    }

    /// The tab whose page it is on.
    const fn tab(self) -> Tab {
        match self {
            Self::Activity => Tab::Overview,
            Self::Inbox => Tab::Notifications,
            Self::Passkeys | Self::AddPasskey | Self::Social => Tab::SignIn,
            Self::Addresses | Self::AddAddress => Tab::Emails,
            Self::Devices | Self::KnownBrowsers => Tab::Devices,
            Self::Apps => Tab::Apps,
            Self::Export | Self::Delete => Tab::Data,
        }
    }

    /// What search finds it by.
    const fn spot(self) -> Spot {
        match self {
            Self::Activity => Spot::setting("Recent security activity", "latest events sign-ins"),
            Self::Inbox => Spot::setting("Inbox", "messages notifications unread"),
            Self::Passkeys => Spot::setting(
                "Passkeys",
                "webauthn security key face id touch id windows hello fingerprint biometrics password rename remove",
            ),
            Self::AddPasskey => Spot::setting(
                "Add a passkey",
                "new passkey webauthn security key register device",
            ),
            Self::Social => Spot::setting(
                "Social sign-in",
                "google github apple microsoft providers linked accounts oauth link unlink",
            ),
            Self::Addresses => Spot::setting("Your addresses", "email primary verified remove"),
            Self::AddAddress => {
                Spot::setting("Add an email address", "new email address mail verify")
            }
            Self::Devices => Spot::setting(
                "Signed-in devices",
                "sessions browsers sign out everywhere log out revoke",
            ),
            Self::KnownBrowsers => Spot::setting(
                "Known browsers",
                "remembered devices new device sign-in alerts",
            ),
            Self::Apps => Spot::setting(
                "Apps with access",
                "connected authorized consent revoke access remove permissions",
            ),
            Self::Export => Spot::setting(
                "Download your data",
                "export takeout archive json backup gdpr copy",
            ),
            Self::Delete => Spot::setting(
                "Delete your account",
                "remove close erase account deletion gdpr",
            ),
        }
    }
}

/// The settings pages an administrator changes for an account, as tabs within
/// the account's page: `current` among them, linking each tab's page in `tabs`.
#[component]
pub async fn settings_tabs<'a>(tabs: &'a [(Tab, &'a str)], current: Tab) -> Result<impl View> {
    Ok(view! {
        navigation(label: "Account settings", class: "tabs", links: tabs, current: current)
    })
}

/// A device's name, from the browser and platform it signed in with, e.g.
/// "Firefox on Linux".
pub(crate) fn device_name(device: UserAgentFamily) -> String {
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
