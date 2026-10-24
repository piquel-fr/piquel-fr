//! The account's settings: the frame every settings page shares, the forms its
//! changes post, and each page's sections.
//!
//! A change posts one form to its page, naming it in the hidden `action` field.
//! One that needs a recent passkey confirmation is marked `data-passkey-confirm`
//! while the session has none, and the SDK confirms before posting it; every other
//! form is marked `data-submit-once`, so a double click posts it once. A row opens
//! for editing or confirmation by a `GET` form, so it works without a script.
//!
//! Each page's changes and query are types here, such as [`SignInChange`] and
//! [`SignInState`]. Forms and links serialize them, and the page that receives them
//! deserializes the same types, so a field's name is written once.

/// Email addresses, and confirming one.
mod emails;
/// Signed-in devices.
mod sessions;
/// Passkeys and social sign-in.
mod sign_in;
/// Security history.
mod timeline;

pub use emails::{EmailChange, EmailRow, EmailsState, addresses, verified, verify};
pub use sessions::{DeviceChange, DeviceRow, devices};
pub use sign_in::{ProviderRow, SignInChange, SignInState, sign_in_methods};
pub use timeline::{HistoryChange, HistoryPage, HistoryRow, HistoryState, Holdings, history};

use crate::intro;
use chrono::{DateTime, Utc};
use piquel_common::events::{Browser, Platform, UserAgentFamily};
use serde::Serialize;
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

/// The settings pages, in the order the tabs list them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// Passkeys and social sign-in.
    SignIn,
    /// Email addresses.
    Emails,
    /// Signed-in devices.
    Devices,
    /// Security history.
    History,
}

impl Tab {
    /// The tab's label, also the page's title in the browser.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SignIn => "Sign-in methods",
            Self::Emails => "Email addresses",
            Self::Devices => "Devices",
            Self::History => "Security history",
        }
    }
}

piquel_common::str_enum! {
    /// What the last change did, which its page says once it is shown again.
    pub enum Notice {
        /// A passkey was added.
        PasskeyAdded = "passkey_added",
        /// A passkey was renamed.
        PasskeyRenamed = "passkey_renamed",
        /// A passkey was removed.
        PasskeyRemoved = "passkey_removed",
        /// A social sign-in was unlinked.
        IdentityUnlinked = "identity_unlinked",
        /// An address was added and its link sent.
        EmailAdded = "email_added",
        /// Another address became the primary one.
        EmailPrimary = "email_primary",
        /// An address was removed.
        EmailRemoved = "email_removed",
        /// One device was signed out.
        DeviceSignedOut = "device_signed_out",
        /// Every other device was signed out.
        OthersSignedOut = "others_signed_out",
    }
}

impl Notice {
    /// What the page says.
    const fn message(self) -> &'static str {
        match self {
            Self::PasskeyAdded => "The passkey was added.",
            Self::PasskeyRenamed => "The passkey was renamed.",
            Self::PasskeyRemoved => "The passkey was removed.",
            Self::IdentityUnlinked => "The social sign-in was unlinked.",
            Self::EmailAdded => "We sent a confirmation link. Open it to confirm the address.",
            Self::EmailPrimary => "Your primary address changed. We told your previous one.",
            Self::EmailRemoved => "The address was removed.",
            Self::DeviceSignedOut => "The device was signed out.",
            Self::OthersSignedOut => "Your other devices were signed out.",
        }
    }
}

/// What a page says when its form came from an older page and does not decode.
pub const OUT_OF_DATE: &str = "This page was out of date. Try again.";

/// What a settings page says above its sections: the last change's `notice`, and
/// the `alert` of a change that failed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Messages<'a> {
    /// What the last change did.
    pub notice: Option<Notice>,
    /// Why the change just posted failed.
    pub alert: Option<&'a str>,
}

impl<'a> Messages<'a> {
    /// Only an `alert`.
    #[must_use]
    pub const fn alert(alert: &'a str) -> Self {
        Self {
            notice: None,
            alert: Some(alert),
        }
    }
}

/// A settings page's query: which history it shows and which of its rows are open.
/// Its links and `GET` forms serialize it, and the page deserializes it back, so
/// both name the same parameters.
pub trait Query: Serialize {
    /// The link to `page` with this query.
    ///
    /// # Errors
    ///
    /// Fails if the query does not serialize as name-value pairs.
    fn on(&self, page: &str) -> Result<String> {
        let query = serde_urlencoded::to_string(self)?;
        Ok(if query.is_empty() {
            page.to_owned()
        } else {
            format!("{page}?{query}")
        })
    }
}

impl Query for () {}

/// Defines [`Fields`], with a conversion from each type a form or link sends.
macro_rules! fields {
    ($($(#[$doc:meta])* $variant:ident($type:ty)),* $(,)?) => {
        /// What a form sends: a page's change, or the query opening one of its rows.
        #[derive(Clone, Debug, Serialize)]
        #[serde(untagged)]
        enum Fields {
            $($(#[$doc])* $variant($type),)*
        }

        $(impl From<$type> for Fields {
            /// The fields sending it.
            fn from(fields: $type) -> Self {
                Self::$variant(fields)
            }
        })*
    };
}

fields! {
    /// A change of the sign-in methods.
    SignIn(SignInChange),
    /// A change of the addresses.
    Email(EmailChange),
    /// A change of the devices.
    Device(DeviceChange),
    /// A change of the history.
    History(HistoryChange),
    /// A row of the sign-in methods.
    SignInRow(SignInState),
    /// A row of the addresses.
    EmailRow(EmailsState),
    /// A page or row of the history.
    HistoryRow(HistoryState),
}

impl Fields {
    /// The name-value pairs the form sends, as its hidden inputs hold them.
    fn pairs(&self) -> Result<Vec<(String, String)>> {
        let encoded = serde_urlencoded::to_string(self)?;
        Ok(serde_urlencoded::from_str(&encoded)?)
    }
}

/// The frame of every settings page: its heading, and the page as `child`. The
/// heading is the tabs' own, or `title` for a page outside them.
#[component]
pub async fn settings_frame<'a>(
    #[into]
    #[default]
    title: Option<&'a str>,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <section class="settings">
            <div class="settings-header">
                intro(
                    eyebrow: "Your account",
                    title: title.unwrap_or("Security, made personal."),
                    lead: title.is_none().then_some(
                        "Manage how you sign in to Piquel and keep your account in your hands.",
                    ),
                )
            </div>
            (child)
        </section>
    })
}

/// The signed-in account's bar and the tabs, `current` among them, linking each
/// tab's page in `tabs`, then the page as `child` with its `messages`. Signing out
/// posts to `sign_out`.
#[component]
pub async fn account<'a>(
    display_name: &'a str,
    handle: &'a str,
    sign_out: &'a str,
    tabs: &'a [(Tab, &'a str)],
    current: Tab,
    #[default] messages: Messages<'a>,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <div class="row between">
            <div>
                <strong>(display_name)</strong>
                <p class="help">(format!("@{handle}"))</p>
            </div>
            <form method="post" action=(sign_out) data-submit-once="">
                <button class="text-button">"Sign out"</button>
            </form>
        </div>
        <nav class="tabs" aria-label="Account settings">
            for (tab, href) in tabs {
                <a href=(*href) aria-current=((*tab == current).then_some("page"))>(tab.label())</a>
            }
        </nav>
        if let Some(alert) = messages.alert {
            <p class="notice error" role="alert">(alert)</p>
        }
        if let Some(notice) = messages.notice {
            <p class="notice" role="status">(notice.message())</p>
        }
        (child)
    })
}

/// What a settings page shows a browser that is not signed in: a link to sign in,
/// at `sign_in`, which comes back to the page.
#[component]
pub async fn signed_out(sign_in: &str) -> Result<impl View> {
    Ok(view! {
        <div class="card stack">
            <h2>"Sign in to see your settings"</h2>
            <p>"Use your Piquel account to manage your passkeys, devices and linked providers."</p>
            <a class="button" href=(sign_in)>"Sign in"</a>
        </div>
    })
}

/// A moment, in UTC, at the precision `format` gives it.
#[component]
async fn time(at: DateTime<Utc>, format: &'static str) -> Result<impl View> {
    Ok(view! {
        <time datetime=(at.to_rfc3339())>(format!("{} UTC", at.format(format)))</time>
    })
}

/// The hidden inputs sending `fields`.
#[component]
async fn hidden(#[into] fields: Fields) -> Result<impl View> {
    let pairs = fields.pairs()?;
    Ok(view! {
        for (name, value) in &pairs {
            <input type="hidden" name=(name.as_str()) value=(value.as_str())>
        }
    })
}

/// A change posted to the page at `action`: `change` as hidden inputs, the inputs
/// the user fills in as `child`, and a button labelled `label`, of `class`, beside
/// a link back to `cancel` when there is one. With `confirm`, the SDK first
/// confirms the session with a passkey; a ceremony that fails says why in the form.
#[component]
async fn change_form<'a>(
    action: &'a str,
    #[into] change: Fields,
    #[into] label: String,
    #[default] class: &'a str,
    #[into]
    #[default]
    aria_label: Option<String>,
    #[default] confirm: bool,
    #[into]
    #[default]
    cancel: Option<String>,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <form
            method="post"
            action=(action)
            data-passkey-confirm=(confirm)
            data-submit-once=(!confirm)
        >
            hidden(fields: change)
            (child)
            if confirm {
                <p class="notice error" role="alert" data-passkey-error="" hidden=""></p>
            }
            <div class="row actions">
                <button class=(class) aria-label=(aria_label.as_deref())>(label.as_str())</button>
                if let Some(cancel) = &cancel {
                    <a class="button secondary" href=(cancel.as_str())>"Cancel"</a>
                }
            </div>
        </form>
    })
}

/// A button opening `page` with the query `opens`, by a `GET` form.
#[component]
async fn open<'a>(
    page: &'a str,
    #[into] opens: Fields,
    label: &'a str,
    #[into]
    #[default]
    aria_label: Option<String>,
    #[default] disabled: bool,
    #[default] secondary: bool,
) -> Result<impl View> {
    Ok(view! {
        <form method="get" action=(page)>
            hidden(fields: opens)
            <button
                class=(if secondary { "secondary" } else { "text-button" })
                aria-label=(aria_label.as_deref())
                disabled=(disabled)
            >
                (label)
            </button>
        </form>
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
