//! What the account's pages' forms and links send, what a page says once a change
//! is made or refused, and the parts every form is built of.
//!
//! A change posts one form to its page, naming it in the hidden `action` field.
//! One that needs a recent passkey confirmation is marked `data-passkey-confirm`
//! while the session has none, and the SDK confirms before posting it; every other
//! form is marked `data-submit-once`, so a double click posts it once. A row opens
//! for editing or confirmation by a `GET` form, so it works without a script.
//!
//! Each page's changes and query are types, such as [`SignInChange`] and
//! [`SignInState`]. Forms and links serialize them, and the page that receives them
//! deserializes the same types, so a field's name is written once. A field the user
//! fills in is left empty in the change a form sends as hidden inputs, and the form
//! renders its input instead.

use crate::{
    AppChange, AppSettingsState, DeviceChange, EmailChange, EmailsState, FieldError, HistoryChange,
    HistoryState, NewAppChange, SecretsChange, SignInChange, SignInState,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::IgnoredAny};
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

piquel_common::str_enum! {
    /// What the last change did, which the page it goes to says once.
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
        /// A public app was registered.
        ClientRegistered = "client_registered",
        /// An app's settings were saved.
        ClientSaved = "client_saved",
        /// An app was enabled.
        ClientEnabled = "client_enabled",
        /// An app was disabled.
        ClientDisabled = "client_disabled",
        /// An app was deleted.
        ClientDeleted = "client_deleted",
    }
}

impl Notice {
    /// What the page says.
    pub(crate) const fn message(self) -> &'static str {
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
            Self::ClientRegistered => "The app was registered.",
            Self::ClientSaved => "Your changes were saved.",
            Self::ClientEnabled => "The app was enabled.",
            Self::ClientDisabled => "The app was disabled.",
            Self::ClientDeleted => "The app was deleted.",
        }
    }
}

/// What a page says when its form came from an older page and does not decode.
pub const OUT_OF_DATE: &str = "This page was out of date. Try again.";

/// Why the change just posted failed.
#[derive(Clone, Copy, Debug)]
pub enum Alert<'a> {
    /// Said above the page.
    Page(&'a str),
    /// Said beside the input of the setting refused, which the page's form shows
    /// again.
    Field(FieldError<'a>),
}

/// What a page says: the last change's `notice`, and the `alert` of a change that
/// failed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Messages<'a> {
    /// What the last change did.
    pub notice: Option<Notice>,
    /// Why the change just posted failed.
    pub alert: Option<Alert<'a>>,
}

impl<'a> Messages<'a> {
    /// Only an `alert`.
    #[must_use]
    pub const fn alert(alert: Alert<'a>) -> Self {
        Self {
            notice: None,
            alert: Some(alert),
        }
    }

    /// The setting the change just posted was refused for, which its form shows
    /// beside its input.
    #[must_use]
    pub const fn field_error(&self) -> Option<FieldError<'a>> {
        match self.alert {
            Some(Alert::Field(error)) => Some(error),
            Some(Alert::Page(_)) | None => None,
        }
    }
}

/// A page's query: which history it shows and which of its rows are open. Its
/// links and `GET` forms serialize it, and the page deserializes it back, so both
/// name the same parameters.
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
        pub(crate) enum Fields {
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
    /// A registration of an app.
    NewApp(NewAppChange),
    /// A change of an app's settings.
    App(AppChange),
    /// A change of an app's secrets.
    Secrets(SecretsChange),
    /// A row of the sign-in methods.
    SignInRow(SignInState),
    /// A row of the addresses.
    EmailRow(EmailsState),
    /// A page or row of the history.
    HistoryRow(HistoryState),
    /// A row of an app's settings.
    AppRow(AppSettingsState),
}

impl Fields {
    /// The name-value pairs the form sends, as its hidden inputs hold them.
    fn pairs(&self) -> Result<Vec<(String, String)>> {
        let encoded = serde_urlencoded::to_string(self)?;
        Ok(serde_urlencoded::from_str(&encoded)?)
    }
}

/// A checkbox, or a flag a query sets by its name alone: checked when the form
/// sends its name, whatever the value, since browsers send nothing for an unchecked
/// one. It decodes from text, as a change's fields must, where a `bool` would not.
/// It is checked as `on`, as browsers send it; leave it out of a form or link with
/// `#[serde(default, skip_serializing_if = "Checkbox::is_off")]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Checkbox(pub bool);

impl Checkbox {
    /// Whether it is unchecked, so its form sends nothing.
    #[must_use]
    pub const fn is_off(&self) -> bool {
        !self.0
    }
}

impl Serialize for Checkbox {
    /// Writes `on` when checked, as browsers send it.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.then_some("on").serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Checkbox {
    /// Checked, whatever the value: an unchecked box is not sent at all.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        IgnoredAny::deserialize(deserializer).map(|_| Self(true))
    }
}

/// Values typed one per line, as a textarea sends them. Blank lines and the
/// spaces around each value, a browser's `\r` included, are dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lines(Vec<String>);

impl Lines {
    /// Whether no value was typed.
    pub(crate) const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The values, one per line, as the textarea shows them.
    pub(crate) fn text(&self) -> String {
        self.0.join("\n")
    }
}

impl From<&str> for Lines {
    /// The values typed in `text`, one per line.
    fn from(text: &str) -> Self {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

impl FromIterator<String> for Lines {
    /// The values, as they are.
    fn from_iter<I: IntoIterator<Item = String>>(values: I) -> Self {
        Self(values.into_iter().collect())
    }
}

impl From<Lines> for Vec<String> {
    /// The values.
    fn from(lines: Lines) -> Self {
        lines.0
    }
}

impl Serialize for Lines {
    /// Writes the values one per line.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text())
    }
}

impl<'de> Deserialize<'de> for Lines {
    /// Reads the values typed one per line.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self::from(text.as_str()))
    }
}

/// How precisely [`time`] writes a moment.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Precision {
    /// Its day.
    Day,
    /// Its day and minute.
    Minute,
    /// Its minute alone, under a heading naming its day.
    Clock,
}

impl Precision {
    /// The `strftime` format writing a moment this precisely.
    const fn format(self) -> &'static str {
        match self {
            Self::Day => "%-d %b %Y",
            Self::Minute => "%-d %b %Y %H:%M",
            Self::Clock => "%H:%M",
        }
    }
}

/// A moment, in UTC, at `precision`. Its `datetime` is to the second, as HTML
/// allows no more than three fractional digits.
#[component]
pub(crate) async fn time(at: DateTime<Utc>, precision: Precision) -> Result<impl View> {
    Ok(view! {
        <time datetime=(at.to_rfc3339_opts(SecondsFormat::Secs, true))>
            (format!("{} UTC", at.format(precision.format())))
        </time>
    })
}

/// The hidden inputs sending `fields`.
#[component]
pub(crate) async fn hidden(#[into] fields: Fields) -> Result<impl View> {
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
pub(crate) async fn change_form<'a>(
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
pub(crate) async fn open<'a>(
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
