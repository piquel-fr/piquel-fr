//! What the pages' forms and links send, what a page says once a change is made or
//! refused, and the parts every form is built of.
//!
//! A change posts one form to its page, naming it in the hidden `action` field.
//! One that needs a recent passkey confirmation is marked `data-passkey-confirm`
//! while the session has none, and the passkey script confirms before posting it.
//! One that a passkey ceremony makes, signing in, creating an account, adding a
//! passkey or undoing a recovery, is a [`passkey_form`], which the passkey script
//! posts once the ceremony is done. One that a link's fragment fills in is a
//! [`fragment_form`]. Every other form is marked `data-submit-once`, so a double
//! click posts it once. A row opens for editing or confirmation by a `GET` form, so
//! it works without a script.
//!
//! Each page's changes and query are types, such as [`SignInChange`] and
//! [`SignInState`]. Forms and links serialize them, and the page that receives them
//! deserializes the same types, so a field's name is written once. A field the user
//! fills in is left empty in the change a form sends as hidden inputs, and the form
//! renders its input instead.

use crate::{
    AppChange, AppSettingsState, ConnectedAppChange, ConnectedAppsState, DeviceChange, EmailChange,
    EmailsState, FieldError, HistoryChange, HistoryState, LoginChange, LoginQuery, NewAppChange,
    RecoverChange, SecretsChange, SignInChange, SignInState, UndoChange,
};
use chrono::{DateTime, SecondsFormat, Utc};
use piquel_common::{
    RecoveryId,
    handle::{MAX_LENGTH, MIN_LENGTH},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::IgnoredAny};
use std::str::FromStr;

/// Why a query could not be written as a link: one of its fields is not a name and
/// a value.
pub use serde_urlencoded::ser::Error as QueryError;
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

piquel_common::str_enum! {
    /// What the last change did, which the page it goes to says once.
    pub enum Notice {
        /// The handle changed.
        HandleChanged = "handle_changed",
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
        /// An app's access was removed.
        AppRemoved = "app_removed",
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
        /// A recovery link added a passkey, which signed the browser in.
        Recovered = "recovered",
        /// A recovery was undone: its link cancelled, and what the link did, if it
        /// was used, taken back.
        RecoveryUndone = "recovery_undone",
    }
}

impl Notice {
    /// What the page says.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::HandleChanged => "Your handle changed.",
            Self::PasskeyAdded => "The passkey was added.",
            Self::PasskeyRenamed => "The passkey was renamed.",
            Self::PasskeyRemoved => "The passkey was removed.",
            Self::IdentityUnlinked => "The social sign-in was unlinked.",
            Self::EmailAdded => "We sent a confirmation link. Open it to confirm the address.",
            Self::EmailPrimary => "Your primary address changed. We told your previous one.",
            Self::EmailRemoved => "The address was removed.",
            Self::DeviceSignedOut => "The device was signed out.",
            Self::OthersSignedOut => "Your other devices were signed out.",
            Self::AppRemoved => "The app no longer has access to your account.",
            Self::ClientRegistered => "The app was registered.",
            Self::ClientSaved => "Your changes were saved.",
            Self::ClientEnabled => "The app was enabled.",
            Self::ClientDisabled => "The app was disabled.",
            Self::ClientDeleted => "The app was deleted.",
            Self::Recovered => "Your account is recovered. Your new passkey signs you in.",
            Self::RecoveryUndone => {
                "The recovery is undone. Its link no longer works, and if it was used, its passkey is removed, every device is signed out, and apps ask for access again."
            }
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

/// A page's query, such as which of its rows are open, or where a sign-in goes on
/// to. Its links and `GET` forms serialize it, and the page deserializes it back, so
/// both name the same parameters.
pub trait Query: Serialize {
    /// The link to `page` with this query.
    ///
    /// # Errors
    ///
    /// Fails if the query does not serialize as name-value pairs.
    fn on(&self, page: &str) -> std::result::Result<String, QueryError> {
        let query = serde_urlencoded::to_string(self)?;
        Ok(if query.is_empty() {
            page.to_owned()
        } else {
            format!("{page}?{query}")
        })
    }

    /// The URL of `page` on the origin of `base`, with this query: a link to
    /// another origin's page.
    ///
    /// # Errors
    ///
    /// Fails if the query does not serialize as name-value pairs.
    fn url(&self, base: &url::Url, page: &str) -> std::result::Result<url::Url, QueryError> {
        let query = serde_urlencoded::to_string(self)?;
        let mut url = base.clone();
        url.set_path(page);
        url.set_query((!query.is_empty()).then_some(query.as_str()));
        Ok(url)
    }
}

impl Query for () {}

/// Defines [`Fields`], with a conversion from each type a form or link sends.
macro_rules! fields {
    ($($(#[$doc:meta])* $variant:ident($type:ty)),* $(,)?) => {
        /// What a form sends: a page's change, the query opening a page or one of
        /// its rows, or nothing but its inputs.
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
    /// A change made on a sign-in page.
    Login(LoginChange),
    /// A change of the sign-in methods.
    SignIn(SignInChange),
    /// A change of the addresses.
    Email(EmailChange),
    /// A change of the devices.
    Device(DeviceChange),
    /// A change of the history.
    History(HistoryChange),
    /// A change of the connected apps.
    Connected(ConnectedAppChange),
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
    /// A row of the connected apps.
    ConnectedRow(ConnectedAppsState),
    /// A row of an app's settings.
    AppRow(AppSettingsState),
    /// A sign-in page, as its query opens it.
    LoginPage(LoginQuery),
    /// A change made on a recovery link's page.
    Recover(RecoverChange),
    /// A change made on a recovery's undo page.
    Undo(UndoChange),
    /// Nothing: the form sends only its inputs.
    Inputs(()),
}

impl Fields {
    /// The name-value pairs the form sends, as its hidden inputs hold them.
    fn pairs(&self) -> Result<Vec<(String, String)>> {
        let encoded = serde_urlencoded::to_string(self)?;
        Ok(serde_urlencoded::from_str(&encoded)?)
    }

    /// Reads a field as `T`, or as absent when it does not parse: the
    /// `deserialize_with` of a field a link or form may get wrong.
    pub(crate) fn lenient<'de, D: Deserializer<'de>, T: FromStr>(
        deserializer: D,
    ) -> std::result::Result<Option<T>, D::Error> {
        Ok(Option::<String>::deserialize(deserializer)?.and_then(|value| value.parse().ok()))
    }

    /// [`Self::lenient`], reading a field that does not parse as `T`'s default.
    pub(crate) fn lenient_or_default<'de, D: Deserializer<'de>, T: FromStr + Default>(
        deserializer: D,
    ) -> std::result::Result<T, D::Error> {
        Ok(Self::lenient(deserializer)?.unwrap_or_default())
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

    /// The moment `at`, in UTC, this precisely, as text where a [`time`] cannot
    /// go, such as a title.
    pub(crate) fn write(self, at: DateTime<Utc>) -> String {
        format!("{} UTC", at.format(self.format()))
    }
}

/// A moment, in UTC, at `precision`. Its `datetime` is to the second, as HTML
/// allows no more than three fractional digits.
#[component]
pub(crate) async fn time(at: DateTime<Utc>, precision: Precision) -> Result<impl View> {
    Ok(view! {
        <time datetime=(at.to_rfc3339_opts(SecondsFormat::Secs, true))>(precision.write(at))</time>
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
/// the user fills in as `child`, the reason an administrator gives when `reason`
/// asks for one, holding what they typed last, and a button labelled `label`, of `class`, beside a link back to
/// `cancel` when there is one. With `confirm`, the passkey script first confirms
/// the session with a passkey; a ceremony that fails says why in the form.
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
    reason: Option<&'a str>,
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
            if let Some(reason) = reason {
                <label>
                    "Reason, shown to the owner in their history"
                    <input name="reason" required="" maxlength="500" value=(reason)>
                </label>
            }
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

/// A passkey ceremony the passkey script runs before posting a [`passkey_form`],
/// named by the form's marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ceremony<'a> {
    /// Signing in, with the form's `handle`, if any, or the browser's account
    /// picker: `data-passkey-sign-in`.
    SignIn,
    /// Creating an account with its first passkey, from the form's `handle`,
    /// `friendly_name`, `passkey_kind`, `invitation` and `pending_signup`:
    /// `data-passkey-register`.
    Register,
    /// Adding a passkey to the signed-in account, from the form's `friendly_name`
    /// and `passkey_kind`, confirming first if it must: `data-passkey-enroll`.
    Enroll,
    /// Adding a passkey with a recovery link, which signs the browser in, from the
    /// form's `friendly_name` and `passkey_kind`: `data-passkey-recover`, whose
    /// value is the link's `token`. The token rides in the marker rather than in an
    /// input, so the form's post never sends it again.
    Recover {
        /// The recovery link's token.
        token: &'a str,
    },
    /// Undoing the `recovery` with a passkey the account had before it:
    /// `data-passkey-undo`, whose value is the recovery's ID.
    Undo {
        /// The recovery.
        recovery: RecoveryId,
    },
}

impl Ceremony<'_> {
    /// Why the form's button stays disabled, until the passkey script finds the
    /// browser can run the ceremony.
    const fn unavailable(self) -> &'static str {
        match self {
            Self::SignIn | Self::Register => {
                "Passkeys need a supported browser and a secure connection, with scripts allowed. Open this page in Safari, Chrome, or another browser with passkey support."
            }
            Self::Enroll => {
                "Adding a passkey needs a browser that supports them, with scripts allowed."
            }
            Self::Recover { .. } => {
                "Recovering needs a browser that supports passkeys, with scripts allowed."
            }
            Self::Undo { .. } => {
                "Undoing needs a browser that supports passkeys, with scripts allowed."
            }
        }
    }
}

/// A change posted to the page at `action` once the passkey script ran the passkey
/// `ceremony`: `change` as hidden inputs, the inputs the ceremony reads as `child`,
/// and a button labelled `label`, of `class`. The button stays disabled, and says
/// so, until the passkey script finds the browser can run the ceremony; a ceremony
/// that fails says why in the form.
#[component]
pub(crate) async fn passkey_form<'a>(
    action: &'a str,
    ceremony: Ceremony<'a>,
    #[into] change: Fields,
    label: &'a str,
    #[default] class: &'a str,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    let (recover, undo) = match ceremony {
        Ceremony::Recover { token } => (Some(token), None),
        Ceremony::Undo { recovery } => (None, Some(recovery.to_string())),
        Ceremony::SignIn | Ceremony::Register | Ceremony::Enroll => (None, None),
    };
    Ok(view! {
        <form
            class="stack"
            method="post"
            action=(action)
            data-passkey-sign-in=(ceremony == Ceremony::SignIn)
            data-passkey-register=(ceremony == Ceremony::Register)
            data-passkey-enroll=(ceremony == Ceremony::Enroll)
            data-passkey-recover=(recover)
            data-passkey-undo=(undo.as_deref())
        >
            hidden(fields: change)
            (child)
            <p class="notice error" role="alert" data-passkey-error="" hidden=""></p>
            <p class="help" data-unavailable="">(ceremony.unavailable())</p>
            <button class=(class) disabled="">(label)</button>
        </form>
    })
}

/// The inputs of a [`passkey_form`] creating a passkey: its name, labelled
/// `label` and starting as `value`, if any, and, on `android`, whose browsers may
/// save it with Google Password Manager, where it is saved.
#[component]
pub(crate) async fn new_passkey<'a>(
    label: &'a str,
    #[into]
    #[default]
    value: Option<&'a str>,
    android: bool,
) -> Result<impl View> {
    Ok(view! {
        <label>
            (label)
            <input name="friendly_name" value=(value) maxlength="80" required="" autocomplete="off">
        </label>
        if android {
            <label>
                "Save this passkey with"
                <select name="passkey_kind">
                    <option value="standard">"Passkey or security key"</option>
                    <option value="google_password_manager">"Google Password Manager on this device"</option>
                </select>
            </label>
            <p class="help">"Choose Google Password Manager only if it is available on this Android device."</p>
        }
    })
}

/// A change posted to the page at `action` with values a link carries in its
/// fragment, which never reaches a server: `change` as hidden inputs, then an input
/// for each of `fragments`, named as the fragment names it, which the passkey
/// script fills in from the fragment as it posts the form, dropping the fragment
/// from the address. The form holds `child`, and a button labelled `label`, which
/// stays disabled without scripts, as the note `unavailable` says. It shows, with
/// its button enabled, while the link has every value; otherwise `missing` shows
/// instead, as after a post that failed, whose `alert` says why: the fragment is
/// gone by then. With `alert_replaces_missing`, the alert says why alone.
#[component]
pub(crate) async fn fragment_form<'a>(
    action: &'a str,
    #[into] change: Fields,
    fragments: &'a [&'a str],
    label: &'a str,
    unavailable: &'a str,
    #[default] alert: Option<&'a str>,
    #[default] alert_replaces_missing: bool,
    #[into] missing: Child<'_>,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        if let Some(alert) = alert {
            <p class="notice error" role="alert">(alert)</p>
        }
        <form class="card stack" method="post" action=(action) data-submit-once="" data-fragment-form="">
            hidden(fields: change)
            for name in fragments {
                <input type="hidden" name=(*name) data-fragment=(*name)>
            }
            (child)
            <p class="help" data-unavailable="">(unavailable)</p>
            <button disabled="">(label)</button>
        </form>
        if !(alert_replaces_missing && alert.is_some()) {
            <div class="card stack" data-fragment-missing="" hidden="">(missing)</div>
        }
    })
}

/// An account's handle, as the passkey script and the handle's settings send it:
/// a `new` one, which creating an account or changing the handle checks against the
/// handle rules, or one to sign in with. It shows `value`, if any, and takes the
/// focus with `focus`.
#[component]
pub(crate) async fn handle_input<'a>(
    new: bool,
    #[default] value: Option<&'a str>,
    #[default] focus: bool,
) -> Result<impl View> {
    Ok(view! {
        <label>
            "Handle"
            <input
                name="handle"
                value=(value)
                autocomplete=(if new { "username" } else { "username webauthn" })
                autocapitalize="none"
                spellcheck="false"
                pattern=(new.then_some("[a-z0-9]+(-[a-z0-9]+)*"))
                minlength=(MIN_LENGTH.to_string())
                maxlength=(MAX_LENGTH.to_string())
                required=""
                autofocus=(focus)
                aria-describedby=(new.then_some("handle-rules"))
            >
        </label>
        if new {
            <small id="handle-rules">
                (format!("{MIN_LENGTH}–{MAX_LENGTH} lowercase letters, numbers, or single hyphens between them."))
            </small>
        }
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
