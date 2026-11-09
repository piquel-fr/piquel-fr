//! What the pages' forms and links send, what a page says once a change is made or
//! refused, and the parts every form is built of.
//!
//! A change posts one form to its page, naming it in the hidden `action` field.
//! Every form posts once: a double click posts it once ([`Once`]). One that needs a
//! recent passkey confirmation, while the session has none, confirms with a
//! passkey before it posts. One that a passkey ceremony makes, signing in, creating
//! an account, adding a passkey or undoing a recovery, is a [`passkey_form`], which
//! posts once the ceremony is done ([`Passkey`]). One that a link's fragment fills in
//! is a [`fragment_form`]. A row opens for editing or confirmation by a `GET` form,
//! so it works without a script.
//!
//! Each page's changes and query are types, such as [`SignInChange`] and
//! [`SignInState`]. Forms and links serialize them, and the page that receives them
//! deserializes the same types, so a field's name is written once. A field the user
//! fills in is left empty in the change a form sends as hidden inputs, and the form
//! renders its input instead.

use crate::{
    AppChange, AppSettingsState, ConnectedAppChange, ConnectedAppsState, DataChange, DataState,
    DeviceChange, EmailChange, EmailsState, FieldError, HistoryChange, HistoryState, InboxChange,
    LoginChange, LoginQuery, NewAppChange, NotificationState, ProfileChange, RecoverChange,
    SecretsChange, SignInChange, SignInState, UndoChange,
    browser::{AsyncHandler, Browser, CeremonyRequest, Fill, Refusal},
};
use chrono::{DateTime, SecondsFormat, Utc};
use piquel_common::{
    RecoveryId,
    handle::{MAX_LENGTH, MIN_LENGTH},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

pub use piquel_common::form::Checkbox;
/// Why a query could not be written as a link: one of its fields is not a name and
/// a value.
pub use serde_urlencoded::ser::Error as QueryError;
use topcoat::{
    Result,
    context::{Cx, context},
    runtime::{Event, Expr, Signal, expr, signal},
    view::{Child, View, component, element_id, view},
};

piquel_common::str_enum! {
    /// What the last change did, which the page it goes to says once.
    pub enum Notice {
        /// The handle changed.
        HandleChanged = "handle_changed",
        /// The display name changed.
        DisplayNameChanged = "display_name_changed",
        /// The profile picture changed.
        PictureChanged = "picture_changed",
        /// The profile picture was removed.
        PictureRemoved = "picture_removed",
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
            Self::DisplayNameChanged => "Your display name changed.",
            Self::PictureChanged => {
                "Your profile picture changed. Apps show it once they refresh your profile."
            }
            Self::PictureRemoved => "Your profile picture was removed.",
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
    /// The page's alert, taken out when a dialog is `shown` again, so the
    /// dialog says the refusal instead of the page behind its scrim; with no
    /// dialog open, the page keeps it.
    #[must_use]
    pub fn into_dialog(self, shown: bool) -> (Option<&'a str>, Self) {
        match self.alert {
            Some(Alert::Page(alert)) if shown => (
                Some(alert),
                Self {
                    alert: None,
                    ..self
                },
            ),
            _ => (None, self),
        }
    }

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
    /// A change of the profile.
    Profile(ProfileChange),
    /// A change of the addresses.
    Email(EmailChange),
    /// A change of the devices.
    Device(DeviceChange),
    /// A change of the account's data.
    Data(DataChange),
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
    /// A row of the account's data.
    DataRow(DataState),
    /// A page or row of the history.
    HistoryRow(HistoryState),
    /// A row of the connected apps.
    ConnectedRow(ConnectedAppsState),
    /// A change of the inbox.
    Inbox(InboxChange),
    /// A notification's page, as its query opens it.
    NotificationRow(NotificationState),
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
pub(crate) async fn time(cx: &Cx, at: DateTime<Utc>, precision: Precision) -> Result<impl View> {
    Ok(view! {
        <time datetime=(at.to_rfc3339_opts(SecondsFormat::Secs, true))>(precision.write(at))</time>
    })
}

/// The hidden inputs sending `fields`.
#[component]
pub(crate) async fn hidden(cx: &Cx, #[into] fields: Fields) -> Result<impl View> {
    let pairs = fields.pairs()?;
    Ok(view! {
        for (name, value) in &pairs {
            <input type="hidden" name=(name.as_str()) value=(value.as_str())>
        }
    })
}

/// What a form that posts once does in the browser: a second submission, such as
/// a double click, is ignored while the first is under way. Its buttons stay
/// enabled, so the clicked one still sends its value.
pub(crate) struct Once {
    /// Whether the form was submitted.
    sent: Signal<bool>,
}

impl Once {
    /// A form's, not yet submitted.
    pub(crate) fn new(cx: &Cx) -> Self {
        Self {
            sent: signal(cx, || false),
        }
    }

    /// The form's `@submit` handler.
    pub(crate) fn submit(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let sent = self.sent.clone();
        expr!(|e: Event| {
            if sent.get() {
                e.prevent_default();
            } else {
                sent.set(true);
            }
        })
    }

    /// The form's `aria-busy`, set once it is submitted.
    pub(crate) fn busy(&self) -> Expr<&'static str> {
        let sent = self.sent.clone();
        expr!(if sent.get() { "true" } else { "false" })
    }
}

/// A form posting to `action`, or to its page without one, once: its `child`
/// is its inputs and buttons, and it is of `class`. A `multipart` one sends files.
/// An `unconfirmed` one is a change the admin dashboard posts without asking for
/// its passkey confirmation, such as writing a draft, unless the button posting
/// it is marked `data-confirms`.
#[component]
pub(crate) async fn post_form<'a>(
    cx: &Cx,
    #[into]
    #[default]
    action: Option<&'a str>,
    #[into]
    #[default]
    class: Option<&'a str>,
    #[default] multipart: bool,
    #[default] unconfirmed: bool,
    child: Child<'_>,
) -> Result<impl View> {
    let once = Once::new(cx);
    Ok(view! {
        <form
            class=(class)
            method="post"
            action=(action)
            enctype=(multipart.then_some("multipart/form-data"))
            data-unconfirmed=(unconfirmed)
            @submit=(once.submit())
            :aria-busy=(once.busy())
        >
            (child)
        </form>
    })
}

/// A form auth posts once it ran a passkey [`Ceremony`] in the browser: while it
/// runs, the form is busy, its button disabled and saying so; a ceremony that
/// failed says why in the form, and leaves it to try again.
pub(crate) struct Passkey {
    /// The form's ID, which the ceremony reads the fields of and posts.
    id: String,
    /// What the ceremony sends.
    request: CeremonyRequest,
    /// Whether this browser can run it, which only the browser knows: until it
    /// says, it cannot.
    available: Signal<bool>,
    /// Whether it runs.
    busy: Signal<bool>,
    /// Why the last one failed, if it did.
    error: Signal<String>,
}

impl Passkey {
    /// The state of the form running `ceremony` at the routes `cx` holds.
    pub(crate) fn new(cx: &Cx, ceremony: Ceremony<'_>) -> Self {
        Self {
            id: element_id(cx),
            request: ceremony.request(context::<PasskeyRoutes>(cx)),
            available: signal(cx, || false),
            busy: signal(cx, || false),
            error: signal(cx, String::new),
        }
    }

    /// The form's ID.
    pub(crate) fn id(&self) -> String {
        self.id.clone()
    }

    /// The form's `@mount` handler, which finds whether the browser can run the
    /// ceremony.
    pub(crate) fn mount(&self) -> Expr<impl FnOnce(Event) + use<>> {
        let (available, passkeys) = (self.available.clone(), Browser::passkeys());
        expr!(|_e: Event| available.set(passkeys))
    }

    /// The form's `@submit` handler, which runs the ceremony once at a time.
    pub(crate) fn submit(&self) -> Expr<impl AsyncHandler + use<>> {
        let (busy, error) = (self.busy.clone(), self.error.clone());
        let ceremony = Browser::ceremony(Some(&self.id), &self.request, &Expr::from(String::new()));
        expr!(async |e: Event| {
            e.prevent_default();
            if !busy.get() {
                busy.set(true);
                error.set("".to_owned());
                let outcome = raw!("await ${ceremony}", Ok::<String, Refusal>(String::new()));
                if outcome.is_err() {
                    busy.set(false);
                    error.set(outcome.unwrap_err().message);
                }
            }
        })
    }

    /// The form's `aria-busy`, set while the ceremony runs.
    pub(crate) fn busy(&self) -> Expr<&'static str> {
        let busy = self.busy.clone();
        expr!(if busy.get() { "true" } else { "false" })
    }

    /// Whether the form's button is disabled: while the ceremony runs, and, when
    /// `gated`, until the browser is known to run it.
    pub(crate) fn disabled(&self, gated: bool) -> Expr<bool> {
        let (busy, available) = (self.busy.clone(), self.available.clone());
        expr!(if busy.get() {
            true
        } else if gated {
            !available.get()
        } else {
            false
        })
    }

    /// The form's button's label: `label`, or that the ceremony waits for the
    /// passkey while it runs.
    pub(crate) fn label(&self, label: &str) -> Expr<String> {
        let (busy, label) = (self.busy.clone(), label.to_owned());
        expr!(if busy.get() {
            "Waiting for your passkey…".to_owned()
        } else {
            label
        })
    }

    /// The alert saying why the last ceremony failed, hidden until one does.
    pub(crate) fn alert<'a>(&self, cx: &'a Cx) -> Child<'a> {
        let error = self.error.clone();
        Child::new(view! {
            <p class="notice error" role="alert" :hidden=$(error.get().is_empty())>$(error.get())</p>
        })
    }

    /// The note saying why the button stays disabled, `unavailable`, hidden once
    /// the browser is known to run the ceremony.
    pub(crate) fn unavailable<'a>(&self, cx: &'a Cx, unavailable: &'static str) -> Child<'a> {
        let available = self.available.clone();
        Child::new(view! {
            <p class="help" :hidden=$(available.get())>(unavailable)</p>
        })
    }
}

/// A change posted to the page at `action`: `change` as hidden inputs, the inputs
/// the user fills in as `child`, the reason an administrator gives when `reason`
/// asks for one, holding what they typed last, and a button labelled `label`, of
/// `class`, beside a link back to `cancel` when there is one. It posts once; with
/// `confirm`, it first confirms the session with a passkey, and a ceremony that
/// fails says why in the form.
#[component]
pub(crate) async fn change_form<'a>(
    cx: &Cx,
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
    let fields = view! {
        hidden(fields: change)
        (child)
        if let Some(reason) = reason {
            <label>
                "Reason, shown to the owner in their history"
                <input name="reason" required="" maxlength="500" value=(reason)>
            </label>
        }
    };
    let cancel = view! {
        if let Some(cancel) = &cancel {
            <a class="button secondary" href=(cancel.as_str())>"Cancel"</a>
        }
    };
    Ok(view! {
        if confirm {
            let passkey = Passkey::new(cx, Ceremony::Confirm);
            <form
                id=(passkey.id())
                method="post"
                action=(action)
                @submit=(passkey.submit())
                :aria-busy=(passkey.busy())
            >
                (fields)
                (passkey.alert(cx))
                <div class="row actions">
                    <button class=(class) aria-label=(aria_label.as_deref()) :disabled=(passkey.disabled(false))>
                        (passkey.label(&label))
                    </button>
                    (cancel)
                </div>
            </form>
        } else {
            post_form(action: action,
                (fields)
                <div class="row actions">
                    <button class=(class) aria-label=(aria_label.as_deref())>(label.as_str())</button>
                    (cancel)
                </div>
            )
        }
    })
}

/// A passkey ceremony a [`Passkey`] form runs before it posts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ceremony<'a> {
    /// Signing in, with the form's `handle`, if any, or the browser's account
    /// picker.
    SignIn,
    /// Creating an account with its first passkey, from the form's `handle`,
    /// `friendly_name`, `passkey_kind`, `invitation` and `pending_signup`.
    Register,
    /// Adding a passkey to the signed-in account, from the form's `friendly_name`
    /// and `passkey_kind`, confirming first if it must.
    Enroll,
    /// Adding a passkey with a recovery link, which signs the browser in, from the
    /// form's `friendly_name` and `passkey_kind`. The link's `token` rides in the
    /// ceremony rather than in an input, so the form's post never sends it again.
    Recover {
        /// The recovery link's token.
        token: &'a str,
    },
    /// Undoing the `recovery` with a passkey the account had before it; the form
    /// posts whether that signed the browser in, in its `signed_in` input, since
    /// the session cookie is `HttpOnly`.
    Undo {
        /// The recovery.
        recovery: RecoveryId,
    },
    /// Confirming the session, for a change that needs a recent passkey.
    Confirm,
    /// Proving a passkey in the ceremony `start` starts; the form posts the proof
    /// in its `assertion` input, and its page verifies it. The session stays as it
    /// was: the proof counts only for that form.
    Prove {
        /// Where the ceremony starts.
        start: &'a str,
    },
}

/// A passkey ceremony's routes on auth: where it starts, which answers its
/// `WebAuthn` options, and where it finishes, which takes the credential.
#[derive(Clone, Copy, Debug)]
pub struct CeremonyRoutes {
    /// Where it starts.
    pub start: &'static str,
    /// Where it finishes.
    pub finish: &'static str,
}

/// Where auth runs the passkey ceremonies its forms ask for. Auth's router keeps
/// it in every page's context, where passkey forms read it.
#[derive(Clone, Copy, Debug)]
pub struct PasskeyRoutes {
    /// Signing in.
    pub sign_in: CeremonyRoutes,
    /// Creating an account.
    pub register: CeremonyRoutes,
    /// Adding a passkey to the signed-in account.
    pub enroll: CeremonyRoutes,
    /// Confirming the session.
    pub confirm: CeremonyRoutes,
    /// Adding a passkey with a recovery link.
    pub recover: CeremonyRoutes,
    /// Undoing a recovery.
    pub undo: CeremonyRoutes,
}

impl Ceremony<'_> {
    /// What the browser sends to run it at `routes`.
    fn request(self, routes: &PasskeyRoutes) -> CeremonyRequest {
        let run = |routes: CeremonyRoutes, create: bool| CeremonyRequest {
            start: routes.start.to_owned(),
            finish: Some(routes.finish.to_owned()),
            create,
            fields: &[],
            finish_fields: &[],
            fixed: serde_json::Map::new(),
            confirm: None,
            fill: None,
            submit: true,
            start_only: false,
        };
        let fixed = |name: &str, value: String| {
            serde_json::Map::from_iter([(name.to_owned(), serde_json::Value::String(value))])
        };
        match self {
            Self::SignIn => CeremonyRequest {
                fields: &["handle"],
                ..run(routes.sign_in, false)
            },
            Self::Register => CeremonyRequest {
                fields: &["handle", "passkey_kind", "invitation", "pending_signup"],
                finish_fields: &["friendly_name"],
                ..run(routes.register, true)
            },
            Self::Enroll => CeremonyRequest {
                fields: &["passkey_kind"],
                finish_fields: &["friendly_name"],
                confirm: Some((
                    routes.confirm.start.to_owned(),
                    routes.confirm.finish.to_owned(),
                )),
                ..run(routes.enroll, true)
            },
            Self::Recover { token } => CeremonyRequest {
                fields: &["passkey_kind"],
                finish_fields: &["friendly_name"],
                fixed: fixed("token", token.to_owned()),
                ..run(routes.recover, true)
            },
            Self::Undo { recovery } => CeremonyRequest {
                fixed: fixed("recovery_id", recovery.to_string()),
                fill: Some(Fill {
                    input: "signed_in",
                    field: Some("signed_in"),
                }),
                ..run(routes.undo, false)
            },
            Self::Confirm => run(routes.confirm, false),
            Self::Prove { start } => CeremonyRequest {
                start: start.to_owned(),
                finish: None,
                fill: Some(Fill {
                    input: "assertion",
                    field: None,
                }),
                ..run(routes.confirm, false)
            },
        }
    }

    /// Why the form's button stays disabled, until the browser is known to run
    /// the ceremony.
    pub(crate) const fn unavailable(self) -> &'static str {
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
            Self::Confirm | Self::Prove { .. } => {
                "Confirming needs a browser that supports passkeys, with scripts allowed."
            }
        }
    }
}

/// A change posted to the page at `action` once the browser ran the passkey
/// `ceremony`: `change` as hidden inputs, the inputs the ceremony reads as
/// `child`, and a button labelled `label`, of `class`. The button stays disabled,
/// and says so, until the browser is known to run the ceremony.
#[component]
pub(crate) async fn passkey_form<'a>(
    cx: &Cx,
    action: &'a str,
    ceremony: Ceremony<'a>,
    #[into] change: Fields,
    label: &'a str,
    #[default] class: &'a str,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    let passkey = Passkey::new(cx, ceremony);
    Ok(view! {
        <form
            id=(passkey.id())
            class="stack"
            method="post"
            action=(action)
            @mount=(passkey.mount())
            @submit=(passkey.submit())
            :aria-busy=(passkey.busy())
        >
            hidden(fields: change)
            (child)
            (passkey.alert(cx))
            (passkey.unavailable(cx, ceremony.unavailable()))
            <button class=(class) :disabled=(passkey.disabled(true))>(passkey.label(label))</button>
        </form>
    })
}

/// The inputs of a [`passkey_form`] creating a passkey: its name, labelled
/// `label` and starting as `value`, if any, and, on `android`, whose browsers may
/// save it with Google Password Manager, where it is saved.
#[component]
pub(crate) async fn new_passkey<'a>(
    cx: &Cx,
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
/// for each of `fragments`, named as the fragment names it, which the browser fills
/// in from the fragment as it posts the form, once, dropping the fragment from the
/// address. The form holds `child`, and a button labelled `label`, which stays
/// disabled without scripts, as the note `unavailable` says. It shows, with its
/// button enabled, while the link has every value, following the fragment as it
/// changes; otherwise `missing` shows instead, as after a post that failed, whose
/// `alert` says why: the fragment is gone by then. With `alert_replaces_missing`,
/// the alert says why alone.
#[component]
pub(crate) async fn fragment_form<'a>(
    cx: &Cx,
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
    let id = element_id(cx);
    let once = Once::new(cx);
    // The fragment, once the browser read it: only it sees the fragment.
    let (fragment, read) = (signal(cx, String::new), signal(cx, || false));
    let complete = Browser::fragment_holds(fragments, &expr!(fragment.get()));
    let (link, follow) = (Browser::fragment(), Browser::follow_fragment(&fragment));
    let (fill, drop) = (Browser::fill_from_fragment(&id), Browser::drop_fragment());
    let sent = once.sent.clone();
    Ok(view! {
        if let Some(alert) = alert {
            <p class="notice error" role="alert">(alert)</p>
        }
        <form
            id=(id.as_str())
            class="card stack"
            method="post"
            action=(action)
            :aria-busy=(once.busy())
            :hidden=$(if read.get() { !complete } else { false })
            @mount=$(|_e: Event| {
                fragment.set(link);
                read.set(true);
                let _followed = follow;
            })
            @submit=$(|e: Event| {
                if sent.get() {
                    e.prevent_default();
                } else {
                    sent.set(true);
                    let _filled = fill;
                    let _dropped = drop;
                }
            })
        >
            hidden(fields: change)
            for name in fragments {
                <input type="hidden" name=(*name) data-fragment=(*name)>
            }
            (child)
            <p class="help" :hidden=$(read.get())>(unavailable)</p>
            <button :disabled=$(if read.get() { !complete } else { true })>(label)</button>
        </form>
        if !(alert_replaces_missing && alert.is_some()) {
            <div class="card stack" :hidden=$(if read.get() { complete } else { true })>(missing)</div>
        }
    })
}

/// An account's handle, as a passkey ceremony and the handle's settings send it:
/// a `new` one, which creating an account or changing the handle checks against the
/// handle rules, or one to sign in with. It shows `value`, if any, and takes the
/// focus with `focus`.
#[component]
pub(crate) async fn handle_input<'a>(
    cx: &Cx,
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

/// A button opening `page` with the query `opens`, by a `GET` form: a quiet
/// text button, a `secondary` one, or a `danger` one for a removal.
#[component]
pub(crate) async fn open<'a>(
    cx: &Cx,
    page: &'a str,
    #[into] opens: Fields,
    label: &'a str,
    #[into]
    #[default]
    aria_label: Option<String>,
    #[default] disabled: bool,
    #[default] secondary: bool,
    #[default] danger: bool,
) -> Result<impl View> {
    let class = if danger {
        "danger small"
    } else if secondary {
        "secondary small"
    } else {
        "text-button"
    };
    Ok(view! {
        <form method="get" action=(page)>
            hidden(fields: opens)
            <button class=(class) aria-label=(aria_label.as_deref()) disabled=(disabled)>
                (label)
            </button>
        </form>
    })
}

/// What a page says, and where.
#[cfg(test)]
mod tests {
    use super::{Alert, Messages};

    /// A dialog shown again says the page's alert instead of the page behind its
    /// scrim; with no dialog shown, the page keeps it.
    #[test]
    fn a_dialog_shown_again_takes_the_page_alert() {
        let refused = Messages::alert(Alert::Page("Refused"));
        let (said, page) = refused.into_dialog(true);
        assert_eq!(said, Some("Refused"));
        assert!(page.alert.is_none());
        let (said, page) = refused.into_dialog(false);
        assert_eq!(said, None);
        assert!(matches!(page.alert, Some(Alert::Page("Refused"))));
    }
}
