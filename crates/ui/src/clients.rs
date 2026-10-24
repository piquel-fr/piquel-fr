//! An OIDC client as the pages managing it show it: its status, its facts, the
//! form of its settings, its secrets and the one just made. The developer console
//! shows an account's own apps with these, and the admin dashboard will show every
//! client with them.

use crate::form::{Checkbox, Fields, Lines, Precision, change_form, time};
use chrono::{DateTime, Utc};
use piquel_common::{
    ClientId,
    clients::{ClientField, ClientKind},
    protocol::oauth::Scope,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};
use topcoat::{
    Result,
    view::{Child, View, component, view},
};

/// Whether a client signs users in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientStatus {
    /// An administrator suspended it, and it stays disabled until they lift that.
    Suspended {
        /// When.
        at: DateTime<Utc>,
    },
    /// Its owner disabled it.
    Disabled,
    /// It signs users in.
    Enabled,
}

impl ClientStatus {
    /// The status of a client `enabled` or not, and suspended at `suspended_at`, if
    /// ever: a suspension comes first.
    #[must_use]
    pub const fn of(enabled: bool, suspended_at: Option<DateTime<Utc>>) -> Self {
        match (suspended_at, enabled) {
            (Some(at), _) => Self::Suspended { at },
            (None, false) => Self::Disabled,
            (None, true) => Self::Enabled,
        }
    }

    /// The status in words.
    pub(crate) const fn state(self) -> &'static str {
        match self {
            Self::Suspended { .. } => "Suspended by an administrator",
            Self::Disabled => "Disabled",
            Self::Enabled => "Enabled",
        }
    }
}

/// A client, as the pages show it.
#[derive(Clone, Copy, Debug)]
pub struct ClientRow<'a> {
    /// Its ID.
    pub id: &'a ClientId,
    /// The name consent screens show.
    pub name: &'a str,
    /// Whether it keeps a secret.
    pub kind: ClientKind,
    /// Whether it signs users in.
    pub status: ClientStatus,
    /// Its authorization callbacks.
    pub redirect_uris: &'a [String],
    /// The pages the browser may return to after logout.
    pub post_logout_uris: &'a [String],
    /// The scopes it may request.
    pub allowed_scopes: &'a [String],
    /// Whether it may receive refresh tokens.
    pub allow_refresh: bool,
    /// Whether it must push its authorization requests.
    pub require_pushed_authorization_requests: bool,
    /// Where logout tokens are posted, if anywhere.
    pub backchannel_logout_uri: Option<&'a str>,
    /// When a token was last issued to it, if ever.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ClientRow<'_> {
    /// What its kind means for its owner.
    pub(crate) const fn kind_name(&self) -> &'static str {
        match self.kind {
            ClientKind::Confidential => "Web app with a backend",
            ClientKind::Public => "Browser or native app",
        }
    }
}

/// One of a confidential client's secrets: when it was made and when it stops
/// working, never its value.
#[derive(Clone, Copy, Debug)]
pub struct SecretRow {
    /// When it was made.
    pub created_at: DateTime<Utc>,
    /// When a rotation made it stop working, if one did.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Where a client's `OpenID` Connect library finds Piquel.
#[derive(Clone, Copy, Debug)]
pub struct Connection<'a> {
    /// The issuer.
    pub issuer: &'a str,
    /// Its discovery document.
    pub discovery: &'a str,
}

/// A secret Piquel just generated, shown only in the response to the change that
/// made it. It never serializes and its `Debug` is redacted, so no query, link or
/// log can hold it.
pub struct Revealed(String);

impl Revealed {
    /// Shows `secret`.
    #[must_use]
    pub const fn new(secret: String) -> Self {
        Self(secret)
    }

    /// The secret.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Revealed {
    /// Writes nothing of the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Revealed(REDACTED)")
    }
}

piquel_common::str_enum! {
    /// How long a client's earlier secrets keep working once it gets a new one, as
    /// the rotation form offers it, written as auth reads grace periods.
    pub enum Grace {
        /// They stop at once.
        Now = "0",
        /// For an hour.
        Hour = "1h",
        /// For a day.
        Day = "24h",
        /// For a week.
        Week = "7d",
        /// For 30 days.
        Month = "30d",
    }
}

impl Grace {
    /// The choice in words.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Now => "Stop them now",
            Self::Hour => "For an hour",
            Self::Day => "For a day",
            Self::Week => "For a week",
            Self::Month => "For 30 days",
        }
    }
}

impl Default for Grace {
    /// A day, which the rotation form's select starts at.
    fn default() -> Self {
        Self::Day
    }
}

/// The standard scopes a client's form chose, one checkbox each, named after its
/// scope: a form sends a list as repeated names, which a change cannot decode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeChoice {
    /// `openid`.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub openid: Checkbox,
    /// `profile`.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub profile: Checkbox,
    /// `email`.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub email: Checkbox,
    /// `offline_access`.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub offline_access: Checkbox,
}

impl ScopeChoice {
    /// The checkbox of `scope`. Exhaustive, so a new scope does not compile until
    /// the form offers it.
    const fn checkbox(&mut self, scope: Scope) -> &mut Checkbox {
        match scope {
            Scope::OpenId => &mut self.openid,
            Scope::Profile => &mut self.profile,
            Scope::Email => &mut self.email,
            Scope::OfflineAccess => &mut self.offline_access,
        }
    }

    /// Whether `scope` is chosen.
    #[must_use]
    pub const fn has(mut self, scope: Scope) -> bool {
        self.checkbox(scope).0
    }

    /// The names of the scopes chosen, in [`Scope::ALL`]'s order.
    #[must_use]
    pub fn names(self) -> Vec<String> {
        Scope::ALL
            .into_iter()
            .filter(|scope| self.has(*scope))
            .map(|scope| scope.as_str().to_owned())
            .collect()
    }
}

impl FromIterator<Scope> for ScopeChoice {
    /// `scopes` chosen.
    fn from_iter<I: IntoIterator<Item = Scope>>(scopes: I) -> Self {
        let mut chosen = Self::default();
        for scope in scopes {
            *chosen.checkbox(scope) = Checkbox(true);
        }
        chosen
    }
}

/// A client's settings as its form sends them. A form leaves every setting empty
/// in the change it sends as hidden inputs, and renders the inputs of the draft it
/// shows instead. Browsers send every text input and textarea; a textarea left out
/// reads as empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientDraft {
    /// The name consent screens show.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// Its authorization callbacks.
    #[serde(default, skip_serializing_if = "Lines::is_empty")]
    pub redirect_uris: Lines,
    /// The pages the browser may return to after logout.
    #[serde(default, skip_serializing_if = "Lines::is_empty")]
    pub post_logout_uris: Lines,
    /// The scopes it may request.
    #[serde(flatten)]
    pub scopes: ScopeChoice,
    /// Whether it may receive refresh tokens.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub allow_refresh: Checkbox,
    /// Whether it must push its authorization requests.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub require_pushed_authorization_requests: Checkbox,
}

impl From<&ClientRow<'_>> for ClientDraft {
    /// `client`'s settings as they are. Only standard scopes have a checkbox.
    fn from(client: &ClientRow<'_>) -> Self {
        Self {
            display_name: client.name.to_owned(),
            redirect_uris: client.redirect_uris.iter().cloned().collect(),
            post_logout_uris: client.post_logout_uris.iter().cloned().collect(),
            scopes: client
                .allowed_scopes
                .iter()
                .filter_map(|scope| scope.parse().ok())
                .collect(),
            allow_refresh: Checkbox(client.allow_refresh),
            require_pushed_authorization_requests: Checkbox(
                client.require_pushed_authorization_requests,
            ),
        }
    }
}

/// Why the service refused one of a client's settings, as its form shows it.
#[derive(Clone, Copy, Debug)]
pub struct FieldError<'a> {
    /// The setting.
    pub field: &'a ClientField,
    /// What is wrong with it, without its name.
    pub message: &'a str,
}

impl FieldError<'_> {
    /// Whether the client form shows a refusal of its setting beside the setting's
    /// input. Only the settings the service validates have a place for one: it
    /// never refuses the refresh and pushed-request checkboxes.
    const fn placed(&self) -> bool {
        match self.field {
            ClientField::DisplayName
            | ClientField::RedirectUris
            | ClientField::PostLogoutUris
            | ClientField::AllowedScopes => true,
            ClientField::AllowRefresh
            | ClientField::Trusted
            | ClientField::RequirePushedAuthorizationRequests
            | ClientField::BackchannelLogoutUri
            | ClientField::Other(_) => false,
        }
    }
}

/// One of a client's form's inputs, and what the form says of it in elements the
/// input names, whose IDs start with its own: its help, and why the service
/// refused its setting, if it did.
struct Described<'a> {
    /// The input's ID.
    id: String,
    /// Why the service refused its setting, if it did.
    refusal: Option<&'a str>,
}

impl<'a> Described<'a> {
    /// The input `id`, whose setting the service did not refuse.
    const fn new(id: String) -> Self {
        Self { id, refusal: None }
    }

    /// The input of `field`, named after it, and `error`'s refusal of it, if it
    /// is about it.
    fn of(error: Option<FieldError<'a>>, field: &ClientField) -> Self {
        Self {
            id: field.to_string(),
            refusal: error
                .filter(|error| error.field == field)
                .map(|error| error.message),
        }
    }

    /// The ID of its help.
    fn help(&self) -> String {
        format!("{}-help", self.id)
    }

    /// The ID of the element saying why its setting was refused.
    fn error(&self) -> String {
        format!("{}-error", self.id)
    }

    /// Its `aria-invalid`.
    fn flag(&self) -> Option<&'static str> {
        self.refusal.map(|_| "true")
    }

    /// Its `aria-describedby`: its help, then why its setting was refused, if it
    /// was.
    fn described_by(&self) -> String {
        if self.refused() {
            format!("{} {}", self.help(), self.error())
        } else {
            self.help()
        }
    }

    /// Whether its setting was refused, so it takes the focus.
    const fn refused(&self) -> bool {
        self.refusal.is_some()
    }
}

/// What a standard scope gives a client.
const fn scope_description(scope: Scope) -> &'static str {
    match scope {
        Scope::OpenId => "Sign users in: their stable user ID",
        Scope::Profile => "Their handle and display name",
        Scope::Email => "Their email address, when they have one",
        Scope::OfflineAccess => "Refresh tokens, if refresh is allowed",
    }
}

/// A client's kind, then a warning when it does not sign users in, as badges.
#[component]
pub(crate) async fn client_status<'a>(client: ClientRow<'a>) -> Result<impl View> {
    Ok(view! {
        <span class="badge">(client.kind_name())</span>
        if let ClientStatus::Suspended { .. } = client.status {
            <span class="badge warning">"Suspended"</span>
        } else if client.status == ClientStatus::Disabled {
            <span class="badge warning">"Disabled"</span>
        }
    })
}

/// A button copying the text of the element whose ID is `target`, named `label` for
/// screen readers, after the status saying whether it did. It starts hidden; the
/// SDK shows it once it can write to the clipboard.
#[component]
pub(crate) async fn copy<'a>(target: &'a str, label: &'a str) -> Result<impl View> {
    Ok(view! {
        <span class="copy">
            <span class="help" role="status"></span>
            <button type="button" class="text-button" data-copy=(target) aria-label=(format!("Copy {label}")) hidden="">
                "Copy"
            </button>
        </span>
    })
}

/// `value` as code, the element `id`, beside a button copying it, named `label`.
#[component]
pub(crate) async fn copyable<'a>(id: &'a str, label: &'a str, value: &'a str) -> Result<impl View> {
    Ok(view! {
        <div class="row between code-line">
            <code id=(id)>(value)</code>
            copy(target: id, label: label)
        </div>
    })
}

/// What a client's `OpenID` Connect library needs to know, found through
/// `connection`, each value with a button copying it, then its redirect URIs.
#[component]
pub(crate) async fn client_facts<'a>(
    client: ClientRow<'a>,
    connection: Connection<'a>,
) -> Result<impl View> {
    let mut facts: Vec<(&str, &str, Cow<'_, str>)> = vec![
        ("issuer", "Issuer", connection.issuer.into()),
        (
            "discovery-url",
            "Discovery URL",
            connection.discovery.into(),
        ),
        ("client-id", "Client ID", client.id.as_str().into()),
        (
            "client-auth",
            "Client authentication",
            client.kind.auth_method().as_str().into(),
        ),
        ("scopes", "Scopes", client.allowed_scopes.join(" ").into()),
    ];
    facts.extend(
        client
            .backchannel_logout_uri
            .map(|uri| ("backchannel-logout", "Back-channel logout URI", uri.into())),
    );
    Ok(view! {
        <dl class="facts">
            for (id, label, value) in facts {
                <dt>(label)</dt>
                <dd>copyable(id: id, label: label, value: &value)</dd>
            }
            <dt>"Redirect URIs"</dt>
            <dd>
                for uri in client.redirect_uris {
                    <div><code>(uri.as_str())</code></div>
                }
            </dd>
        </dl>
    })
}

/// Help with the input `of`, below it.
#[component]
async fn help<'a>(of: &'a Described<'a>, child: Child<'_>) -> Result<impl View> {
    Ok(view! {
        <small class="field-help" id=(of.help())>(child)</small>
    })
}

/// Why the service refused the setting of the input `of`, if it did, below it.
#[component]
async fn refusal<'a>(of: &'a Described<'a>) -> Result<impl View> {
    Ok(view! {
        if let Some(message) = of.refusal {
            <p class="field-error" id=(of.error())>(message)</p>
        }
    })
}

/// A checkbox sending `name`, or with a `value`, a radio button of the group
/// `name` choosing it, `checked` or not, which takes the focus if `autofocus`:
/// its `label` beside it, then its `detail` below, which describes it.
#[component]
async fn choice<'a>(
    name: &'a str,
    #[default] value: Option<&'a str>,
    checked: bool,
    #[default] autofocus: bool,
    #[into] label: Child<'_>,
    #[into] detail: Child<'_>,
) -> Result<impl View> {
    let input =
        Described::new(value.map_or_else(|| name.to_owned(), |value| format!("{name}-{value}")));
    Ok(view! {
        <div class="choice">
            <input
                type=(if value.is_some() { "radio" } else { "checkbox" })
                id=(input.id.as_str())
                name=(name)
                value=(value)
                checked=(checked)
                autofocus=(autofocus)
                aria-describedby=(input.described_by())
            >
            <label for=(input.id.as_str())>(label)</label>
            help(of: &input, (detail))
        </div>
    })
}

/// The question of a new client's kind, `chosen` checked.
#[component]
async fn kind_question(chosen: ClientKind) -> Result<impl View> {
    Ok(view! {
        <fieldset>
            <legend>"Does your app have a backend that can keep a secret?"</legend>
            for kind in [ClientKind::Confidential, ClientKind::Public] {
                let (answer, detail) = match kind {
                    ClientKind::Confidential => (
                        "Yes, a web app with a backend",
                        "Its server signs users in with a client secret.",
                    ),
                    ClientKind::Public => (
                        "No, it runs in the browser or on a device",
                        "Single-page, mobile and desktop apps, which cannot hide a secret.",
                    ),
                };
                choice(
                    name: "kind",
                    value: Some(kind.as_str()),
                    checked: kind == chosen,
                    label: view! { (answer) },
                    detail: view! { (detail) },
                )
            }
            <small>"Both sign in with PKCE (S256). The type cannot change later."</small>
        </fieldset>
    })
}

/// A checkbox for each standard scope, those of `chosen` checked, and why the
/// service refused them, as `scopes` says, if it did.
#[component]
async fn scope_choices<'a>(chosen: ScopeChoice, scopes: &'a Described<'a>) -> Result<impl View> {
    Ok(view! {
        <fieldset aria-describedby=(scopes.refused().then(|| scopes.error()))>
            <legend>"Scopes"</legend>
            for scope in Scope::ALL {
                choice(
                    name: scope.as_str(),
                    checked: chosen.has(scope),
                    autofocus: scopes.refused() && scope == Scope::ALL[0],
                    label: view! { <code>(scope.as_str())</code> },
                    detail: view! { (scope_description(scope)) },
                )
            }
        </fieldset>
        refusal(of: scopes)
    })
}

/// A client's settings form, posting `change` to `action` with a button labelled
/// `label`: its inputs show `draft`, and, with `kind`, it asks for a new client's
/// kind, `kind` chosen. Each input is named by its label alone, and described by
/// its help. The service's `error` shows beside the input of its setting, which
/// takes the focus, or above the inputs for a setting with no place for one (see
/// [`FieldError::placed`]). With `confirm`, the SDK confirms with a passkey first.
#[component]
pub(crate) async fn client_form<'a>(
    action: &'a str,
    #[into] change: Fields,
    draft: &'a ClientDraft,
    #[default] kind: Option<ClientKind>,
    label: &'a str,
    #[default] error: Option<FieldError<'a>>,
    #[default] confirm: bool,
) -> Result<impl View> {
    let unplaced = error.filter(|error| !error.placed());
    let name = Described::of(error, &ClientField::DisplayName);
    let redirects = Described::of(error, &ClientField::RedirectUris);
    let logouts = Described::of(error, &ClientField::PostLogoutUris);
    let scopes = Described::of(error, &ClientField::AllowedScopes);
    Ok(view! {
        <div class="card">
            change_form(
                action: action,
                change: change,
                label: label,
                confirm: confirm,
                if let Some(error) = unplaced {
                    <p class="notice error" role="alert">(error.message)</p>
                }
                <label>
                    "App name"
                    <input
                        name="display_name"
                        value=(draft.display_name.as_str())
                        maxlength="80"
                        required=""
                        aria-invalid=(name.flag())
                        aria-describedby=(name.described_by())
                        autofocus=(name.refused())
                    >
                </label>
                help(of: &name, "Users see it when they sign in to your app.")
                refusal(of: &name)
                if let Some(chosen) = kind {
                    kind_question(chosen: chosen)
                }
                <label>
                    "Redirect URIs"
                    <textarea
                        name="redirect_uris"
                        rows="3"
                        placeholder="https://app.example/auth/callback"
                        required=""
                        aria-invalid=(redirects.flag())
                        aria-describedby=(redirects.described_by())
                        autofocus=(redirects.refused())
                    >(draft.redirect_uris.text())</textarea>
                </label>
                help(
                    of: &redirects,
                    "One per line, matched exactly: where Piquel sends users back after signing in. HTTPS, or HTTP on a loopback IP for native apps."
                )
                refusal(of: &redirects)
                <label>
                    "Post-logout URIs"
                    <textarea
                        name="post_logout_uris"
                        rows="2"
                        placeholder="https://app.example/"
                        aria-invalid=(logouts.flag())
                        aria-describedby=(logouts.described_by())
                        autofocus=(logouts.refused())
                    >(draft.post_logout_uris.text())</textarea>
                </label>
                help(of: &logouts, "Optional, one per line: pages users may return to after signing out.")
                refusal(of: &logouts)
                scope_choices(chosen: draft.scopes, scopes: &scopes)
                choice(
                    name: "allow_refresh",
                    checked: draft.allow_refresh.0,
                    label: view! { "Allow refresh tokens" },
                    detail: view! {
                        "When your app requests " <code>"offline_access"</code> ", it can stay signed in without sending users back to Piquel."
                    },
                )
                choice(
                    name: "require_pushed_authorization_requests",
                    checked: draft.require_pushed_authorization_requests.0,
                    label: view! { "Require pushed authorization requests" },
                    detail: view! {
                        "Your app must post its sign-in requests to " <code>"/oauth/par"</code> " (RFC 9126), so none of their parameters travel through the browser."
                    },
                )
            )
        </div>
    })
}

/// A confidential client's `secrets`, oldest first, as of `now`: when each was
/// made, and when it stops or stopped working.
#[component]
pub(crate) async fn secrets_list<'a>(
    secrets: &'a [SecretRow],
    now: DateTime<Utc>,
) -> Result<impl View> {
    Ok(view! {
        <ul class="list">
            for secret in secrets {
                <li>
                    <strong>"Created " time(at: secret.created_at, precision: Precision::Minute)</strong>
                    <p class="help">
                        if let Some(at) = secret.expires_at {
                            (if at > now { "Stops working " } else { "Stopped working " })
                            time(at: at, precision: Precision::Minute)
                        } else {
                            "Works until you rotate it"
                        }
                    </p>
                </li>
            }
        </ul>
    })
}

/// A client `secret` Piquel just made, shown once, with a button copying it, on
/// `page`, whose address the SDK puts back so that reloading it gets the page
/// without the secret; saving it leads on to `next`.
#[component]
pub(crate) async fn secret_panel<'a>(
    secret: &'a Revealed,
    page: &'a str,
    next: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <section class="card stack" aria-labelledby="secret-heading" data-replace-url=(page)>
            <h2 id="secret-heading" tabindex="-1" autofocus="">"Your client secret"</h2>
            <p class="notice error" role="alert">
                "This is the only time this secret is shown. Store it in your app's secret manager or environment now; Piquel keeps only a digest of it."
            </p>
            copyable(id: "client-secret", label: "client secret", value: secret.expose())
            <a class="button" href=(next)>"I saved it"</a>
        </section>
    })
}
