//! The developer console: the apps an account registers as `OpenID` Connect
//! clients, registering one, and each app's overview, settings and secrets.
//!
//! A secret shows only in the response to the change that made it, a registration
//! or a rotation: the change's query holds it in a field no link or form
//! serializes, and the panel showing it asks the SDK to put back the page's own
//! address, so reloading gets the page without it.

use crate::{
    clients::{
        ClientDraft, ClientRow, ClientStatus, Connection, FieldError, Grace, Revealed, SecretRow,
        client_facts, client_form, client_status, copy, secret_panel, secrets_list,
    },
    form::{Checkbox, Precision, Query, change_form, open, time},
    layout::{Label, navigation},
};
use chrono::{DateTime, Utc};
use piquel_common::{clients::ClientKind, protocol::oauth::Scope};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// The Rust SDK's source and guide.
const RUST_SDK: &str = "https://github.com/piquel-fr/piquel-fr/tree/main/crates/auth-sdk";
/// The guide to asking for a passkey before sensitive actions.
const STEP_UP_GUIDE: &str =
    "https://github.com/piquel-fr/piquel-fr/blob/main/docs/guides/step-up-authentication.md";

/// What an app's page says when the account has no such app.
pub const MISSING: &str = "This app does not exist, or it is not yours.";

/// What the new-app page posts, named by its `action` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NewAppChange {
    /// Registers an app with what was typed, once confirmed with a passkey.
    Register {
        /// Its kind, which the form's radio group chooses: confidential when the
        /// form sends none, as the group starts there.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<ClientKind>,
        /// Its settings.
        #[serde(flatten)]
        draft: ClientDraft,
    },
}

impl NewAppChange {
    /// The kind the form's radio group starts at.
    pub const DEFAULT_KIND: ClientKind = ClientKind::Confidential;
}

/// The new-app page's query, which only holds what a registration's answer shows.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NewAppState {
    /// The kind a registration that failed chose.
    #[serde(skip)]
    pub kind: Option<ClientKind>,
    /// What a registration that failed was given, to ask for it again.
    #[serde(skip)]
    pub draft: Option<ClientDraft>,
    /// The confidential app just registered, whose secret shows only in this
    /// response.
    #[serde(skip)]
    pub registered: Option<Registered>,
}

impl Query for NewAppState {}

/// A confidential app just registered.
#[derive(Debug)]
pub struct Registered {
    /// Its overview page.
    pub overview: String,
    /// Its secret.
    pub secret: Revealed,
}

/// What an app's settings page posts, named by its `action` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AppChange {
    /// Saves what was typed. Changing the redirect or post-logout URIs needs a
    /// recent passkey confirmation, which only the change shows.
    Save {
        /// The settings.
        #[serde(flatten)]
        draft: ClientDraft,
    },
    /// Stops the app signing users in until it is enabled again.
    Disable {},
    /// Lets the app sign users in again.
    Enable {},
    /// Deletes the app for good, once confirmed with a passkey.
    Delete {},
}

/// Which row of an app's settings is open, as the page's query names it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppSettingsState {
    /// The deletion awaits confirmation.
    #[serde(rename = "delete", default, skip_serializing_if = "Checkbox::is_off")]
    pub deleting: Checkbox,
    /// What a save that failed was given, to ask for it again.
    #[serde(skip)]
    pub draft: Option<ClientDraft>,
}

impl Query for AppSettingsState {}

/// What an app's secrets page posts, named by its `action` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SecretsChange {
    /// Gives the app a new secret, once confirmed with a passkey.
    Rotate {
        /// How long the earlier ones keep working, which the form's select
        /// chooses: a day when the form sends none, as the select starts there.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grace: Option<Grace>,
    },
}

/// An app's secrets page's query, which only holds what a rotation's answer shows.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SecretsState {
    /// The grace a rotation that failed chose.
    #[serde(skip)]
    pub grace: Option<Grace>,
    /// The secret just made, shown only in this response.
    #[serde(skip)]
    pub rotated: Option<Revealed>,
}

impl Query for SecretsState {}

/// One of the account's apps, and its page.
#[derive(Clone, Debug)]
pub struct AppLink<'a> {
    /// The app.
    pub client: ClientRow<'a>,
    /// Its overview page.
    pub page: String,
}

/// The pages of one app, in the order its tabs list them. A public app has no
/// secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppTab {
    /// What its `OpenID` Connect library needs.
    Overview,
    /// Its settings, disabling and deleting it.
    Settings,
    /// A confidential app's secrets.
    Secrets,
}

impl AppTab {
    /// Its page's title in the browser, for the app named `app`.
    #[must_use]
    pub fn title(self, app: &str) -> String {
        match self {
            Self::Overview => app.to_owned(),
            Self::Settings | Self::Secrets => format!("{} · {app}", self.label()),
        }
    }
}

impl Label for AppTab {
    /// Its tab's label.
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Settings => "Settings",
            Self::Secrets => "Secrets",
        }
    }
}

impl ClientRow<'_> {
    /// A Rust program signing users in through this app at `issuer`, with the Rust
    /// SDK's axum routes. It never holds the secret: it reads it from the
    /// environment.
    fn rust_example(&self, issuer: &str) -> String {
        let id = self.id;
        let credentials = match self.kind {
            ClientKind::Confidential => {
                r#"Credentials::Secret(std::env::var("PIQUEL_CLIENT_SECRET")?.into())"#
            }
            ClientKind::Public => "Credentials::None",
        };
        let redirect = self
            .redirect_uris
            .first()
            .map_or("https://app.example/auth/callback", String::as_str);
        let scopes = self
            .allowed_scopes
            .iter()
            .map(String::as_str)
            .filter(|scope| *scope != Scope::OpenId.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            r#"// Cargo.toml, with axum at the SDK's version, so its router and layer fit yours:
// [dependencies]
// piquel-auth = {{ git = "https://github.com/piquel-fr/piquel-fr", features = ["axum"] }}
// axum = "0.8"
// tokio = {{ version = "1", features = ["macros", "rt-multi-thread", "net"] }}
use axum::{{Router, routing::get}};
use piquel_auth::axum::{{LoginRoutes, MemoryBackend, SignedIn}};
use piquel_auth::{{ClientConfig, Credentials, Issuer}};

async fn home(user: SignedIn) -> String {{
    format!("Hello {{}}", user.name())
}}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {{
    let issuer = Issuer::discover("{issuer}").await?;
    let config = ClientConfig {{
        client_id: "{id}".parse()?,
        credentials: {credentials},
        // The login routes' callback, nested at /auth below: register it as a redirect URI.
        redirect_uri: "{redirect}".parse()?,
    }};
    // Sessions in memory, lost on restart: implement SessionBackend to keep them.
    let auth = LoginRoutes::new(issuer.client(config), MemoryBackend::default())
        .scopes("{scopes}".parse()?);
    let app = Router::new()
        .route("/", get(home))
        .nest("/auth", auth.router())
        .layer(auth.layer());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}}"#
        )
    }
}

/// The console's home: the account's apps, each with its page in `links`, of the
/// `limit` it may have, a link to register one at `new` while it may, and where
/// to learn more.
#[component]
pub async fn apps<'a>(links: &'a [AppLink<'a>], limit: u32, new: &'a str) -> Result<impl View> {
    let count = links.len();
    let room = u32::try_from(count).is_ok_and(|count| count < limit);
    Ok(view! {
        <section class="card" aria-labelledby="apps-heading">
            <div class="row between">
                <h2 id="apps-heading">"Your apps"</h2>
                <span class="badge">(format!("{count} of {limit}"))</span>
            </div>
            <ul class="list">
                for app in links {
                    <li>
                        <a href=(app.page.as_str())><strong>(app.client.name)</strong></a>
                        <p class="help"><code>(app.client.id.as_str())</code></p>
                        <p class="help">
                            (format!("{} · {} · ", app.client.kind_name(), app.client.status.state()))
                            if let Some(at) = app.client.last_used_at {
                                "last used " time(at: at, precision: Precision::Day)
                            } else {
                                "never used"
                            }
                        </p>
                    </li>
                }
            </ul>
            if links.is_empty() {
                <p class="empty">"You have no apps yet. Register one to get its client ID."</p>
            }
            if room {
                <a class="button full" href=(new)>"New app"</a>
            } else {
                <p class="help">"Delete an app to register another."</p>
            }
        </section>
        <section class="card stack" aria-labelledby="docs-heading">
            <h2 id="docs-heading">"How it works"</h2>
            <p>
                "Piquel is a standard OpenID Connect provider. Each app gets a client ID, and apps with a backend a secret. Use the Rust SDK, or any OpenID Connect library with the settings on your app's page."
            </p>
            <ul>
                <li><a href=(RUST_SDK)>"Rust SDK (" <code>"piquel-auth"</code> ")"</a></li>
                <li><a href=(STEP_UP_GUIDE)>"Asking for a passkey before sensitive actions (step-up)"</a></li>
            </ul>
        </section>
    })
}

/// The link back to the console's `home`, the account's apps.
#[component]
pub async fn back_to_apps(home: &str) -> Result<impl View> {
    Ok(view! {
        <p><a href=(home)>"← Your apps"</a></p>
    })
}

/// Registering an app on `page`, which links back to the console's `home`: the form showing
/// `draft` and the kind `state` chose, which needs a passkey confirmation unless
/// `confirmed`, with the service's `error` beside its input. Once a confidential
/// app is registered, its secret instead, once.
#[component]
pub async fn new_app<'a>(
    page: &'a str,
    home: &'a str,
    state: &'a NewAppState,
    draft: &'a ClientDraft,
    confirmed: bool,
    #[default] error: Option<FieldError<'a>>,
) -> Result<impl View> {
    Ok(view! {
        if let Some(registered) = &state.registered {
            secret_panel(secret: &registered.secret, page: page, next: registered.overview.as_str())
        } else {
            back_to_apps(home: home)
            <h2>"Register an app"</h2>
            client_form(
                action: page,
                change: NewAppChange::Register { kind: None, draft: ClientDraft::default() },
                draft: draft,
                kind: Some(state.kind.unwrap_or(NewAppChange::DEFAULT_KIND)),
                label: "Register app",
                error: error,
                confirm: !confirmed,
            )
        }
    })
}

/// An app's page's opening: the link back to the console's `home`, the app's
/// name and status, and its `tabs`, `current` among them.
#[component]
pub async fn app_header<'a>(
    home: &'a str,
    client: ClientRow<'a>,
    tabs: &'a [(AppTab, String)],
    current: AppTab,
) -> Result<impl View> {
    let tabs: Vec<_> = tabs
        .iter()
        .map(|(tab, href)| (*tab, href.as_str()))
        .collect();
    Ok(view! {
        back_to_apps(home: home)
        <div class="row">
            <h2>(client.name)</h2>
            client_status(client: client)
        </div>
        navigation(label: "App", class: "tabs", links: &tabs, current: current)
    })
}

/// An app's overview: why it does not sign users in, if it does not, what its
/// `OpenID` Connect library needs, found through `connection`, a Rust example and
/// how to ask for a passkey. `secrets`, given for a confidential app, links its
/// secrets page.
#[component]
pub async fn overview<'a>(
    client: ClientRow<'a>,
    connection: Connection<'a>,
    #[default] secrets: Option<&'a str>,
) -> Result<impl View> {
    let example = client.rust_example(connection.issuer);
    let confidential = client.kind == ClientKind::Confidential;
    Ok(view! {
        if let ClientStatus::Suspended { at } = client.status {
            <p class="notice error">
                "An administrator suspended this app on " time(at: at, precision: Precision::Day)
                ": it cannot sign users in. Contact them to restore it."
            </p>
        } else if client.status == ClientStatus::Disabled {
            <p class="notice">
                "This app is disabled: it cannot sign users in until you enable it in its settings."
            </p>
        }
        <section class="card" aria-labelledby="oidc-heading">
            <h2 id="oidc-heading">"OpenID Connect settings"</h2>
            <p class="help">
                "For any OpenID Connect library. Use the authorization code flow with PKCE (S256)"
                if confidential {
                    ", and send the client secret with HTTP Basic authentication"
                }
                "."
            </p>
            client_facts(client: client, connection: connection)
            if let Some(secrets) = secrets {
                <p class="help">
                    "Keep the client secret on your server, for example in a " <code>"PIQUEL_CLIENT_SECRET"</code>
                    " environment variable. Lost it? Rotate it on the " <a href=(secrets)>"Secrets"</a> " tab."
                </p>
            }
        </section>
        <section class="card stack" aria-labelledby="rust-heading">
            <div class="row between">
                <h2 id="rust-heading">"Rust with axum"</h2>
                copy(target: "rust-example", label: "Rust example")
            </div>
            <p class="help">
                "The " <a href=(RUST_SDK)>"Rust SDK"</a> " signs users in on your server and keeps their tokens there."
            </p>
            <pre><code id="rust-example">(example)</code></pre>
        </section>
        <section class="card stack" aria-labelledby="step-up-heading">
            <h2 id="step-up-heading">"Sensitive actions"</h2>
            <p>
                "Before an action that needs a fresh passkey, such as deleting data, your app can ask users to sign in again with one. "
                <a href=(STEP_UP_GUIDE)>"The step-up guide"</a> " explains how."
            </p>
        </section>
    })
}

/// An app's settings on `page`: its form, showing what a save that failed was
/// given or the app as it is, with the service's `error` beside its input, which
/// asks for a passkey only once a save was `asked` to; then disabling or enabling
/// it, and deleting it, whose confirmation `state` opens, and which needs a
/// passkey confirmation unless `confirmed`.
#[component]
pub async fn app_settings<'a>(
    page: &'a str,
    client: ClientRow<'a>,
    state: &'a AppSettingsState,
    confirmed: bool,
    asked: bool,
    #[default] error: Option<FieldError<'a>>,
) -> Result<impl View> {
    let shown = state
        .draft
        .clone()
        .unwrap_or_else(|| ClientDraft::from(&client));
    let (title, help, toggle) = match client.status {
        ClientStatus::Suspended { .. } => (
            "Suspended",
            "An administrator suspended this app. Contact them to restore it.",
            None,
        ),
        ClientStatus::Enabled => (
            "Disable this app",
            "It stops signing users in, exchanging codes and refreshing tokens until you enable it again.",
            Some((AppChange::Disable {}, "Disable")),
        ),
        ClientStatus::Disabled => (
            "Enable this app",
            "It can sign users in again.",
            Some((AppChange::Enable {}, "Enable")),
        ),
    };
    Ok(view! {
        client_form(
            action: page,
            change: AppChange::Save { draft: ClientDraft::default() },
            draft: &shown,
            label: "Save changes",
            error: error,
            confirm: asked,
        )
        <section class="card stack" aria-labelledby="danger-heading">
            <h2 id="danger-heading">"Danger zone"</h2>
            <div class="row between">
                <div>
                    <strong>(title)</strong>
                    <p class="help">(help)</p>
                </div>
                if let Some((change, label)) = toggle {
                    change_form(action: page, change: change, label: label, class: "secondary")
                }
            </div>
            if state.deleting.0 {
                <div class="notice stack">
                    <strong tabindex="-1" autofocus="">(format!("Delete “{}”?", client.name))</strong>
                    <p>
                        "It stops working at once: its refresh tokens are revoked, and its secrets and the consents users gave it are removed. This cannot be undone."
                    </p>
                    change_form(
                        action: page,
                        change: AppChange::Delete {},
                        label: "Delete for good",
                        class: "danger",
                        confirm: !confirmed,
                        cancel: page.to_owned(),
                    )
                </div>
            } else {
                <div class="row between">
                    <div>
                        <strong>"Delete this app"</strong>
                        <p class="help">"Its client ID is never used again."</p>
                    </div>
                    open(
                        page: page,
                        opens: AppSettingsState { deleting: Checkbox(true), draft: None },
                        label: "Delete",
                        secondary: true,
                    )
                </div>
            }
        </section>
    })
}

/// A confidential app's secrets on `page`: the one a rotation just made, once,
/// then the lifetimes of its `secrets` as of `now`, and rotating, with the grace
/// `state` chose, which needs a passkey confirmation unless `confirmed`.
#[component]
pub async fn app_secrets<'a>(
    page: &'a str,
    secrets: &'a [SecretRow],
    now: DateTime<Utc>,
    state: &'a SecretsState,
    confirmed: bool,
) -> Result<impl View> {
    let chosen = state.grace.unwrap_or_default();
    Ok(view! {
        if let Some(secret) = &state.rotated {
            secret_panel(secret: secret, page: page, next: page)
        }
        <section class="card" aria-labelledby="secrets-heading">
            <h2 id="secrets-heading">"Client secrets"</h2>
            <p class="help">
                "Your server sends one with HTTP Basic authentication. Piquel shows a secret only when it creates it."
            </p>
            secrets_list(secrets: secrets, now: now)
        </section>
        <section class="card stack" aria-labelledby="rotate-heading">
            <h2 id="rotate-heading">"Rotate the secret"</h2>
            <p class="help">
                "Get a new secret, and give your app time to switch to it: the earlier ones keep working for the period you choose."
            </p>
            change_form(
                action: page,
                change: SecretsChange::Rotate { grace: None },
                label: "Rotate secret",
                confirm: !confirmed,
                <label>
                    "Earlier secrets keep working"
                    <select name="grace">
                        for grace in Grace::ALL {
                            <option value=(grace.as_str()) selected=(grace == chosen)>(grace.label())</option>
                        }
                    </select>
                </label>
            )
        </section>
    })
}
