//! Passkeys and social sign-in.

use crate::form::{Query, change_form, hidden, open};
use piquel_common::{
    PasskeyId, Provider,
    protocol::api::{Identity, Passkey},
};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the sign-in methods page posts, named by its `action` field. A field
/// the user types is left empty here, and the form renders its input instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SignInChange {
    /// Renames a passkey.
    Rename {
        /// The passkey.
        id: PasskeyId,
        /// Its new name, which the user types.
        #[serde(skip_serializing_if = "String::is_empty")]
        friendly_name: String,
    },
    /// Removes a passkey, once confirmed with one.
    Remove {
        /// The passkey.
        id: PasskeyId,
    },
    /// Starts linking a provider, at the provider.
    Link {
        /// The provider.
        provider: Provider,
    },
    /// Unlinks a provider, once confirmed with a passkey.
    Unlink {
        /// The provider.
        provider: Provider,
    },
    /// Shows that the SDK just added a passkey, through the account API: this
    /// changes nothing.
    Enrolled {},
}

/// Which row of the sign-in methods is open, as the page's query names it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignInState {
    /// The passkey being renamed.
    #[serde(rename = "rename")]
    pub renaming: Option<PasskeyId>,
    /// The passkey whose removal awaits confirmation.
    #[serde(rename = "remove")]
    pub removing: Option<PasskeyId>,
    /// The provider whose unlinking awaits confirmation.
    #[serde(rename = "unlink")]
    pub unlinking: Option<Provider>,
    /// The name a rename that failed asked for, to ask for it again.
    #[serde(skip)]
    pub name: Option<String>,
}

impl Query for SignInState {}

/// A social sign-in provider, as the sign-in methods list it.
#[derive(Clone, Copy, Debug)]
pub struct ProviderRow<'a> {
    /// The provider.
    pub provider: Provider,
    /// The account's identity there, if linked.
    pub identity: Option<&'a Identity>,
    /// Whether Piquel offers it now. A linked provider since disabled is still
    /// listed, so it can be unlinked.
    pub enabled: bool,
}

/// A provider's name.
pub(super) const fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::GitHub => "GitHub",
        Provider::Google => "Google",
    }
}

/// The sign-in methods page: the account's `passkeys`, and the social sign-in
/// `providers`. Its rows open on `page` as `state` says, and its changes post
/// there; `confirmed` says whether the session needs no passkey confirmation for
/// them. On Android, adding a passkey offers Google Password Manager.
#[component]
pub async fn sign_in_methods<'a>(
    page: &'a str,
    passkeys: &'a [Passkey],
    providers: &'a [ProviderRow<'a>],
    state: &'a SignInState,
    confirmed: bool,
    android: bool,
) -> Result<impl View> {
    Ok(view! {
        passkey_list(page: page, passkeys: passkeys, state: state, confirmed: confirmed, android: android)
        social(page: page, providers: providers, state: state, confirmed: confirmed)
    })
}

/// The passkeys section of [`sign_in_methods`].
#[component]
async fn passkey_list<'a>(
    page: &'a str,
    passkeys: &'a [Passkey],
    state: &'a SignInState,
    confirmed: bool,
    android: bool,
) -> Result<impl View> {
    let count = passkeys.len();
    Ok(view! {
        <section class="card" aria-labelledby="passkeys-heading">
            <div class="row between">
                <h2 id="passkeys-heading">"Passkeys"</h2>
                <span class="badge">(format!("{count} registered"))</span>
            </div>
            <p class="help">
                "Saved securely with your device or password manager. Keep a second passkey so you can always get back in."
            </p>
            <ul class="list">
                for passkey in passkeys {
                    <li>
                        passkey_row(page: page, passkey: passkey, removable: count > 1, state: state, confirmed: confirmed)
                    </li>
                }
            </ul>
            if passkeys.is_empty() {
                <p class="empty">"Add your first passkey to protect your account."</p>
            }
            enroll(page: page, android: android)
            <p class="help">"Your last passkey cannot be removed."</p>
        </section>
    })
}

/// One passkey of [`passkey_list`]: its name, or the open rename or removal row,
/// which takes the focus.
#[component]
async fn passkey_row<'a>(
    page: &'a str,
    passkey: &'a Passkey,
    removable: bool,
    state: &'a SignInState,
    confirmed: bool,
) -> Result<impl View> {
    let id = passkey.id;
    let name = passkey.friendly_name.as_str();
    Ok(view! {
        if state.renaming == Some(id) {
            change_form(
                action: page,
                change: SignInChange::Rename { id, friendly_name: String::new() },
                label: "Save name",
                cancel: page.to_owned(),
                <label>
                    "Passkey name"
                    <input
                        name="friendly_name"
                        value=(state.name.as_deref().unwrap_or(name))
                        maxlength="80"
                        required=""
                        autofocus=""
                    >
                </label>
            )
        } else if state.removing == Some(id) {
            <div class="stack">
                <strong tabindex="-1" autofocus="">(format!("Remove “{name}”?"))</strong>
                <p class="help">"You won’t be able to use this passkey to sign in again."</p>
                change_form(
                    action: page,
                    change: SignInChange::Remove { id },
                    label: "Confirm removal",
                    class: "danger",
                    confirm: !confirmed,
                    cancel: page.to_owned(),
                )
            </div>
        } else {
            <div class="row between">
                <div><strong>(name)</strong></div>
                <div class="row">
                    open(
                        page: page,
                        opens: SignInState { renaming: Some(id), ..SignInState::default() },
                        label: "Rename",
                        aria_label: format!("Rename {name}"),
                    )
                    open(
                        page: page,
                        opens: SignInState { removing: Some(id), ..SignInState::default() },
                        label: "Remove",
                        aria_label: format!("Remove {name}"),
                        disabled: !removable,
                    )
                </div>
            </div>
        }
    })
}

/// Adding a passkey, which the SDK runs: the button stays disabled, and says so,
/// until it finds the browser can create passkeys. Once added, the SDK posts the
/// form to `page`, which says so. On Android, it offers Google Password Manager.
#[component]
async fn enroll(page: &str, android: bool) -> Result<impl View> {
    Ok(view! {
        <form class="stack" method="post" action=(page) data-passkey-enroll="">
            hidden(fields: SignInChange::Enrolled {})
            <label>
                "New passkey name"
                <input name="friendly_name" maxlength="80" required="" autocomplete="off">
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
            <p class="notice error" role="alert" data-passkey-error="" hidden=""></p>
            <p class="help" data-unavailable="">
                "Adding a passkey needs a browser that supports them, with scripts allowed."
            </p>
            <button class="secondary full" disabled="">"Add a passkey"</button>
        </form>
    })
}

/// The social sign-in section of [`sign_in_methods`].
#[component]
async fn social<'a>(
    page: &'a str,
    providers: &'a [ProviderRow<'a>],
    state: &'a SignInState,
    confirmed: bool,
) -> Result<impl View> {
    Ok(view! {
        <section class="card" aria-labelledby="social-heading">
            <h2 id="social-heading">"Social sign-in"</h2>
            <p class="help">
                "Linked providers can sign you in. Only a passkey can authorize changes to these settings."
            </p>
            <ul class="list">
                for row in providers {
                    <li>
                        provider_row(
                            page: page,
                            row: *row,
                            unlinking: state.unlinking == Some(row.provider),
                            confirmed: confirmed,
                        )
                    </li>
                }
            </ul>
            if providers.is_empty() {
                <p class="empty">"Social sign-in is not available yet."</p>
            }
        </section>
    })
}

/// One provider of [`social`]: whether it is linked, and linking or unlinking it.
/// The open unlinking row takes the focus.
#[component]
async fn provider_row<'a>(
    page: &'a str,
    row: ProviderRow<'a>,
    unlinking: bool,
    confirmed: bool,
) -> Result<impl View> {
    let provider = row.provider;
    let name = provider_name(provider);
    Ok(view! {
        <div class="row between">
            <div>
                <strong>(name)</strong>
                <p class="help">
                    (match row.identity {
                        Some(identity) => identity.linked_email.as_deref().unwrap_or("Linked to your account"),
                        None => "Not linked",
                    })
                </p>
                if !row.enabled {
                    <p class="help">(format!("{name} sign-in is currently unavailable."))</p>
                }
            </div>
            if row.identity.is_some() {
                open(
                    page: page,
                    opens: SignInState { unlinking: Some(provider), ..SignInState::default() },
                    label: "Unlink",
                    aria_label: format!("Unlink {name}"),
                    secondary: true,
                )
            } else if row.enabled {
                change_form(
                    action: page,
                    change: SignInChange::Link { provider },
                    label: format!("Link {name}"),
                    class: "secondary",
                )
            }
        </div>
        if row.identity.is_some() && unlinking {
            <div class="notice stack">
                <p tabindex="-1" autofocus="">(format!("Remove {name} sign-in? Your passkeys will still work."))</p>
                change_form(
                    action: page,
                    change: SignInChange::Unlink { provider },
                    label: "Confirm unlink",
                    class: "danger",
                    confirm: !confirmed,
                    cancel: page.to_owned(),
                )
            </div>
        }
    })
}
