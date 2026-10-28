//! The handle, passkeys and social sign-in.

use super::Audience;
use crate::{
    Recovery, RecoveryPasskey, RecoveryStage,
    form::{
        Ceremony, Checkbox, Precision, Query, change_form, handle_input, new_passkey, open,
        passkey_form, time,
    },
};
use chrono::{DateTime, Utc};
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
    /// Changes the account's handle, once confirmed with a passkey.
    Handle {
        /// The new handle, which the user types.
        #[serde(skip_serializing_if = "String::is_empty")]
        handle: String,
    },
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
    /// Shows that the passkey script just added a passkey, through the account API:
    /// this changes nothing.
    Enrolled {},
}

/// Which row of the sign-in methods is open, as the page's query names it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignInState {
    /// The handle is being changed.
    #[serde(default, rename = "handle", skip_serializing_if = "Checkbox::is_off")]
    pub changing_handle: Checkbox,
    /// The handle a change that failed asked for, to ask for it again.
    #[serde(skip)]
    pub handle: Option<String>,
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

/// The account's handle, as its owner's sign-in methods show it.
#[derive(Clone, Copy, Debug)]
pub struct HandleRow<'a> {
    /// The handle.
    pub handle: &'a str,
    /// When it may change again, if not yet.
    pub changeable_at: Option<DateTime<Utc>>,
}

/// The sign-in methods page: the account's `handle`, if its owner may change it
/// here, its `passkeys`, and the social sign-in `providers`. Its rows open on
/// `page` as `state` says, and its changes post there, for `audience`. On Android,
/// adding a passkey offers Google Password Manager. While the account has a
/// `recovery` that can still be undone, only its passkey can be removed.
#[component]
pub async fn sign_in_methods<'a>(
    page: &'a str,
    passkeys: &'a [Passkey],
    providers: &'a [ProviderRow<'a>],
    state: &'a SignInState,
    audience: Audience<'a>,
    android: bool,
    recovery: Option<&'a Recovery>,
    #[default] handle: Option<HandleRow<'a>>,
) -> Result<impl View> {
    Ok(view! {
        if let Some(handle) = handle {
            handle_card(page: page, row: handle, state: state, audience: audience)
        }
        passkey_list(
            page: page,
            passkeys: passkeys,
            state: state,
            audience: audience,
            android: android,
            recovery: recovery,
        )
        social(page: page, providers: providers, state: state, audience: audience)
    })
}

/// The handle section of [`sign_in_methods`]: the handle, and changing it when
/// `state` opens it, which takes the focus. While the last change is recent, it says
/// when the handle may change again instead.
#[component]
async fn handle_card<'a>(
    page: &'a str,
    row: HandleRow<'a>,
    state: &'a SignInState,
    audience: Audience<'a>,
) -> Result<impl View> {
    let current = row.handle;
    Ok(view! {
        <section class="card" aria-labelledby="handle-heading">
            <h2 id="handle-heading">"Handle"</h2>
            <p class="help">
                "Your public name on Piquel and the name you sign in with. Apps you use see it as your username."
            </p>
            if state.changing_handle.0 && row.changeable_at.is_none() {
                change_form(
                    action: page,
                    change: SignInChange::Handle { handle: String::new() },
                    label: "Change handle",
                    confirm: audience.confirms(),
                    cancel: page.to_owned(),
                    handle_input(new: true, value: state.handle.as_deref().or(Some(current)), focus: true)
                    <div class="notice stack">
                        <p>
                            <strong>(format!("@{current} stops working right away."))</strong>
                            " Links to it, and apps and services that look you up by it, stop finding you."
                        </p>
                        <p>"It stays reserved for you: nobody else can take it unless Piquel support releases it, and you can take it back later. You can change your handle once every 30 days."</p>
                    </div>
                )
            } else {
                <div class="row between">
                    <div>
                        <strong>(format!("@{current}"))</strong>
                        if let Some(at) = row.changeable_at {
                            <p class="help">
                                "You can change it again on " time(at: at, precision: Precision::Day) "."
                            </p>
                        }
                    </div>
                    open(
                        page: page,
                        opens: SignInState { changing_handle: Checkbox(true), ..SignInState::default() },
                        label: "Change",
                        aria_label: "Change handle".to_owned(),
                        disabled: row.changeable_at.is_some(),
                    )
                </div>
            }
        </section>
    })
}

/// The passkeys section of [`sign_in_methods`].
#[component]
async fn passkey_list<'a>(
    page: &'a str,
    passkeys: &'a [Passkey],
    state: &'a SignInState,
    audience: Audience<'a>,
    android: bool,
    recovery: Option<&'a Recovery>,
) -> Result<impl View> {
    let count = passkeys.len();
    let added = recovery.and_then(Recovery::passkey);
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
                    let recovered = added == Some(passkey.id);
                    <li>
                        passkey_row(
                            page: page,
                            passkey: passkey,
                            recovered: recovered,
                            removable: count > 1 && !recovery.is_some_and(|recovery| recovery.keeps(passkey.id)),
                            state: state,
                            audience: audience,
                        )
                    </li>
                }
            </ul>
            if passkeys.is_empty() {
                <p class="empty">
                    (if audience.owns() { "Add your first passkey to protect your account." } else { "No passkey." })
                </p>
            }
            if audience.owns() {
                enroll(page: page, android: android)
            }
            <p class="help">"Your last passkey cannot be removed."</p>
            match recovery.map(|recovery| recovery.stage) {
                Some(RecoveryStage::Open { .. }) => {
                    <p class="help">"Passkeys can't be removed while the recovery can be cancelled."</p>
                }
                Some(RecoveryStage::Probation { settles_at, .. }) => {
                    <p class="help">
                        (if added.is_some() && count > 1 {
                            format!("Only {} can be removed until the recovery settles on ", RecoveryPasskey::NAME)
                        } else {
                            "Passkeys can't be removed until the recovery settles on ".to_owned()
                        })
                        time(at: settles_at, precision: Precision::Day)
                        "."
                    </p>
                }
                None => {}
            }
        </section>
    })
}

/// One passkey of [`passkey_list`]: its name and when it was added, or the open
/// rename or removal row, which takes the focus. The passkey a recovery added,
/// which whoever used its link may have named, is `recovered`: it goes by
/// [`RecoveryPasskey`]'s phrase, with a mark, the minute it was added and its ID,
/// and it is never renamed here. A passkey that can't be removed never opens its
/// removal row, even from a hand-made link.
#[component]
async fn passkey_row<'a>(
    page: &'a str,
    passkey: &'a Passkey,
    recovered: bool,
    removable: bool,
    state: &'a SignInState,
    audience: Audience<'a>,
) -> Result<impl View> {
    let id = passkey.id;
    let (name, removal, precision) = if recovered {
        let removal = format!("Remove {}?", RecoveryPasskey::NAME);
        (RecoveryPasskey::TITLE, removal, Precision::Minute)
    } else {
        let name = passkey.friendly_name.as_str();
        (name, format!("Remove “{name}”?"), Precision::Day)
    };
    Ok(view! {
        if state.renaming == Some(id) && !recovered {
            change_form(
                action: page,
                change: SignInChange::Rename { id, friendly_name: String::new() },
                label: "Save name",
                reason: audience.asks_reason(),
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
        } else if state.removing == Some(id) && removable {
            <div class="stack">
                <strong tabindex="-1" autofocus="">(removal)</strong>
                <p class="help">"You won’t be able to use this passkey to sign in again."</p>
                change_form(
                    action: page,
                    change: SignInChange::Remove { id },
                    label: "Confirm removal",
                    class: "danger",
                    confirm: audience.confirms(),
                    reason: audience.asks_reason(),
                    cancel: page.to_owned(),
                )
            </div>
        } else {
            <div class="row between">
                <div>
                    <div class="row">
                        <strong>(name)</strong>
                        if recovered {
                            <span class="badge">"Added by the recovery"</span>
                        }
                    </div>
                    <p class="help">
                        "Added "
                        time(at: passkey.created_at, precision: precision)
                        if recovered {
                            (format!(" · ID {id}"))
                        }
                    </p>
                </div>
                <div class="row">
                    if !recovered {
                        open(
                            page: page,
                            opens: SignInState { renaming: Some(id), ..SignInState::default() },
                            label: "Rename",
                            aria_label: format!("Rename {name}"),
                        )
                    }
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

/// Adding a passkey, which the passkey script runs, then posts the form to `page`,
/// which says so. On Android, it offers Google Password Manager.
#[component]
async fn enroll(page: &str, android: bool) -> Result<impl View> {
    Ok(view! {
        passkey_form(
            action: page,
            ceremony: Ceremony::Enroll,
            change: SignInChange::Enrolled {},
            label: "Add a passkey",
            class: "secondary full",
            new_passkey(label: "New passkey name", android: android)
        )
    })
}

/// The social sign-in section of [`sign_in_methods`].
#[component]
async fn social<'a>(
    page: &'a str,
    providers: &'a [ProviderRow<'a>],
    state: &'a SignInState,
    audience: Audience<'a>,
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
                            audience: audience,
                        )
                    </li>
                }
            </ul>
            if providers.is_empty() {
                <p class="empty">
                    (if audience.owns() { "Social sign-in is not available yet." } else { "No linked provider." })
                </p>
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
    audience: Audience<'a>,
) -> Result<impl View> {
    let provider = row.provider;
    let name = provider.name();
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
            } else if row.enabled && audience.owns() {
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
                    confirm: audience.confirms(),
                    reason: audience.asks_reason(),
                    cancel: page.to_owned(),
                )
            </div>
        }
    })
}
