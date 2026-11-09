//! Passkeys and social sign-in.

use super::Audience;
use crate::{
    Recovery, RecoveryPasskey, RecoveryStage,
    form::{Ceremony, Precision, Query, change_form, new_passkey, open, passkey_form, time},
    layout::page_head,
};
use serde::{Deserialize, Serialize};
use sourceorigin_common::{
    PasskeyId, Provider,
    protocol::api::{Identity, Passkey},
};
use topcoat::{
    Result,
    context::Cx,
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
    /// Shows that the browser just added a passkey, through the account API:
    /// this changes nothing.
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
    /// Whether SourceOrigin offers it now. A linked provider since disabled is still
    /// listed, so it can be unlinked.
    pub enabled: bool,
}

/// The sign-in methods page: the account's `passkeys`, and the social sign-in
/// `providers`. Its rows open on
/// `page` as `state` says, and its changes post there, for `audience`. On Android,
/// adding a passkey offers Google Password Manager. While the account has a
/// `recovery` that can still be undone, only its passkey can be removed.
#[component]
pub async fn sign_in_methods<'a>(
    cx: &Cx,
    page: &'a str,
    passkeys: &'a [Passkey],
    providers: &'a [ProviderRow<'a>],
    state: &'a SignInState,
    audience: Audience<'a>,
    android: bool,
    recovery: Option<&'a Recovery>,
) -> Result<impl View> {
    Ok(view! {
        if audience.owns() {
            page_head(
                title: "Sign-in methods",
                lead: "The passkeys and linked providers that can sign in to your account.".to_owned(),
            )
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

/// The passkeys section of [`sign_in_methods`].
#[component]
async fn passkey_list<'a>(
    cx: &Cx,
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
            <header>
                <h2 id="passkeys-heading">"Passkeys " <span class="count">(count.to_string())</span></h2>
            </header>
            <ul class="list">
                #[key(position)]
                for (position, passkey) in passkeys.iter().enumerate() {
                    let recovered = added == Some(passkey.id);
                    passkey_row(
                        page: page,
                        passkey: passkey,
                        recovered: recovered,
                        removable: count > 1 && !recovery.is_some_and(|recovery| recovery.keeps(passkey.id)),
                        state: state,
                        audience: audience,
                    )
                }
            </ul>
            if passkeys.is_empty() {
                <p class="empty">
                    (if audience.owns() { "Add your first passkey to protect your account." } else { "No passkey." })
                </p>
            }
            <p class="help">
                "Saved securely with your device or password manager. Keep a second passkey so you can always get back in: your last passkey cannot be removed."
                match recovery.map(|recovery| recovery.stage) {
                    Some(RecoveryStage::Open { .. }) => {
                        " Passkeys can't be removed while the recovery can be cancelled."
                    }
                    Some(RecoveryStage::Probation { settles_at, .. }) => {
                        (if added.is_some() && count > 1 {
                            format!(" Only {} can be removed until the recovery settles on ", RecoveryPasskey::NAME)
                        } else {
                            " Passkeys can't be removed until the recovery settles on ".to_owned()
                        })
                        time(at: settles_at, precision: Precision::Day)
                        "."
                    }
                    None => {}
                }
            </p>
            if audience.owns() {
                <details class="disclosure">
                    <summary><span class="button secondary small">"Add a passkey"</span></summary>
                    <div class="open-row">
                        enroll(page: page, android: android)
                    </div>
                </details>
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
    cx: &Cx,
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
            <li class="open">
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
            </li>
        } else if state.removing == Some(id) && removable {
            <li class="open">
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
            </li>
        } else {
            <li>
                <div class="text">
                    <strong>(name)</strong>
                    if recovered {
                        " " <span class="badge warning">"Added by the recovery"</span>
                    }
                    <small>
                        "added "
                        time(at: passkey.created_at, precision: precision)
                        if recovered {
                            (format!(" · ID {id}"))
                        }
                    </small>
                </div>
                if !recovered {
                    open(
                        page: page,
                        opens: SignInState { renaming: Some(id), ..SignInState::default() },
                        label: "Rename",
                        aria_label: format!("Rename {name}"),
                        secondary: true,
                    )
                }
                open(
                    page: page,
                    opens: SignInState { removing: Some(id), ..SignInState::default() },
                    label: "Remove",
                    aria_label: format!("Remove {name}"),
                    disabled: !removable,
                    danger: true,
                )
            </li>
        }
    })
}

/// Adding a passkey, which the browser runs, then posts the form to `page`,
/// which says so. On Android, it offers Google Password Manager.
#[component]
async fn enroll(cx: &Cx, page: &str, android: bool) -> Result<impl View> {
    Ok(view! {
        passkey_form(
            action: page,
            ceremony: Ceremony::Enroll,
            change: SignInChange::Enrolled {},
            label: "Create the passkey",
            class: "",
            new_passkey(label: "New passkey name", android: android)
        )
    })
}

/// The social sign-in section of [`sign_in_methods`].
#[component]
async fn social<'a>(
    cx: &Cx,
    page: &'a str,
    providers: &'a [ProviderRow<'a>],
    state: &'a SignInState,
    audience: Audience<'a>,
) -> Result<impl View> {
    let linked = providers
        .iter()
        .filter(|row| row.identity.is_some())
        .count();
    Ok(view! {
        <section class="card" aria-labelledby="social-heading">
            <header>
                <h2 id="social-heading">
                    "Social sign-in"
                    <span class="count">(format!("{linked} / {}", providers.len()))</span>
                </h2>
            </header>
            <ul class="list">
                #[key(position)]
                for (position, row) in providers.iter().enumerate() {
                    provider_row(
                        page: page,
                        row: *row,
                        unlinking: state.unlinking == Some(row.provider),
                        audience: audience,
                    )
                }
            </ul>
            if providers.is_empty() {
                <p class="empty">
                    (if audience.owns() { "Social sign-in is not available yet." } else { "No linked provider." })
                </p>
            }
            <p class="help">
                "Linked providers can sign you in. Only a passkey can authorize changes to these settings."
            </p>
        </section>
    })
}

/// One provider of [`social`]: whether it is linked, and linking or unlinking it.
/// The open unlinking row takes the focus.
#[component]
async fn provider_row<'a>(
    cx: &Cx,
    page: &'a str,
    row: ProviderRow<'a>,
    unlinking: bool,
    audience: Audience<'a>,
) -> Result<impl View> {
    let provider = row.provider;
    let name = provider.name();
    Ok(view! {
        if row.identity.is_some() && unlinking {
            <li class="open">
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
            </li>
        } else {
            <li>
                <div class="text">
                    <strong>(name)</strong>
                    <small>
                        (match row.identity {
                            Some(identity) => identity.linked_email.as_deref().unwrap_or("linked to your account"),
                            None => "not linked",
                        })
                        if !row.enabled {
                            (format!(" · {name} sign-in is currently unavailable."))
                        }
                    </small>
                </div>
                if row.identity.is_some() {
                    open(
                        page: page,
                        opens: SignInState { unlinking: Some(provider), ..SignInState::default() },
                        label: "Unlink",
                        aria_label: format!("Unlink {name}"),
                        danger: true,
                    )
                } else if row.enabled && audience.owns() {
                    change_form(
                        action: page,
                        change: SignInChange::Link { provider },
                        label: format!("Link {name}"),
                        class: "secondary small",
                    )
                }
            </li>
        }
    })
}
