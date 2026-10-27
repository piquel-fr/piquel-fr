//! Email addresses, and confirming one.

use super::Audience;
use crate::{
    Section, Title,
    form::{Query, change_form, fragment_form, open},
    layout::frame,
};
use piquel_common::EmailId;
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the addresses page posts, named by its `action` field. Each needs a
/// recent passkey confirmation. A field the user types is left empty here, and
/// the form renders its input instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum EmailChange {
    /// Adds an address, or sends a pending one a new link.
    Add {
        /// The address, which the user types unless it is resent.
        #[serde(skip_serializing_if = "String::is_empty")]
        email: String,
    },
    /// Makes a verified address the primary one.
    Primary {
        /// The address.
        id: EmailId,
    },
    /// Removes an address.
    Remove {
        /// The address.
        id: EmailId,
    },
}

/// Which row of the addresses is open, as the page's query names it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EmailsState {
    /// The address whose removal awaits confirmation.
    #[serde(rename = "remove")]
    pub removing: Option<EmailId>,
    /// The address an addition that failed asked for, to ask for it again.
    #[serde(skip)]
    pub adding: Option<String>,
}

impl Query for EmailsState {}

/// One of the account's addresses.
#[derive(Clone, Copy, Debug)]
pub struct EmailRow<'a> {
    /// The address's ID.
    pub id: EmailId,
    /// The address.
    pub address: &'a str,
    /// Whether someone followed its verification link.
    pub verified: bool,
    /// Whether it is the primary address.
    pub primary: bool,
}

/// The email addresses page: the account's `emails`, primary first. Its rows open
/// on `page` as `state` says, and its changes post there, for `audience`. Only the
/// owner adds addresses, or sends one a new link, and only when Piquel `sends`
/// email.
#[component]
pub async fn addresses<'a>(
    page: &'a str,
    emails: &'a [EmailRow<'a>],
    state: &'a EmailsState,
    audience: Audience,
    sends: bool,
) -> Result<impl View> {
    // The primary address can be removed only while no other verified one could
    // replace it.
    let replaceable = emails.iter().any(|email| email.verified && !email.primary);
    Ok(view! {
        <p class="help">
            "Piquel sends security notices to your primary address, and apps you sign in to receive it. Every address is verified before it is used."
        </p>
        <section class="card" aria-labelledby="emails-heading">
            <div class="row between">
                <h2 id="emails-heading">"Your addresses"</h2>
                <span class="badge">(format!("{} added", emails.len()))</span>
            </div>
            <ul class="list">
                for email in emails {
                    <li>
                        address_row(
                            page: page,
                            email: *email,
                            replaceable: replaceable,
                            state: state,
                            audience: audience,
                            sends: sends,
                        )
                    </li>
                }
            </ul>
            if emails.is_empty() {
                <p class="empty">"Add an address so Piquel can tell you about changes to your account."</p>
            }
            if audience.owns() && sends {
                change_form(
                    action: page,
                    change: EmailChange::Add { email: String::new() },
                    label: "Send a confirmation link",
                    class: "secondary full",
                    confirm: audience.confirms(),
                    <label>
                        "Add an address"
                        <input
                            type="email"
                            name="email"
                            value=(state.adding.as_deref())
                            autocomplete="email"
                            maxlength="254"
                            required=""
                        >
                    </label>
                )
            } else if audience.owns() {
                <p class="help">"Piquel cannot send email right now, so addresses cannot be added."</p>
            }
        </section>
    })
}

/// One address of [`addresses`]: its status and changes, and its removal row when
/// `state` opens it, which takes the focus. The primary address can be removed only
/// while no other verified one is `replaceable` with it, and an unverified one sent
/// a new link only when Piquel `sends` email.
#[component]
async fn address_row<'a>(
    page: &'a str,
    email: EmailRow<'a>,
    replaceable: bool,
    state: &'a EmailsState,
    audience: Audience,
    sends: bool,
) -> Result<impl View> {
    let id = email.id;
    let address = email.address;
    let blocked = email.primary && replaceable;
    Ok(view! {
        <div class="row between">
            <div>
                <strong>(address)</strong>
                <p class="help">
                    (if blocked {
                        "Primary: receives security notices. Make another address primary to remove it."
                    } else if email.primary {
                        "Primary: receives security notices"
                    } else if email.verified {
                        "Verified"
                    } else {
                        "Waiting for confirmation: open the link we sent"
                    })
                </p>
            </div>
            <div class="row">
                if email.verified && !email.primary {
                    change_form(
                        action: page,
                        change: EmailChange::Primary { id },
                        label: "Make primary",
                        class: "text-button",
                        aria_label: format!("Make primary {address}"),
                        confirm: audience.confirms(),
                        reason: audience.asks_reason(),
                    )
                }
                if sends && !email.verified && audience.owns() {
                    change_form(
                        action: page,
                        change: EmailChange::Add { email: address.to_owned() },
                        label: "Resend link",
                        class: "text-button",
                        aria_label: format!("Resend link to {address}"),
                        confirm: audience.confirms(),
                    )
                }
                open(
                    page: page,
                    opens: EmailsState { removing: Some(id), adding: None },
                    label: "Remove",
                    aria_label: format!("Remove {address}"),
                    disabled: blocked,
                )
            </div>
        </div>
        if state.removing == Some(id) {
            <div class="notice stack">
                <p tabindex="-1" autofocus="">
                    (format!("Remove {address}?"))
                    if email.primary {
                        " Piquel will no longer be able to email you security notices."
                    }
                </p>
                change_form(
                    action: page,
                    change: EmailChange::Remove { id },
                    label: "Confirm removal",
                    class: "danger",
                    confirm: audience.confirms(),
                    reason: audience.asks_reason(),
                    cancel: page.to_owned(),
                )
            </div>
        }
    })
}

/// Confirming an address from its verification link, which posts to `action`.
/// The link carries its token in the fragment, which never reaches a server: the
/// passkey script copies it into the form when it is posted, enabling the button
/// once it finds one, and shows instead that the link is incomplete when it has
/// none, as after a confirmation that failed, whose `alert` says why. Its links
/// lead to the addresses at `emails`.
#[component]
pub async fn verify<'a>(
    action: &'a str,
    emails: &'a str,
    #[default] alert: Option<&'a str>,
) -> Result<impl View> {
    Ok(view! {
        frame(
            section: Section::Account,
            title: Title::VerifyEmail.as_str(),
            fragment_form(
                action: action,
                change: (),
                fragments: &["token"],
                label: "Confirm this address",
                unavailable: "Confirming an address needs scripts allowed.",
                alert: alert,
                missing: view! {
                    <h2>"This link is incomplete"</h2>
                    <p>"Open the link from the email again, or add the address again to get a new one."</p>
                    <a class="button secondary" href=(emails)>"Manage your addresses"</a>
                },
                <p>
                    "Confirm only if you added this address to your own Piquel account: the email names the account it joins."
                </p>
            )
        )
    })
}

/// The address now confirmed, and whether it became the `primary` one; its link
/// leads to the addresses at `emails`.
#[component]
pub async fn verified<'a>(address: &'a str, primary: bool, emails: &'a str) -> Result<impl View> {
    Ok(view! {
        frame(
            section: Section::Account,
            title: Title::VerifyEmail.as_str(),
            <div class="card stack">
                <h2>"Address confirmed"</h2>
                <p>
                    (format!(
                        "{address} is verified{}.",
                        if primary { " and is now your primary address" } else { "" }
                    ))
                </p>
                <a class="button" href=(emails)>"Manage your addresses"</a>
            </div>
        )
    })
}
