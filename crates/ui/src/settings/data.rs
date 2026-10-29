//! The account's data: downloading it, and deleting the account.

use crate::{
    Section, Title,
    form::{Precision, Query, change_form, open, time},
    layout::frame,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the data page posts, named by its `action` field. Each needs a recent
/// passkey confirmation. A field the user types is left empty here, and the form
/// renders its input instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DataChange {
    /// Downloads every record of the account.
    Export,
    /// Schedules the account's deletion.
    Delete {
        /// The account's handle, typed to confirm.
        #[serde(skip_serializing_if = "String::is_empty")]
        handle: String,
    },
}

/// Whether the data page's deletion row is open, as its query names it.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct DataState {
    /// The deletion awaits its confirmation.
    #[serde(rename = "delete", default)]
    pub deleting: bool,
}

impl Query for DataState {}

/// The data page: downloading the account's records, and deleting the account,
/// whose `handle` confirms it, after `grace_days` days. Its changes post to `page`,
/// which `state` opens; `confirmed` says whether the session needs no passkey
/// confirmation for them.
#[component]
pub async fn account_data<'a>(
    page: &'a str,
    handle: &'a str,
    grace_days: i64,
    state: DataState,
    confirmed: bool,
) -> Result<impl View> {
    Ok(view! {
        <section class="card stack" aria-labelledby="export-heading">
            <h2 id="export-heading">"Download your data"</h2>
            <p class="help">
                "Everything Piquel keeps about your account, in one JSON file: your profile, email addresses, passkeys, devices, connected apps, the apps you registered, account recoveries and your security history. It holds no passkey keys or secrets."
            </p>
            change_form(
                action: page,
                change: DataChange::Export,
                label: "Download your data",
                class: "secondary full",
                confirm: !confirmed,
            )
        </section>
        <section class="card stack" aria-labelledby="delete-heading">
            <h2 id="delete-heading">"Delete your account"</h2>
            <p class="help">
                (format!(
                    "Your account stops working at once and every device is signed out. It is deleted for good after {grace_days} days, with the apps you registered; until then, signing in with your passkey restores it. Apps you signed in to keep their own records of you."
                ))
            </p>
            if state.deleting {
                <div class="notice stack">
                    <p tabindex="-1" autofocus="">"Delete your account?"</p>
                    change_form(
                        action: page,
                        change: DataChange::Delete { handle: String::new() },
                        label: "Delete my account",
                        class: "danger",
                        confirm: !confirmed,
                        cancel: page.to_owned(),
                        <label>
                            (format!("Type your handle, {handle}, to confirm"))
                            <input
                                name="handle"
                                autocomplete="off"
                                autocapitalize="none"
                                spellcheck="false"
                                required=""
                            >
                        </label>
                    )
                </div>
            } else {
                open(
                    page: page,
                    opens: DataState { deleting: true },
                    label: "Delete account",
                    secondary: true,
                )
            }
        </section>
    })
}

/// The account just scheduled for deletion, which is purged at `purge_after`
/// unless its owner signs in at `sign_in` with their passkey before then.
#[component]
pub async fn account_deleted<'a>(
    purge_after: DateTime<Utc>,
    sign_in: &'a str,
) -> Result<impl View> {
    Ok(view! {
        frame(
            section: Section::Account,
            title: Title::AccountDeleted.as_str(),
            <div class="card stack">
                <p>
                    "Every device was signed out. Your account will be deleted for good on "
                    time(at: purge_after, precision: Precision::Day)
                    ". Changed your mind? Sign in with your passkey before then to restore it."
                </p>
                <a class="button secondary" href=(sign_in)>"Restore my account"</a>
            </div>
        )
    })
}
