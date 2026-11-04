//! Accounts whose handle is reserved, and releasing a handle.

use super::{Change, dashboard_change};
use crate::{clients::choice, layout::page_head};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// An account whose current handle the handle rules reserve.
#[derive(Clone, Debug)]
pub struct ReservedHandle<'a> {
    /// The handle.
    pub handle: &'a str,
    /// Why the rules reserve it.
    pub why: String,
    /// The account's page.
    pub account: String,
    /// The page renaming the account.
    pub rename: String,
}

/// The accounts whose handle is reserved, `rows`, and the page releasing a
/// handle at `release`.
#[component]
pub async fn handle_list<'a>(
    rows: &'a [ReservedHandle<'a>],
    release: &'a str,
) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Handles",
            lead: "Accounts whose handle the handle rules reserve: an administrator gave it on purpose, or a later rule reserved it.".to_owned(),
            actions: view! { <a class="button secondary" href=(release)>"Release a handle"</a> },
        )
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No account has a reserved handle."</p>
            } else {
                <ul class="list">
                    for row in rows {
                        <li>
                            <div class="text">
                                <a href=(row.account.as_str())><strong>(format!("@{}", row.handle))</strong></a>
                                <small>(row.why.as_str())</small>
                            </div>
                            <a class="button secondary small" href=(row.rename.as_str()) aria-label=(format!("Rename @{}", row.handle))>"Rename"</a>
                        </li>
                    }
                </ul>
            }
        </section>
    })
}

/// The page releasing a handle, with why the last attempt was `refused`, if it
/// was, holding the handle `typed`; it goes back to `back`.
#[component]
pub async fn handle_release<'a>(
    back: &'a str,
    #[into]
    #[default]
    refused: Option<&'a str>,
    typed: &'a str,
) -> Result<impl View> {
    Ok(view! {
        dashboard_change(
            change: Change::ReleaseHandle,
            back: back,
            refusal: refused,
            <label>
                "Handle"
                <input name="handle" required="" maxlength="32" autocomplete="off" value=(typed) autofocus="">
            </label>
        )
    })
}

/// The choice letting a rename take a reserved handle, `checked` or not.
#[component]
pub async fn reserved_handle_choice(checked: bool) -> Result<impl View> {
    Ok(view! {
        choice(
            name: "allow_reserved",
            checked: checked,
            label: view! { "Allow a reserved handle" },
            detail: view! { "A name the handle rules keep for Piquel, such as admin or support, or one that looks like it. Give one only on purpose, such as to an official account." },
        )
    })
}
