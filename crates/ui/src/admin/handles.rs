//! Handles: the reserved list, the accounts holding a reserved handle, and the
//! released handles kept from others.

use super::{Action, Change, confirm, moment};
use crate::{clients::choice, layout::page_head};
use sourceorigin_common::admin::{ReleasedHandle, ReservedHandle};
use topcoat::{
    Result,
    context::Cx,
    view::{View, component, view},
};

/// An account whose current handle is reserved.
#[derive(Clone, Debug)]
pub struct ReservedHolder<'a> {
    /// The handle.
    pub handle: &'a str,
    /// Why it is reserved.
    pub why: String,
    /// The account's page.
    pub account: String,
    /// The page changing the account's handle.
    pub change: String,
}

/// A handle an administrator reserved, and the change removing it from the list.
#[derive(Clone, Debug)]
pub struct ReservationRow<'a> {
    /// The reservation.
    pub reservation: &'a ReservedHandle,
    /// Removing it.
    pub unreserve: Action,
}

/// A handle no account holds but that is kept from others, the page of the
/// account that held it, if not purged, and the change releasing it.
#[derive(Clone, Debug)]
pub struct ReleasedRow<'a> {
    /// The handle.
    pub released: &'a ReleasedHandle,
    /// The page of the account that held it, unless it was purged.
    pub account: Option<String>,
    /// Releasing it.
    pub release: Action,
}

/// What the handles page shows.
#[derive(Clone, Copy, Debug)]
pub struct HandlesPage<'a> {
    /// The handles administrators reserved.
    pub reserved: &'a [ReservationRow<'a>],
    /// The names the handle rules reserve, which no administrator changes.
    pub built_in: &'a [&'a str],
    /// The page reserving a handle.
    pub reserve: &'a str,
    /// The accounts whose current handle is reserved.
    pub holders: &'a [ReservedHolder<'a>],
    /// The handles kept from others until released.
    pub released: &'a [ReleasedRow<'a>],
}

/// The handles page: the reserved list, with the built-in names, the accounts
/// holding a reserved handle, and the released handles, each with its change.
#[component]
pub async fn handle_list<'a>(cx: &Cx, page: HandlesPage<'a>) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Handles",
            lead: "Reserve handles for the people or teams who will need them, give them out, and free the ones no account holds anymore.".to_owned(),
            actions: view! { <a data-confirm-first="" class="button" href=(page.reserve)>"Reserve a handle"</a> },
        )
        <section class="card" aria-labelledby="reserved-heading">
            <header><h2 id="reserved-heading">"Reserved"</h2></header>
            <p class="help">"Nobody can take these, or names that look like them, at signup or in their settings. Give one to an account with Change handle and “Allow a reserved handle”."</p>
            if page.reserved.is_empty() {
                <p class="empty">"No handle reserved yet."</p>
            } else {
                <ul class="list">
                    #[key(position)]
                    for (position, row) in page.reserved.iter().enumerate() {
                        let handle = format!("@{}", row.reservation.handle);
                        <li>
                            <div class="text">
                                <strong>(handle.as_str())</strong>
                                <small>(row.reservation.reason.as_str()) " · since " moment(at: row.reservation.reserved_at)</small>
                            </div>
                            confirm(action: &row.unreserve, change: Change::UnreserveHandle, subject: handle.as_str())
                        </li>
                    }
                </ul>
            }
            <div class="body">
                <p class="help">
                    "Built into the handle rules, with their look-alikes: "
                    #[key(index)]
                    for (index, name) in page.built_in.iter().enumerate() {
                        if index > 0 { ", " }
                        <code>(*name)</code>
                    }
                    "."
                </p>
            </div>
        </section>
        <section class="card" aria-labelledby="holders-heading">
            <header><h2 id="holders-heading">"Accounts holding a reserved handle"</h2></header>
            if page.holders.is_empty() {
                <p class="empty">"No account has a reserved handle."</p>
            } else {
                <ul class="list">
                    #[key(position)]
                    for (position, row) in page.holders.iter().enumerate() {
                        <li>
                            <div class="text">
                                <a href=(row.account.as_str())><strong>(format!("@{}", row.handle))</strong></a>
                                <small>(row.why.as_str())</small>
                            </div>
                            <a data-confirm-first="" class="button secondary small" href=(row.change.as_str()) aria-label=(format!("Change handle: @{}", row.handle))>"Change handle"</a>
                        </li>
                    }
                </ul>
            }
        </section>
        <section class="card" aria-labelledby="released-heading">
            <header><h2 id="released-heading">"Released"</h2></header>
            <p class="help">"Handles no account uses anymore. Each stays with the account that held it, which can take it back, until it is released for anyone to claim."</p>
            if page.released.is_empty() {
                <p class="empty">"No released handle."</p>
            } else {
                <ul class="list">
                    #[key(position)]
                    for (position, row) in page.released.iter().enumerate() {
                        let handle = format!("@{}", row.released.handle);
                        <li>
                            <div class="text">
                                <strong>(handle.as_str())</strong>
                                <small>
                                    // Only a purged account's last handle has no release time.
                                    match (&row.account, row.released.released_at) {
                                        (Some(account), Some(at)) => {
                                            "Held by " <a href=(account.as_str())>"an account"</a> " until " moment(at: at)
                                        },
                                        _ => "Held by an account since purged",
                                    }
                                </small>
                            </div>
                            confirm(action: &row.release, change: Change::ReleaseHandle, subject: handle.as_str())
                        </li>
                    }
                </ul>
            }
        </section>
    })
}

/// The choice letting a rename take a reserved handle, `checked` or not.
#[component]
pub async fn reserved_handle_choice(cx: &Cx, checked: bool) -> Result<impl View> {
    Ok(view! {
        choice(
            name: "allow_reserved",
            checked: checked,
            label: view! { "Allow a reserved handle" },
            detail: view! { "One on the Handles page's reserved list, built in such as admin or support, or one that looks like it. Give one only to whom it is kept for." },
        )
    })
}
