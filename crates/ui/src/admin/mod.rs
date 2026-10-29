//! The admin dashboard at admin.piquel.fr: the frame of its pages, each page's
//! view, and auth's page handing an administrator off to it.
//!
//! The pages render the views of `piquel_common::admin`, as the service returns
//! them, with the links their handler resolves. Each change has its own page: a
//! `GET` shows its form, and only that form's `POST` makes the change, so a link,
//! even with a query, never changes anything. The dashboard loads no script: a
//! passkey confirmation happens on auth's handoff page.

/// The lists: administrators, invitations, clients and events.
mod lists;
/// An account's recent recoveries.
mod recoveries;
/// Account search and one account.
mod users;

pub use lists::{
    AdminClientRow, AdministratorRow, EventRow, InvitationRow, administrator_list, client_list,
    event_list, event_rows, invitation_created, invitation_list,
};
pub use recoveries::{RecoveryKey, RecoveryRow, RecoveryStanding, recovery_list};
pub use users::{AccountPages, SessionRow, UserRow, user_page, user_search};

use crate::{
    Area, Checkbox, Query, document,
    form::{Precision, time},
    layout::Label,
    settings::Tab as SettingsTab,
    settings_tabs,
};
use chrono::{DateTime, Utc};
use piquel_common::{
    AccountStatus,
    admin::{EventSearch, UserSearch},
};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{Child, View, class, component, view},
};

/// What the dashboard asks auth's handoff page for: the `state` its cookie binds
/// the handoff to, the dashboard path to go on to, and whether a passkey must
/// confirm the handoff, for a change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffQuery {
    /// The state, which only the dashboard's cookie in the asking browser holds.
    pub state: String,
    /// The dashboard path to go on to.
    pub return_to: String,
    /// Whether a passkey must confirm the handoff.
    #[serde(default, skip_serializing_if = "Checkbox::is_off")]
    pub confirm: Checkbox,
}

impl Query for HandoffQuery {}

/// What the handoff page's form posts once a passkey proved the handoff: the
/// handoff, and the proof, which the passkey script fills in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandoffProof {
    /// The state of the handoff.
    pub state: String,
    /// The dashboard path to go on to.
    pub return_to: String,
    /// The passkey's assertion, as the passkey script encodes it.
    #[serde(default)]
    pub assertion: String,
}

impl Query for UserSearch {}
impl Query for EventSearch {}

/// A tab of the dashboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// Accounts.
    Users,
    /// Who administers Piquel.
    Administrators,
    /// Signup invitations.
    Invitations,
    /// The OIDC clients.
    Clients,
    /// Domain events.
    Events,
}

impl Label for Tab {
    /// A tab's link opens its list, so it marks every page of its part.
    const CURRENT: &'static str = "true";
    /// Its name.
    fn label(self) -> &'static str {
        match self {
            Self::Users => "Users",
            Self::Administrators => "Administrators",
            Self::Invitations => "Invitations",
            Self::Clients => "Clients",
            Self::Events => "Events",
        }
    }
}

/// The document around every dashboard page, titled `title`, linking
/// `stylesheet`, whose brand links `home`: for the signed-in `administrator`, by
/// handle, the `tabs`, `current` among them, and the form signing out at
/// `sign_out`; then the page as `child`.
#[component]
pub async fn dashboard_frame<'a>(
    title: &'a str,
    stylesheet: &'a str,
    home: &'a str,
    #[into]
    #[default]
    administrator: Option<&'a str>,
    tabs: &'a [(Tab, &'a str)],
    #[into]
    #[default]
    current: Option<Tab>,
    sign_out: &'a str,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        document(
            title: title,
            stylesheet: stylesheet,
            home: home,
            area: Area::Admin,
            <section class="dashboard stack">
                if let Some(administrator) = administrator {
                    <div class="row between">
                        <nav class="site-nav" aria-label="Dashboard">
                            for (tab, href) in tabs {
                                <a href=(*href) aria-current=((Some(*tab) == current).then_some(Tab::CURRENT))>
                                    (tab.label())
                                </a>
                            }
                        </nav>
                        <form class="row" method="post" action=(sign_out) data-submit-once="">
                            <span class="muted">(format!("@{administrator}"))</span>
                            <button class="text-button">"Sign out"</button>
                        </form>
                    </div>
                }
                (child)
            </section>
        )
    })
}

/// A page heading, with a `lead` line under it, if any.
#[component]
pub(crate) async fn heading<'a>(
    title: &'a str,
    #[into]
    #[default]
    lead: Option<String>,
) -> Result<impl View> {
    Ok(view! {
        <div>
            <h1>(title)</h1>
            if let Some(lead) = lead {
                <p>(lead)</p>
            }
        </div>
    })
}

/// The page of one change: what it does, its inputs as `child`, why the last
/// attempt was refused, if it was, and its button, beside a link back to `back`.
/// The handler confirms a recent passkey before showing it.
#[component]
pub async fn dashboard_change<'a>(
    title: &'a str,
    description: &'a str,
    button: &'a str,
    back: &'a str,
    #[into]
    #[default]
    refusal: Option<&'a str>,
    #[default] danger: bool,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <section class="card narrow stack">
            <h1>(title)</h1>
            <p>(description)</p>
            if let Some(refusal) = refusal {
                <p class="notice error" role="alert">(refusal)</p>
            }
            <form class="stack" method="post" data-submit-once="">
                (child)
                <div class="row actions">
                    <button class=(class!("danger" if danger))>(button)</button>
                    <a class="button secondary" href=(back)>"Cancel"</a>
                </div>
            </form>
        </section>
    })
}

/// An account's settings tab, as an administrator changes them: a link `back` to
/// the account, the `tabs`, `current` among them, why the change just posted was
/// refused, if it was, and the tab's section as `child`.
#[component]
pub async fn account_settings<'a>(
    back: &'a str,
    tabs: &'a [(SettingsTab, &'a str)],
    current: SettingsTab,
    #[into]
    #[default]
    refusal: Option<&'a str>,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        <a href=(back)>"Back to the account"</a>
        settings_tabs(tabs: tabs, current: current)
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        (child)
    })
}

/// A change the service would refuse, shown disabled with the `reason`.
#[component]
pub(crate) async fn refused_action<'a>(label: &'a str, reason: &'a str) -> Result<impl View> {
    Ok(view! {
        <span class="row">
            <button class="secondary" disabled="" title=(reason)>(label)</button>
            <small>(reason)</small>
        </span>
    })
}

/// An account's status.
#[component]
pub(crate) async fn account_status(status: AccountStatus) -> Result<impl View> {
    Ok(view! {
        <span class=(class!("badge", "disabled" if status != AccountStatus::Active))>
            (status.to_string())
        </span>
    })
}

/// A moment, to the minute, in UTC.
#[component]
pub(crate) async fn moment(at: DateTime<Utc>) -> Result<impl View> {
    Ok(view! { time(at: at, precision: Precision::Minute) })
}

/// What an account that does not administer Piquel sees, on the dashboard or on
/// auth's handoff page, and where it may go instead.
#[component]
pub async fn no_access<'a>(home: &'a str) -> Result<impl View> {
    Ok(view! {
        <section class="card narrow stack">
            <h1>"This account has no access"</h1>
            <p>"Only administrators can use the admin dashboard."</p>
            <a class="button secondary" href=(home)>"Back to your account"</a>
        </section>
    })
}

/// What a page says when the service refused it, or a sign-in did not work:
/// `title`, the `detail` of why, and a link to `retry`, if there is one.
#[component]
pub async fn dashboard_failure<'a>(
    title: &'a str,
    #[into] detail: String,
    #[into]
    #[default]
    retry: Option<String>,
) -> Result<impl View> {
    Ok(view! {
        <section class="card narrow stack">
            <h1>(title)</h1>
            <p>(detail)</p>
            if let Some(retry) = retry {
                <a class="button" href=(retry)>"Sign in again"</a>
            }
        </section>
    })
}

/// What the dashboard says once signed out: signing in again, at `sign_in`, is
/// quick while the Piquel session lasts, which signs out at `auth_sign_out`.
#[component]
pub async fn dashboard_signed_out<'a>(
    sign_in: &'a str,
    auth_sign_out: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <section class="card narrow stack">
            <h1>"Signed out of the dashboard"</h1>
            <p>"You are still signed in to your Piquel account, so signing in to the dashboard again is quick."</p>
            <div class="row actions">
                <a class="button" href=(sign_in)>"Sign in again"</a>
                <a class="button secondary" href=(auth_sign_out)>"Sign out of Piquel"</a>
            </div>
        </section>
    })
}

/// Auth's page asking an administrator to prove a passkey before going on to the
/// dashboard to make a change: its form posts to `action` once the
/// passkey script ran the ceremony `proof` starts, for this handoff only. It
/// posts the handoff `query` asked for, and says why the last proof was refused,
/// as `alert`, if it was.
#[component]
pub async fn handoff_proof<'a>(
    action: &'a str,
    proof: &'a str,
    query: &'a HandoffQuery,
    #[into]
    #[default]
    alert: Option<&'a str>,
) -> Result<impl View> {
    Ok(view! {
        <section class="card narrow stack">
            <h1>"Confirm it's you"</h1>
            <p>"The admin dashboard needs your passkey before it makes a change. It counts for the dashboard only, for five minutes."</p>
            if let Some(alert) = alert {
                <p class="notice error" role="alert">(alert)</p>
            }
            <form
                class="stack"
                method="post"
                action=(action)
                data-passkey-assertion=(proof)
            >
                <input type="hidden" name="state" value=(query.state.as_str())>
                <input type="hidden" name="return_to" value=(query.return_to.as_str())>
                <input type="hidden" name="assertion" value="">
                <p class="notice error" role="alert" data-passkey-error="" hidden=""></p>
                <p class="help" data-unavailable="">"Confirming needs a browser that supports passkeys, with scripts allowed."</p>
                <button disabled="">"Confirm with a passkey"</button>
            </form>
        </section>
    })
}
