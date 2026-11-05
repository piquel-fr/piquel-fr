//! The admin dashboard at admin.piquel.fr: the frame of its pages, each page's
//! view, and auth's page handing an administrator off to it.
//!
//! The pages render the views of `piquel_common::admin`, as the service returns
//! them, with the links their handler resolves. Each change has its own page: a
//! `GET` shows its form, and only that form's `POST` makes the change, so a link,
//! even with a query, never changes anything. A passkey confirmation happens in
//! a dialog on the page, which the browser opens, as [`Confirmation`] says;
//! without scripts, the browser confirms on auth's handoff page, and comes back.
//! Every page works without them.

/// The audit chain's state and its checkpoints.
mod audit;
/// The OIDC clients, one client, and registering and changing them.
mod clients;
/// The outbound delivery queue.
mod deliveries;
/// Domain events, in words.
mod events;
/// Accounts whose handle is reserved, and releasing a handle.
mod handles;
/// Signing keys.
mod keys;
/// The lists: administrators and invitations.
mod lists;
/// What needs attention, and what the service is doing now.
mod overview;
/// An account's recent recoveries.
mod recoveries;
/// Account search and one account.
mod users;

pub use audit::audit_page;
pub use clients::{
    AdminClientRow, ClientChanges, ClientPage, NewClientForm, OperatorDraft, Registration,
    client_created, client_list, client_page, client_registration, client_secrets,
};
pub use deliveries::{DeliveryRow, delivery_list};
pub use events::{EventRow, event_list, event_rows};
pub use handles::{
    HandlesPage, ReleasedRow, ReservationRow, ReservedHolder, handle_list, reserved_handle_choice,
};
pub use keys::{SigningKeyRow, signing_key_list, signing_key_rotation};
pub use lists::{
    AdministratorRow, InvitationRow, administrator_list, grant_search, invitation_created,
    invitation_list,
};
pub use overview::{AdminOverview, Measure, Problem, admin_overview};
pub use recoveries::{RecoveryKey, RecoveryRow, RecoveryStanding, recovery_list};
pub use users::{AccountPages, SessionRow, UserRow, user_page, user_search};

use crate::{
    Checkbox, Query,
    browser::{AsyncHandler, Browser, CeremonyRequest, Refusal},
    form::{Ceremony, Passkey, Precision, post_form, time},
    icons::{Icon, icon},
    layout::{
        Crumb, Health, Label, NavGroup, NavItem, Policies, Preferences, Search, Shell, Who,
        page_head, shell,
    },
    settings::{Tab as SettingsTab, settings_tabs},
};
use chrono::{DateTime, Utc};
use piquel_common::{
    AccountStatus, TraceId,
    admin::{EventSearch, UserSearch},
};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    context::Cx,
    runtime::{Event, Expr, Signal, expr, signal},
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
/// handoff, and the proof, which the browser fills in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandoffProof {
    /// The state of the handoff.
    pub state: String,
    /// The dashboard path to go on to.
    pub return_to: String,
    /// The passkey's assertion, as the browser encodes it: its ceremony and the
    /// credential's JSON.
    #[serde(default)]
    pub assertion: String,
}

impl Query for UserSearch {}
impl Query for EventSearch {}

/// A page of the dashboard, as the sidebar lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// What needs attention, and what the service is doing now.
    Overview,
    /// Accounts.
    Users,
    /// Who administers Piquel.
    Administrators,
    /// Signup invitations.
    Invitations,
    /// Reserved handles, and releasing one.
    Handles,
    /// The OIDC clients.
    Clients,
    /// Domain events.
    Events,
    /// The outbound delivery queue.
    Deliveries,
    /// The keys signing tokens.
    SigningKeys,
    /// The tamper-evident audit chain.
    Audit,
}

impl Tab {
    /// Its icon in the sidebar.
    const fn icon(self) -> Icon {
        match self {
            Self::Overview => Icon::Home,
            Self::Users => Icon::Users,
            Self::Administrators => Icon::Shield,
            Self::Invitations => Icon::Invitation,
            Self::Handles => Icon::At,
            Self::Clients => Icon::Client,
            Self::Events => Icon::Events,
            Self::Deliveries => Icon::Send,
            Self::SigningKeys => Icon::Key,
            Self::Audit => Icon::Audit,
        }
    }
}

impl Label for Tab {
    /// Its name.
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Users => "Users",
            Self::Administrators => "Administrators",
            Self::Invitations => "Invitations",
            Self::Handles => "Handles",
            Self::Clients => "Clients",
            Self::Events => "Events",
            Self::Deliveries => "Deliveries",
            Self::SigningKeys => "Signing keys",
            Self::Audit => "Audit",
        }
    }
}

/// What every dashboard page's frame shows.
#[derive(Clone, Copy, Debug)]
pub struct Dashboard<'a> {
    /// The page's name, in the crumb.
    pub title: Crumb<'a>,
    /// Where the brand links: the overview.
    pub home: &'a str,
    /// The signed-in administrator, if the browser is signed in.
    pub administrator: Option<Who<'a>>,
    /// The signed-in administrator's account settings, on auth, which their
    /// avatar links.
    pub me: &'a str,
    /// Each tab's page.
    pub tabs: &'a [(Tab, &'a str)],
    /// The tab the page belongs to, if any.
    pub current: Option<Tab>,
    /// The page the page is under, inside its tab, if any, named and linked in
    /// the crumb: the account under Users, or the client under Clients.
    pub parent: Option<(&'a str, &'a str)>,
    /// Where signing out posts.
    pub sign_out: &'a str,
    /// What the browser chose, which the preference forms reverse.
    pub preferences: Preferences,
    /// Where the preference forms post.
    pub preferences_action: &'a str,
    /// The page's own path and query, which the preference forms come back to.
    pub here: &'a str,
    /// Whether the service needs attention, as the overview finds, if known.
    pub health: Option<Health>,
    /// The deployment the status bar names.
    pub environment: &'a str,
    /// Piquel's policies, which the status bar links.
    pub policies: Policies<'a>,
    /// The account search in the top bar, with what was searched, if anything.
    pub search: Search<'a>,
    /// The `reference` of a server error's trace, for the user to quote.
    pub reference: Option<TraceId>,
    /// The signed-in administrator's passkey confirmation, if the browser is
    /// signed in.
    pub confirmation: Option<Confirmation<'a>>,
}

/// The dialog confirming the dashboard with a passkey, and how long the
/// confirmation lasts. Once too little is left, the browser asks for a passkey
/// there before it follows a link marked `data-confirm-first`, to a change's page,
/// or posts a form in the page with one of its buttons, a change; then it goes on.
/// Without scripts, or in a browser that cannot run the ceremony on the
/// dashboard's origin, the browser goes on at once, and the page confirms on
/// auth's handoff page instead.
#[derive(Clone, Copy, Debug)]
pub struct Confirmation<'a> {
    /// Where the browser starts the passkey ceremony, for the dashboard's
    /// origin.
    pub start: &'a str,
    /// Where it posts the assertion, which confirms the dashboard.
    pub finish: &'a str,
    /// The seconds the confirmation still lasts: a change posted later needs a
    /// new one. Zero or less without one.
    pub left: i64,
    /// The seconds a change's page needs left to show its form: a link to one
    /// followed with less confirms first.
    pub form_time: i64,
}

/// The dashboard's [`Confirmation`] in the browser: whether the browser can run
/// its ceremony on the dashboard's origin, which it finds out as the page loads,
/// the change its dialog is open for, and the ceremony, started as the dialog
/// opens, so the button's click reaches the browser's passkey prompt at once, as
/// Safari needs. Closing the dialog drops the change.
struct Gate {
    /// Starting the ceremony.
    start: CeremonyRequest,
    /// Running it, once started, which confirms the dashboard.
    run: CeremonyRequest,
    /// The milliseconds, from when the page loaded, until the confirmation ends.
    until: f64,
    /// The milliseconds a change's page needs left to show its form.
    form_time: f64,
    /// Whether the browser runs the ceremony on the dashboard's origin, once
    /// known: until then, it does not, and the change goes on at once.
    usable: Signal<bool>,
    /// The change the dialog is open for, as [`Browser::go_on`] takes it.
    change: Signal<String>,
    /// What the ceremony's start answered, once it did.
    started: Signal<String>,
    /// Whether the ceremony runs.
    busy: Signal<bool>,
    /// Why the last one failed, if it did.
    error: Signal<String>,
}

impl Gate {
    /// The dialog's ID.
    const DIALOG: &'static str = "passkey-confirmation";

    /// The browser's state of `confirmation`.
    fn new(cx: &Cx, confirmation: Confirmation<'_>) -> Self {
        Self {
            start: CeremonyRequest::assertion(confirmation.start, confirmation.finish, true),
            run: CeremonyRequest::assertion(confirmation.start, confirmation.finish, false),
            // Whole seconds, which an `f64` holds exactly.
            #[expect(clippy::cast_precision_loss, reason = "seconds of a confirmation")]
            until: confirmation.left.max(0) as f64 * 1000.0,
            #[expect(clippy::cast_precision_loss, reason = "seconds of a confirmation")]
            form_time: confirmation.form_time as f64 * 1000.0,
            usable: signal(cx, || false),
            change: signal(cx, String::new),
            started: signal(cx, String::new),
            busy: signal(cx, || false),
            error: signal(cx, String::new),
        }
    }

    /// The dialog's `@mount` handler, which finds whether the browser runs the
    /// ceremony on the dashboard's origin.
    fn mount(&self) -> Expr<impl AsyncHandler + use<>> {
        let (usable, capable) = (self.usable.clone(), Browser::related_origins());
        expr!(async |_e: Event| {
            usable.set(raw!("await ${capable}", false));
        })
    }

    /// The `@click` handler of the page, which opens the dialog for a click
    /// making a change once too little of the confirmation is left: on a link
    /// marked `data-confirm-first`, to a change's page, which needs time left to
    /// fill in its form, or on a button posting a form. A click opening a link
    /// elsewhere, such as in a new tab, goes on as it is.
    fn intercept(&self) -> Expr<impl AsyncHandler + use<>> {
        let (usable, change, started) = (
            self.usable.clone(),
            self.change.clone(),
            self.started.clone(),
        );
        let (busy, error) = (self.busy.clone(), self.error.clone());
        let (until, form_time, now) = (self.until, self.form_time, Browser::since_load());
        let (show, hide, shown) = (
            Browser::show(Self::DIALOG),
            Browser::hide(Self::DIALOG),
            Browser::shown(Self::DIALOG),
        );
        let start = Browser::ceremony(None, &self.start, &Expr::from(String::new()));
        let go_on = Browser::go_on(&expr!(change.get()));
        expr!(async |e: Event| {
            // Topcoat's events name no element, so the change the click makes is
            // read from the DOM event: a link's `a:` and its URL, or `b:` for a
            // posting button, which it marks `data-pending`.
            let clicked = raw!(
                r#"cx.hydrate(((event) => {
                    const target = event.target instanceof Element ? event.target : null;
                    const link = target?.closest('a[data-confirm-first]');
                    if (link)
                        return event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey
                            ? 'a:' + link.href : '';
                    const button = target?.closest('button');
                    if (!button || button.type !== 'submit' || button.form?.method !== 'post') return '';
                    for (const marked of document.querySelectorAll('[data-pending]')) marked.removeAttribute('data-pending');
                    button.setAttribute('data-pending', '');
                    return 'b:';
                })(${e}.inner))"#,
                String::new()
            );
            if usable.get() {
                if !clicked.is_empty() {
                    let ahead = if clicked.starts_with("a:") {
                        form_time
                    } else {
                        0.0
                    };
                    if now + ahead >= until {
                        e.prevent_default();
                        change.set(clicked.to_owned());
                        started.set("".to_owned());
                        busy.set(false);
                        error.set("".to_owned());
                        let _shown = show;
                        let begun = raw!("await ${start}", Ok::<String, Refusal>(String::new()));
                        // A ceremony that does not start, such as when the session
                        // ended, goes on at once: the change's page then confirms on
                        // auth's handoff page.
                        if change.get() == clicked {
                            if begun.is_ok() {
                                started.set(begun.unwrap());
                            } else if shown {
                                let _hidden = hide;
                                let _went = go_on;
                            }
                        }
                    }
                }
            }
        })
    }

    /// The `@click` handler of the dialog's button, which runs the ceremony, then
    /// goes on with the change, unless the dialog closed meanwhile. A browser that
    /// refuses the dashboard's origin for auth's RP ID goes on at once.
    fn confirm(&self) -> Expr<impl AsyncHandler + use<>> {
        let (usable, change, started) = (
            self.usable.clone(),
            self.change.clone(),
            self.started.clone(),
        );
        let (busy, error) = (self.busy.clone(), self.error.clone());
        let (hide, shown) = (Browser::hide(Self::DIALOG), Browser::shown(Self::DIALOG));
        let run = Browser::ceremony(None, &self.run, &expr!(started.get()));
        let start = Browser::ceremony(None, &self.start, &Expr::from(String::new()));
        let go_on = Browser::go_on(&expr!(change.get()));
        expr!(async |_e: Event| {
            let confirming = change.get();
            busy.set(true);
            error.set("".to_owned());
            let outcome = raw!("await ${run}", Ok::<String, Refusal>(String::new()));
            // A dialog closed meanwhile, or opened for another change, confirms
            // nothing.
            if shown {
                if change.get() == confirming {
                    if outcome.is_ok() {
                        let _hidden = hide;
                        let _went = go_on;
                    } else {
                        let refusal = outcome.unwrap_err();
                        if refusal.unsupported {
                            usable.set(false);
                            let _hidden = hide;
                            let _went = go_on;
                        } else {
                            busy.set(false);
                            error.set(refusal.message);
                            // A ceremony serves one try.
                            started.set("".to_owned());
                            let again =
                                raw!("await ${start}", Ok::<String, Refusal>(String::new()));
                            if again.is_ok() {
                                started.set(again.unwrap());
                            }
                        }
                    }
                }
            }
        })
    }

    /// Whether the dialog's button is disabled: while the ceremony runs.
    fn busy(&self) -> Expr<bool> {
        let busy = self.busy.clone();
        expr!(busy.get())
    }

    /// The dialog's button's label.
    fn label(&self) -> Expr<String> {
        let busy = self.busy.clone();
        expr!(if busy.get() {
            "Waiting for your passkey…".to_owned()
        } else {
            "Confirm with a passkey".to_owned()
        })
    }

    /// The alert saying why the last ceremony failed, hidden until one does.
    fn alert<'a>(&self, cx: &'a Cx) -> Child<'a> {
        let error = self.error.clone();
        Child::new(view! {
            <p class="notice error" role="alert" :hidden=$(error.get().is_empty())>$(error.get())</p>
        })
    }
}

/// The document around every dashboard page, in the shell `dashboard` describes:
/// the sidebar of its tabs, the signed-in administrator, the status bar with the
/// service's health; then the page as `child`.
#[component]
pub async fn dashboard_frame<'a>(
    cx: &Cx,
    dashboard: &'a Dashboard<'a>,
    child: Child<'_>,
) -> Result<impl View> {
    let warning = dashboard
        .health
        .is_some_and(|health| health != Health::Normal);
    let items: Vec<_> = dashboard
        .tabs
        .iter()
        .map(|(tab, href)| NavItem {
            icon: tab.icon(),
            label: tab.label(),
            href,
            current: dashboard.current == Some(*tab),
            warning: warning && *tab == Tab::Overview,
        })
        .collect();
    // A page inside a tab, such as one account under Users, has the tab in its
    // crumb, then the page it is under; the tab's own page, at its path, is
    // named once.
    let path = dashboard.here.split('?').next().unwrap_or_default();
    let tab = dashboard
        .current
        .and_then(|current| dashboard.tabs.iter().find(|(tab, _)| *tab == current))
        .filter(|(_, href)| *href != path)
        .map(|(tab, href)| (Crumb::Label(tab.label()), *href));
    let parent = dashboard
        .parent
        .map(|(name, href)| (Crumb::Name(name), href));
    let trail: Vec<_> = tab.into_iter().chain(parent).collect();
    Ok(view! {
        let groups = [NavGroup {
            label: Some("dashboard"),
            items: &items,
        }];
        let frame = Shell {
            home: dashboard.home,
            area: "Admin",
            area_home: dashboard.home,
            groups: &groups,
            who: dashboard.administrator,
            me: dashboard.administrator.map(|_| dashboard.me),
            trail: &trail,
            page: dashboard.title,
            search: dashboard.administrator.map(|_| dashboard.search),
            preferences: dashboard.preferences,
            preferences_action: dashboard.preferences_action,
            here: dashboard.here,
            sign_out: dashboard.administrator.map(|_| dashboard.sign_out),
            health: dashboard.health,
            environment: Some(dashboard.environment),
            policies: dashboard.policies,
            reference: dashboard.reference,
        };
        if let Some(confirmation) = dashboard.confirmation {
            let gate = Gate::new(cx, confirmation);
            <div
                class="dialog"
                id=(Gate::DIALOG)
                popover=""
                role="dialog"
                aria-labelledby="passkey-confirmation-title"
                aria-describedby="passkey-confirmation-help"
                @mount=(gate.mount())
            >
                <span class="dialog-mark">icon(kind: Icon::Key)</span>
                <h2 id="passkey-confirmation-title">"Confirm it's you"</h2>
                <p class="help" id="passkey-confirmation-help">"This change needs your passkey. It confirms the dashboard only, for five minutes."</p>
                (gate.alert(cx))
                <div class="row actions">
                    <button type="button" autofocus="" :disabled=(gate.busy()) @click=(gate.confirm())>
                        (gate.label())
                    </button>
                    <button type="button" class="secondary" popovertarget=(Gate::DIALOG) popovertargetaction="hide">"Cancel"</button>
                </div>
            </div>
            shell(frame: &frame, <div class="gate" @click=(gate.intercept())>(child)</div>)
        } else {
            shell(frame: &frame, (child))
        }
    })
}

/// A change the dashboard makes after a confirmation: what it does, in the
/// words its form and its row's button use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Disabling an account, with a reason.
    Disable,
    /// Enabling a disabled account again.
    Enable,
    /// Scheduling an account's deletion, with a reason.
    Delete,
    /// Restoring an account scheduled for deletion, with a reason.
    Restore,
    /// Ending every session of an account.
    RevokeSessions,
    /// Ending one session.
    RevokeSession,
    /// Revoking an administrator's rights.
    RevokeAdministrator,
    /// Granting administrator rights.
    GrantAdministrator,
    /// Revoking an invitation.
    RevokeInvitation,
    /// Creating an invitation.
    Invite,
    /// Starting an account's recovery, with a reason.
    Recover,
    /// Undoing an account's recovery, with a reason.
    UndoRecovery,
    /// Approving an origin for a client's pages to sign users in with passkeys.
    ApproveOrigin,
    /// Removing an approved origin.
    RemoveOrigin,
    /// Changing an account's handle, with a reason.
    ChangeHandle,
    /// Letting a disabled client sign users in again.
    EnableClient,
    /// Stopping a client signing users in, until it is enabled again.
    DisableClient,
    /// Suspending a client, so that its owner cannot enable it.
    SuspendClient,
    /// Lifting a client's suspension.
    UnsuspendClient,
    /// Deleting a client for good.
    DeleteClient,
    /// Changing an account's display name, with a reason.
    ChangeDisplayName,
    /// Freeing a released handle for anyone to claim.
    ReleaseHandle,
    /// Reserving a handle, with who or what it is kept for.
    ReserveHandle,
    /// Removing a handle from the reserved list.
    UnreserveHandle,
    /// Attempting a failed or cancelled delivery again.
    RetryDelivery,
    /// Cancelling a pending or failed delivery.
    CancelDelivery,
    /// Publishing a new signing key.
    RotateSigningKey,
    /// Deleting a signing key at once.
    RevokeSigningKey,
}

impl Change {
    /// Its title, on its page and its dialog.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Disable => "Disable this account",
            Self::Enable => "Enable this account",
            Self::Delete => "Delete this account",
            Self::Restore => "Restore this account",
            Self::RevokeSessions => "Revoke every session",
            Self::RevokeSession => "Revoke this session",
            Self::RevokeAdministrator => "Revoke administrator rights",
            Self::GrantAdministrator => "Grant administrator rights",
            Self::RevokeInvitation => "Revoke this invitation",
            Self::Invite => "Invite someone",
            Self::Recover => "Recover this account",
            Self::UndoRecovery => "Undo this account's recovery",
            Self::ApproveOrigin => "Add approved origin",
            Self::RemoveOrigin => "Remove approved origin",
            Self::ChangeHandle => "Change this account's handle",
            Self::EnableClient => "Enable this client",
            Self::DisableClient => "Disable this client",
            Self::SuspendClient => "Suspend this client",
            Self::UnsuspendClient => "Lift this client's suspension",
            Self::DeleteClient => "Delete this client",
            Self::ChangeDisplayName => "Change this account's display name",
            Self::ReleaseHandle => "Release this handle",
            Self::ReserveHandle => "Reserve a handle",
            Self::UnreserveHandle => "Remove this reservation",
            Self::RetryDelivery => "Retry this delivery",
            Self::CancelDelivery => "Cancel this delivery",
            Self::RotateSigningKey => "Rotate the signing key",
            Self::RevokeSigningKey => "Revoke this signing key",
        }
    }

    /// What it does, below the title.
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Disable => {
                "The account can no longer sign in, and every session and refresh grant ends now."
            }
            Self::Enable => "The account can sign in again with its passkeys.",
            Self::Delete => {
                "The account can no longer sign in, and every session and refresh grant ends now. It is purged with its apps and personal data after 30 days, unless it is restored first; its owner can restore it by signing in with a passkey. To purge at once, use auth-service user delete --immediately, at the terminal."
            }
            Self::Restore => {
                "The account is no longer scheduled for deletion and can sign in again with its passkeys."
            }
            Self::RevokeSessions => {
                "Every browser signed in to this account is signed out, and its applications lose their refresh grants."
            }
            Self::RevokeSession => {
                "The browser is signed out, and applications signed in through it lose their refresh grants."
            }
            Self::RevokeAdministrator => {
                "The account keeps its sessions, but can no longer use this dashboard."
            }
            Self::GrantAdministrator => {
                "The account can use this dashboard and every admin operation. The dashboard cannot change it afterwards, until its rights are revoked."
            }
            Self::RevokeInvitation => "Its link stops working.",
            Self::Invite => "Creates a single-use signup link.",
            Self::Recover => {
                "For an owner who lost every passkey. Ends every session, removes the account's unverified addresses, and emails its primary verified address a link that enrolls one passkey, once, within a day. For 15 days after, that passkey signs in but confirms no change, and any older passkey can undo the recovery. Follow the evidence policy first. An account that was in someone else's hands needs auth-service user recover --revoke, at the terminal."
            }
            Self::UndoRecovery => {
                "For an owner support has confirmed, who has no passkey left from before the recovery, or whose account is disabled. In probation, removes the recovery's passkey, even the last, withdraws every consent and ends every session; its link unused, cancels the link."
            }
            Self::ApproveOrigin => {
                "Pages of the client on this origin sign users in with their Piquel passkeys. It must be the origin of one of the client's redirect URIs, and browsers honour approved origins on a few domains only, across every client."
            }
            Self::RemoveOrigin => {
                "Pages of the client on this origin stop signing users in, and send them to Piquel's pages instead. Users stay signed in."
            }
            Self::ChangeHandle => {
                "The account signs in and is shown under the new handle at once. Its old handle stays reserved for it: no other account can take it unless it is released on the Handles page, and the account can take it back."
            }
            Self::ChangeDisplayName => {
                "The account is shown under the new name at once. Applications receive it as its name once they refresh its profile."
            }
            Self::ReleaseHandle => {
                "Anyone can claim the handle again, such as after a trademark dispute. The account that held it can no longer take it back."
            }
            Self::ReserveHandle => {
                "Nobody can take the handle, or one that looks like it, at signup or in their settings. Give it to the account it is kept for with Change handle and “Allow a reserved handle”. An account that already holds it keeps it."
            }
            Self::UnreserveHandle => {
                "Anyone can claim the handle again, unless an account holds or held it."
            }
            Self::RetryDelivery => {
                "It is attempted again now. A cancelled ordered delivery cannot be retried: the deliveries after it may already have gone on without it."
            }
            Self::CancelDelivery => {
                "It is not attempted again, and the deliveries ordered after it go on without it."
            }
            Self::RotateSigningKey => {
                "Publishes a new key, which signs after a day, once verifiers have fetched it; the current key signs until then. A key already waiting is kept. Every replica picks up the change within a minute."
            }
            Self::RevokeSigningKey => {
                "For a compromised key. It leaves the key set at once, and every replica stops accepting its tokens within a minute; verifiers that cached it keep accepting them for up to an hour. Revoking the key that signs also deletes the waiting and retiring keys, whose private keys were stored beside it, and a new key signs at once."
            }
            Self::EnableClient => "It can sign users in, exchange codes and refresh tokens again.",
            Self::DisableClient => {
                "It stops signing users in, exchanging codes and refreshing tokens at once. Its owner can enable it again."
            }
            Self::SuspendClient => {
                "It stops working at once, and its owner cannot enable it again until an administrator lifts the suspension. Its owner sees that it was suspended."
            }
            Self::UnsuspendClient => {
                "Its owner can enable it again. It stays disabled until someone does."
            }
            Self::DeleteClient => {
                "It stops working at once: its refresh tokens are revoked, and its secrets and the consents users gave it are removed. Its ID can never be registered again. This cannot be undone."
            }
        }
    }

    /// Its button, on its form.
    pub(crate) const fn button(self) -> &'static str {
        match self {
            Self::Disable | Self::DisableClient => "Disable",
            Self::Enable | Self::EnableClient => "Enable",
            Self::Delete => "Schedule the deletion",
            Self::Restore => "Restore",
            Self::RevokeSessions => "Revoke all",
            Self::RevokeSession
            | Self::RevokeAdministrator
            | Self::RevokeInvitation
            | Self::RevokeSigningKey => "Revoke",
            Self::GrantAdministrator => "Grant",
            Self::Invite => "Create link",
            Self::Recover => "Send the recovery link",
            Self::UndoRecovery => "Undo the recovery",
            Self::ApproveOrigin => "Add",
            Self::RemoveOrigin | Self::UnreserveHandle => "Remove",
            Self::ChangeHandle => "Change handle",
            Self::SuspendClient => "Suspend",
            Self::UnsuspendClient => "Lift the suspension",
            Self::DeleteClient => "Delete for good",
            Self::ChangeDisplayName => "Change",
            Self::ReleaseHandle => "Release",
            Self::ReserveHandle => "Reserve",
            Self::RetryDelivery => "Retry",
            // Not "Cancel", which closes its dialog.
            Self::CancelDelivery => "Cancel delivery",
            Self::RotateSigningKey => "Rotate",
        }
    }

    /// The button opening it, on the row or page it belongs to.
    const fn label(self) -> &'static str {
        match self {
            Self::Delete | Self::DeleteClient => "Delete",
            Self::UnsuspendClient => "Lift suspension",
            Self::Recover => "Recover",
            Self::UndoRecovery => "Undo recovery",
            Self::GrantAdministrator => "Grant rights",
            Self::Invite => "Invite someone",
            Self::Disable
            | Self::Enable
            | Self::Restore
            | Self::RevokeSessions
            | Self::RevokeSession
            | Self::RevokeAdministrator
            | Self::RevokeInvitation
            | Self::ApproveOrigin
            | Self::RemoveOrigin
            | Self::ChangeHandle
            | Self::EnableClient
            | Self::DisableClient
            | Self::SuspendClient
            | Self::ChangeDisplayName
            | Self::ReleaseHandle
            | Self::ReserveHandle
            | Self::UnreserveHandle
            | Self::RetryDelivery
            | Self::CancelDelivery
            | Self::RotateSigningKey
            | Self::RevokeSigningKey => self.button(),
        }
    }

    /// Whether it takes something away, which its buttons show.
    const fn danger(self) -> bool {
        matches!(
            self,
            Self::Disable
                | Self::Delete
                | Self::RevokeSessions
                | Self::RevokeSession
                | Self::RevokeAdministrator
                | Self::RevokeInvitation
                | Self::Recover
                | Self::UndoRecovery
                | Self::RemoveOrigin
                | Self::DisableClient
                | Self::SuspendClient
                | Self::DeleteClient
                | Self::ReleaseHandle
                | Self::UnreserveHandle
                | Self::CancelDelivery
                | Self::RevokeSigningKey
        )
    }

    /// The label of the reason its form asks for, if it asks for one.
    const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Disable => Some("Reason"),
            Self::Delete | Self::Restore | Self::ChangeHandle | Self::ChangeDisplayName => {
                Some("Reason, shown to the owner in their history")
            }
            Self::ReserveHandle => Some("Who or what it is kept for"),
            Self::Recover | Self::UndoRecovery => Some(
                "Reason, shown to the owner in their history: what was asked, never the evidence",
            ),
            Self::Enable
            | Self::RevokeSessions
            | Self::RevokeSession
            | Self::RevokeAdministrator
            | Self::GrantAdministrator
            | Self::RevokeInvitation
            | Self::Invite
            | Self::ApproveOrigin
            | Self::RemoveOrigin
            | Self::EnableClient
            | Self::DisableClient
            | Self::SuspendClient
            | Self::UnsuspendClient
            | Self::DeleteClient
            | Self::ReleaseHandle
            | Self::UnreserveHandle
            | Self::RetryDelivery
            | Self::CancelDelivery
            | Self::RotateSigningKey
            | Self::RevokeSigningKey => None,
        }
    }
}

/// A change's button on a row, with where it posts: its page, at `href`. A
/// dashboard confirmed with a passkey makes the change `inline`, from a dialog
/// on the row's page; one that is not links the page, which confirms first,
/// in the frame's dialog where the browser can open it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// The change's page, whose `POST` makes it.
    pub href: String,
    /// Whether the page it is on may show its form in a dialog.
    pub inline: bool,
}

impl Action {
    /// The ID of its dialog, from its page and the `subject` it acts on, when
    /// several rows of a page post to the same page.
    fn dialog(&self, subject: Option<&str>) -> String {
        let id = self
            .href
            .chars()
            .chain(subject.unwrap_or_default().chars())
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>();
        format!("dialog{id}")
    }
}

/// The page of one change: what it does, its inputs as `child`, why the last
/// attempt was refused, if it was, and its button, beside a link back to `back`.
/// A change that asks why shows its reason input, holding the `reason` last
/// typed. The handler confirms a recent passkey before showing it.
#[component]
pub async fn dashboard_change<'a>(
    cx: &Cx,
    change: Change,
    back: &'a str,
    #[into]
    #[default]
    refusal: Option<&'a str>,
    #[into]
    #[default]
    reason: Option<&'a str>,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        page_head(title: change.title(), lead: change.description().to_owned())
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        <section class="card">
            post_form(class: "stack",
                (child)
                reason_field(change: change, value: reason)
                <div class="row actions">
                    <button class=(class!("danger" if change.danger()))>(change.button())</button>
                    <a class="button secondary" href=(back)>"Cancel"</a>
                </div>
            )
        </section>
    })
}

/// The reason input of `change`'s form, if it asks why, holding `value`.
#[component]
async fn reason_field<'a>(
    cx: &Cx,
    change: Change,
    #[into]
    #[default]
    value: Option<&'a str>,
) -> Result<impl View> {
    Ok(view! {
        if let Some(label) = change.reason() {
            <label>
                (label)
                <input name="reason" required="" maxlength="500" value=(value) autofocus="">
            </label>
        }
    })
}

/// A row's button making `change` through `action`: a dialog on the page, posting
/// to the change's page with the hidden fields of `child`, once the dashboard
/// confirmed a passkey, which the browser opens and closes with no script; a
/// link to the change's page otherwise. When several rows of a page make the
/// same change to different things, each names its `subject`, which its dialog
/// shows and its button is named by.
#[component]
pub(crate) async fn confirm<'a>(
    cx: &Cx,
    action: &'a Action,
    change: Change,
    #[into]
    #[default]
    subject: Option<&'a str>,
    #[default] child: Child<'_>,
) -> Result<impl View> {
    let class = if change.danger() {
        "button danger small"
    } else {
        "button secondary small"
    };
    let dialog = action.dialog(subject);
    let name = subject.map(|subject| format!("{}: {subject}", change.title()));
    Ok(view! {
        if action.inline {
            <button type="button" class=(class) popovertarget=(dialog.as_str()) aria-label=(name.as_deref())>(change.label())</button>
            // The title's ID is prefixed, so no subject can make it another
            // dialog's ID: every dialog's starts with "dialog".
            <div class="dialog" id=(dialog.as_str()) popover="" role="dialog" aria-labelledby=(format!("title-{dialog}"))>
                <h2 id=(format!("title-{dialog}"))>(change.title())</h2>
                if let Some(subject) = subject {
                    <p><strong>(subject)</strong></p>
                }
                <p class="help">(change.description())</p>
                post_form(action: action.href.as_str(),
                    (child)
                    reason_field(change: change)
                    <div class="row actions">
                        <button class=(class!("danger" if change.danger()))>(change.button())</button>
                        <button type="button" class="secondary" popovertarget=(dialog.as_str()) popovertargetaction="hide">"Cancel"</button>
                    </div>
                )
            </div>
        } else {
            <a data-confirm-first="" class=(class) href=(action.href.as_str()) aria-label=(name.as_deref())>(change.label())</a>
        }
    })
}

/// An account's settings tab, as an administrator changes them: the `tabs`,
/// `current` among them, why the change just posted was refused, if it was, and
/// the tab's section as `child`.
#[component]
pub async fn account_settings<'a>(
    cx: &Cx,
    tabs: &'a [(SettingsTab, &'a str)],
    current: SettingsTab,
    #[into]
    #[default]
    refusal: Option<&'a str>,
    child: Child<'_>,
) -> Result<impl View> {
    Ok(view! {
        settings_tabs(tabs: tabs, current: current)
        if let Some(refusal) = refusal {
            <p class="notice error" role="alert">(refusal)</p>
        }
        (child)
    })
}

/// A change the service would refuse, shown disabled with the `reason`.
#[component]
pub(crate) async fn refused_action<'a>(
    cx: &Cx,
    label: &'a str,
    reason: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <span class="refused">
            <button class="secondary small" disabled="" title=(reason)>(label)</button>
            <small>(reason)</small>
        </span>
    })
}

/// An account's status, as a badge.
#[component]
pub(crate) async fn account_status(cx: &Cx, status: AccountStatus) -> Result<impl View> {
    let (tone, label) = match status {
        AccountStatus::Active => ("ok", "Active"),
        AccountStatus::Disabled => ("neutral", "Disabled"),
        AccountStatus::Deleting => ("warning", "Deleting"),
    };
    Ok(view! {
        <span class=(class!("badge", tone))>(label)</span>
    })
}

/// A moment, to the minute, in UTC.
#[component]
pub(crate) async fn moment(cx: &Cx, at: DateTime<Utc>) -> Result<impl View> {
    Ok(view! { time(at: at, precision: Precision::Minute) })
}

/// What an account that does not administer Piquel sees, on the dashboard or on
/// auth's handoff page, and where it may go instead.
#[component]
pub async fn no_access<'a>(cx: &Cx, home: &'a str) -> Result<impl View> {
    Ok(view! {
        <h1>"This account has no access"</h1>
        <p class="lead">"Only administrators can use the admin dashboard."</p>
        <a class="button secondary" href=(home)>"Back to your account"</a>
    })
}

/// What a page says when the service refused it, or a sign-in did not work:
/// `title`, the `detail` of why, and a link to `retry`, if there is one.
#[component]
pub async fn dashboard_failure<'a>(
    cx: &Cx,
    title: &'a str,
    #[into] detail: String,
    #[into]
    #[default]
    retry: Option<String>,
) -> Result<impl View> {
    Ok(view! {
        <h1>(title)</h1>
        <p class="lead">(detail)</p>
        if let Some(retry) = retry {
            <div class="row"><a class="button" href=(retry)>"Sign in again"</a></div>
        }
    })
}

/// What the dashboard says once signed out: signing in again, at `sign_in`, is
/// quick while the Piquel session lasts, which signs out at `auth_sign_out`.
#[component]
pub async fn dashboard_signed_out<'a>(
    cx: &Cx,
    sign_in: &'a str,
    auth_sign_out: &'a str,
) -> Result<impl View> {
    Ok(view! {
        <h1>"Signed out of the dashboard"</h1>
        <p class="lead">"You are still signed in to your Piquel account, so signing in to the dashboard again is quick."</p>
        <div class="row actions">
            <a class="button" href=(sign_in)>"Sign in again"</a>
            <a class="button secondary" href=(auth_sign_out)>"Sign out of Piquel"</a>
        </div>
    })
}

/// Auth's page asking an administrator to prove a passkey before going on to the
/// dashboard to make a change: its form posts to `action` once the browser ran
/// the ceremony `proof` starts, for this handoff only. It posts the handoff
/// `query` asked for, and says why the last proof was refused, as `alert`, if it
/// was.
#[component]
pub async fn handoff_proof<'a>(
    cx: &Cx,
    action: &'a str,
    proof: &'a str,
    query: &'a HandoffQuery,
    #[into]
    #[default]
    alert: Option<&'a str>,
) -> Result<impl View> {
    let ceremony = Ceremony::Prove { start: proof };
    let passkey = Passkey::new(cx, ceremony);
    Ok(view! {
        <div>
            <h1>"Confirm it's you"</h1>
            <p class="lead">"The admin dashboard needs your passkey before it makes a change. It counts for the dashboard only, for five minutes."</p>
        </div>
        if let Some(alert) = alert {
            <p class="notice error" role="alert">(alert)</p>
        }
        <form
            id=(passkey.id())
            class="stack"
            method="post"
            action=(action)
            @mount=(passkey.mount())
            @submit=(passkey.submit())
            :aria-busy=(passkey.busy())
        >
            <input type="hidden" name="state" value=(query.state.as_str())>
            <input type="hidden" name="return_to" value=(query.return_to.as_str())>
            <input type="hidden" name="assertion" value="">
            (passkey.alert(cx))
            (passkey.unavailable(cx, ceremony.unavailable()))
            <button :disabled=(passkey.disabled(true))>(passkey.label("Confirm with a passkey"))</button>
        </form>
    })
}
