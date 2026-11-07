//! The admin dashboard at admin.piquel.fr: the frame of its pages, each page's
//! view, and auth's page handing an administrator off to it.
//!
//! The pages render the views of `piquel_common::admin`, as the service returns
//! them, with the links their handler resolves. Each change has its own page: a
//! `GET` shows its form, and only that form's `POST` makes the change, so a link,
//! even with a query, never changes anything. A passkey confirmation happens in
//! a dialog on the page, which the dashboard's one script opens, as
//! [`Confirmation`] says; without the script, the browser confirms on auth's
//! handoff page, and comes back. Every page works without it.

/// Announcements to accounts.
mod announcements;
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

pub use announcements::{
    AdminAnnouncementRow, DraftActions, FoundAccount, announcement_form, announcement_list,
    announcement_page,
};
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
    form::{Precision, time},
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
    admin::{EventSearch, SendAnnouncement, UserSearch},
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
impl Query for SendAnnouncement {}

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
    /// Announcements to accounts.
    Announcements,
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
            Self::Announcements => Icon::Megaphone,
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
            Self::Announcements => "Announcements",
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

/// The dialog confirming the dashboard with a passkey, which its script opens,
/// and how long the confirmation lasts, which it reads from the dialog. Once too
/// little is left, it asks for a passkey there before it follows a link marked
/// `data-confirm-first`, to a change's page, or posts a form in the page's
/// `<main>`, a change, unless the form is marked `data-unconfirmed`, as a draft
/// announcement's changes are; then it goes on. Without the script, or a browser that
/// cannot run the ceremony on the dashboard's origin, the browser goes on at
/// once, and the page confirms on auth's handoff page instead.
#[derive(Clone, Copy, Debug)]
pub struct Confirmation<'a> {
    /// Where the script starts the passkey ceremony, for the dashboard's
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

/// The document around every dashboard page, in the shell `dashboard` describes:
/// the sidebar of its tabs, the signed-in administrator, the status bar with the
/// service's health; then the page as `child`.
#[component]
pub async fn dashboard_frame<'a>(
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
            count: None,
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
            // Only the account's own pages on auth tell the password manager.
            signal: None,
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
            <div
                class="dialog"
                id="passkey-confirmation"
                popover=""
                role="dialog"
                aria-labelledby="passkey-confirmation-title"
                aria-describedby="passkey-confirmation-help"
                data-confirmation-start=(confirmation.start)
                data-confirmation-finish=(confirmation.finish)
                data-confirmed-for=(confirmation.left.max(0).to_string())
                data-form-time=(confirmation.form_time.to_string())
            >
                <span class="dialog-mark">icon(kind: Icon::Key)</span>
                <h2 id="passkey-confirmation-title">"Confirm it's you"</h2>
                <p class="help" id="passkey-confirmation-help">"This change needs your passkey. It confirms the dashboard only, for five minutes."</p>
                <p class="notice error" role="alert" data-passkey-error="" hidden=""></p>
                <div class="row actions">
                    <button type="button" data-passkey-confirm="" autofocus="">"Confirm with a passkey"</button>
                    <button type="button" class="secondary" popovertarget="passkey-confirmation" popovertargetaction="hide">"Cancel"</button>
                </div>
            </div>
        }
        shell(frame: &frame, (child))
    })
}

/// A change the dashboard makes, after a confirmation unless it changes only an
/// administrators' draft: what it does, in the words its form and its row's
/// button use.
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
    /// Drafting an announcement, which needs no confirmation.
    DraftAnnouncement,
    /// Changing a draft announcement, which needs no confirmation.
    EditAnnouncement,
    /// Sending a draft announcement.
    SendAnnouncement,
    /// Deleting a draft announcement, which needs no confirmation.
    DiscardAnnouncement,
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
            Self::DraftAnnouncement => "New announcement",
            Self::EditAnnouncement => "Edit the draft",
            Self::SendAnnouncement => "Send this announcement",
            Self::DiscardAnnouncement => "Discard this draft",
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
            Self::DraftAnnouncement => {
                "Save it as a draft to check its email first, or send it now."
            }
            Self::EditAnnouncement => "Nothing is sent until you send it.",
            Self::SendAnnouncement => {
                "Emails it to each recipient with a primary verified address, and puts it in every recipient's inbox. Nobody can change or take it back once it is sent."
            }
            Self::DiscardAnnouncement => "It is deleted, and goes to nobody.",
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
            Self::DraftAnnouncement | Self::EditAnnouncement => "Save draft",
            Self::SendAnnouncement => "Send",
            Self::DiscardAnnouncement => "Discard",
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
            | Self::RevokeSigningKey
            | Self::DraftAnnouncement
            | Self::EditAnnouncement
            | Self::SendAnnouncement
            | Self::DiscardAnnouncement => self.button(),
        }
    }

    /// Whether it needs the dashboard's recent passkey confirmation, which the
    /// dashboard's script asks for in a dialog before its link or form goes on. A
    /// draft announcement's own changes don't: a long text never outlasts one.
    const fn confirms(self) -> bool {
        !matches!(
            self,
            Self::DraftAnnouncement | Self::EditAnnouncement | Self::DiscardAnnouncement
        )
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
                | Self::DiscardAnnouncement
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
            | Self::RevokeSigningKey
            | Self::DraftAnnouncement
            | Self::EditAnnouncement
            | Self::SendAnnouncement
            | Self::DiscardAnnouncement => None,
        }
    }
}

/// A change's button on a row, with where it posts: its page, at `href`. A
/// dashboard confirmed with a passkey makes the change `inline`, from a dialog
/// on the row's page; one that is not links the page, which confirms first,
/// in the frame's dialog where the dashboard's script can open it.
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
            <form class="stack" method="post" data-submit-once="" data-unconfirmed=(!change.confirms())>
                (child)
                reason_field(change: change, value: reason)
                <div class="row actions">
                    <button class=(class!("danger" if change.danger()))>(change.button())</button>
                    <a class="button secondary" href=(back)>"Cancel"</a>
                </div>
            </form>
        </section>
    })
}

/// The reason input of `change`'s form, if it asks why, holding `value`.
#[component]
async fn reason_field<'a>(
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
                <form method="post" action=(action.href.as_str()) data-submit-once="" data-unconfirmed=(!change.confirms())>
                    (child)
                    reason_field(change: change)
                    <div class="row actions">
                        <button class=(class!("danger" if change.danger()))>(change.button())</button>
                        <button type="button" class="secondary" popovertarget=(dialog.as_str()) popovertargetaction="hide">"Cancel"</button>
                    </div>
                </form>
            </div>
        } else {
            <a data-confirm-first=(change.confirms()) class=(class) href=(action.href.as_str()) aria-label=(name.as_deref())>(change.label())</a>
        }
    })
}

/// An account's settings tab, as an administrator changes them: the `tabs`,
/// `current` among them, why the change just posted was refused, if it was, and
/// the tab's section as `child`.
#[component]
pub async fn account_settings<'a>(
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
pub(crate) async fn refused_action<'a>(label: &'a str, reason: &'a str) -> Result<impl View> {
    Ok(view! {
        <span class="refused">
            <button class="secondary small" disabled="" title=(reason)>(label)</button>
            <small>(reason)</small>
        </span>
    })
}

/// An account's status, as a badge.
#[component]
pub(crate) async fn account_status(status: AccountStatus) -> Result<impl View> {
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
pub(crate) async fn moment(at: DateTime<Utc>) -> Result<impl View> {
    Ok(view! { time(at: at, precision: Precision::Minute) })
}

/// What an account that does not administer Piquel sees, on the dashboard or on
/// auth's handoff page, and where it may go instead.
#[component]
pub async fn no_access<'a>(home: &'a str) -> Result<impl View> {
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
        <div>
            <h1>"Confirm it's you"</h1>
            <p class="lead">"The admin dashboard needs your passkey before it makes a change. It counts for the dashboard only, for five minutes."</p>
        </div>
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
    })
}
