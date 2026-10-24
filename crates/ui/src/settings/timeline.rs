//! Security history.

use super::{
    EmailChange, EmailRow, Fields, Query, SignInChange, change_form, device_name, open,
    sign_in::provider_name, time,
};
use chrono::{DateTime, Utc};
use piquel_common::{
    AuthenticationMethod, EmailId, EventId, PasskeyId, Provider,
    events::{FollowUp, HistoryActor, HistoryEntry, RevocationReason, UserAgentFamily},
    protocol::api::Passkey,
};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the history page posts, named by its `action` field. Undoing what a
/// reported entry added posts to the page that holds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HistoryChange {
    /// Reports an entry as not the owner's.
    Report {
        /// The entry.
        event_id: EventId,
        /// The entry the page started after, to stay on it.
        #[serde(default)]
        before: Option<EventId>,
    },
}

/// Which history the page shows, and which of its rows is open, as its query names
/// them.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct HistoryState {
    /// The entry the page starts after, if not the newest.
    pub before: Option<EventId>,
    /// The entry whose report awaits confirmation.
    #[serde(rename = "report")]
    pub reporting: Option<EventId>,
    /// The entry just reported.
    pub reported: Option<EventId>,
}

impl Query for HistoryState {}

/// One entry of the account's history.
#[derive(Clone, Copy, Debug)]
pub struct HistoryRow<'a> {
    /// The event, to report it.
    pub id: EventId,
    /// When it happened.
    pub occurred_at: DateTime<Utc>,
    /// What happened.
    pub entry: &'a HistoryEntry,
    /// Who did it.
    pub actor: HistoryActor,
    /// Why, as the administrator or operator who did it wrote it.
    pub reason: Option<&'a str>,
    /// The application involved, by ID and name, if any.
    pub client: Option<(&'a str, Option<&'a str>)>,
    /// The request's IP address, while kept.
    pub ip: Option<std::net::IpAddr>,
    /// The request's browser and platform, while kept.
    pub device: Option<UserAgentFamily>,
    /// Whether retention or a purge deleted the IP address and device.
    pub erased: bool,
}

/// What the account holds now, to name what entries refer to and to offer undoing
/// what a reported entry added while it is still there.
#[derive(Clone, Copy, Debug, Default)]
pub struct Holdings<'a> {
    /// The account's passkeys.
    pub passkeys: &'a [Passkey],
    /// The account's addresses.
    pub emails: &'a [EmailRow<'a>],
    /// The providers linked to the account.
    pub linked: &'a [Provider],
}

impl Holdings<'_> {
    /// The passkey `id`, if the account still has it.
    fn find_passkey(&self, id: PasskeyId) -> Option<&Passkey> {
        self.passkeys.iter().find(|passkey| passkey.id == id)
    }

    /// The address `id`, if the account still has it.
    fn find_email(&self, id: EmailId) -> Option<&EmailRow<'_>> {
        self.emails.iter().find(|email| email.id == id)
    }

    /// ` “name”` of the passkey `id`, if the account still has it.
    fn passkey(&self, id: PasskeyId) -> String {
        self.find_passkey(id)
            .map(|passkey| format!(" “{}”", passkey.friendly_name))
            .unwrap_or_default()
    }

    /// ` address` of the address `id`, if the account still has it.
    fn email(&self, id: EmailId) -> String {
        self.find_email(id)
            .map(|email| format!(" {}", email.address))
            .unwrap_or_default()
    }
}

impl HistoryRow<'_> {
    /// What happened, naming what the account still holds.
    fn describe(&self, holdings: &Holdings<'_>) -> String {
        match self.entry {
            HistoryEntry::AccountCreated { method } => match method {
                AuthenticationMethod::Passkey => "Account created with a passkey".to_owned(),
                AuthenticationMethod::Federation => {
                    "Account created with social sign-in".to_owned()
                }
            },
            HistoryEntry::SignedIn { method } => match method {
                AuthenticationMethod::Passkey => "Signed in with a passkey".to_owned(),
                AuthenticationMethod::Federation => "Signed in with a social provider".to_owned(),
            },
            HistoryEntry::SignedOut => "Signed out".to_owned(),
            HistoryEntry::SessionRevoked { reason } => Self::revocation(reason).to_owned(),
            HistoryEntry::PasskeyAdded { passkey_id } => {
                format!("Passkey{} added", holdings.passkey(*passkey_id))
            }
            HistoryEntry::PasskeyRenamed { passkey_id } => {
                format!("Passkey{} renamed", holdings.passkey(*passkey_id))
            }
            HistoryEntry::PasskeyRemoved { .. } => "Passkey removed".to_owned(),
            HistoryEntry::IdentityLinked { provider } => {
                format!("{} sign-in linked", provider_name(*provider))
            }
            HistoryEntry::IdentityUnlinked { provider } => {
                format!("{} sign-in unlinked", provider_name(*provider))
            }
            HistoryEntry::EmailAdded { email_id, address } => {
                let address = address.as_ref().map_or_else(
                    || holdings.email(*email_id),
                    |address| format!(" {address}"),
                );
                format!("Email address{address} added")
            }
            HistoryEntry::EmailVerified { email_id } => {
                format!("Email address{} confirmed", holdings.email(*email_id))
            }
            HistoryEntry::PrimaryEmailChanged { email_id } => {
                let address = holdings.email(*email_id);
                if address.is_empty() {
                    "Primary email address changed".to_owned()
                } else {
                    format!("Primary email address changed to{address}")
                }
            }
            HistoryEntry::EmailRemoved { .. } => "Email address removed".to_owned(),
            HistoryEntry::ConsentGranted { scopes } => {
                format!("Access approved: {}", scopes.join(", "))
            }
            HistoryEntry::TokenReused => {
                "An app’s sign-in was used twice, so its access was revoked".to_owned()
            }
            HistoryEntry::AccountDisabled => "Account disabled".to_owned(),
            HistoryEntry::AccountEnabled => "Account re-enabled".to_owned(),
            HistoryEntry::AccountViewed => "Account details viewed".to_owned(),
            HistoryEntry::AdministratorGranted => "Administrator rights granted".to_owned(),
            HistoryEntry::AdministratorRevoked => "Administrator rights removed".to_owned(),
            HistoryEntry::HandleChanged => "Handle changed".to_owned(),
            HistoryEntry::CompromiseReported { .. } => {
                "You reported activity that wasn’t you".to_owned()
            }
            HistoryEntry::Legacy { action, outcome } => {
                let failed = if outcome == "success" {
                    ""
                } else {
                    " (failed)"
                };
                format!("{}{failed}", Self::legacy(action))
            }
        }
    }

    /// Why a session was ended for the user.
    const fn revocation(reason: &RevocationReason) -> &'static str {
        match reason {
            RevocationReason::CredentialRemoved => "Signed out after a passkey was removed",
            RevocationReason::IdentityUnlinked => "Signed out after a social sign-in was unlinked",
            RevocationReason::Admin => "Signed out by an administrator",
            RevocationReason::AccountDisabled => "Signed out because the account was disabled",
            RevocationReason::AccountDeletion => "Signed out because the account is being deleted",
            RevocationReason::CompromiseReported => "Signed out after you reported activity",
            RevocationReason::UserRevoked => "Signed out from your devices list",
            RevocationReason::Logout
            | RevocationReason::AccountSwitched
            | RevocationReason::RelyingPartyLogout { .. }
            | RevocationReason::Expired => "Signed out",
        }
    }

    /// A row the audit log recorded before typed history, by its logged action.
    fn legacy(action: &str) -> &str {
        match action {
            "account.create" => "Account created",
            "passkey.login" => "Signed in with a passkey",
            "passkey.add" => "Passkey added",
            "passkey.rename" => "Passkey renamed",
            "passkey.remove" => "Passkey removed",
            "settings.unlock" => "Settings unlocked",
            "federation.login" => "Signed in with a social provider",
            "federation.link" => "Social sign-in linked",
            "federation.unlink" => "Social sign-in unlinked",
            "refresh.replay" => "An app’s sign-in was reused and revoked",
            "refresh.policy_rejected" => "An app’s access ended",
            other => other,
        }
    }

    /// From where and through which application, after its time.
    fn details(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if self.erased {
            parts.push("Device details erased".to_owned());
        } else {
            parts.extend(self.device.map(device_name));
            parts.extend(self.ip.map(|ip| ip.to_string()));
        }
        if let Some((id, name)) = self.client {
            parts.push(format!("App: {}", name.unwrap_or(id)));
        }
        parts
    }

    /// Who did it, if not the account itself, and why, if they said.
    fn by(&self) -> Option<String> {
        let actor = match self.actor {
            HistoryActor::Admin => "By a Piquel administrator",
            HistoryActor::Operator => "By a Piquel operator",
            HistoryActor::Client => "By an app",
            HistoryActor::System => "Automatically by Piquel",
            HistoryActor::Account | HistoryActor::Anonymous | HistoryActor::Unrecorded => {
                return None;
            }
        };
        Some(match self.reason {
            Some(reason) => format!("{actor}: “{reason}”"),
            None => actor.to_owned(),
        })
    }

    /// Whether the account can report it as not theirs: what its own sessions did,
    /// but reports and the sign-outs other changes caused.
    fn reportable(&self) -> bool {
        self.actor == HistoryActor::Account
            && !matches!(
                self.entry,
                HistoryEntry::CompromiseReported { .. } | HistoryEntry::SessionRevoked { .. }
            )
    }
}

impl<'a> HistoryRow<'a> {
    /// `rows`, grouped by the UTC day they happened on, newest first.
    fn days(rows: &'a [Self]) -> Vec<(String, Vec<&'a Self>)> {
        let mut days: Vec<(String, Vec<&Self>)> = Vec::new();
        for row in rows {
            let day = row.occurred_at.format("%A %-d %B %Y").to_string();
            match days.last_mut() {
                Some((last, entries)) if *last == day => entries.push(row),
                _ => days.push((day, vec![row])),
            }
        }
        days
    }
}

/// Where the history page and the pages undoing a report are, what it shows, and
/// what a report left to undo.
#[derive(Clone, Copy, Debug)]
pub struct HistoryPage<'a> {
    /// The history page.
    pub page: &'a str,
    /// The sign-in methods page, which removes passkeys and unlinks providers.
    pub sign_in: &'a str,
    /// The addresses page, which removes addresses.
    pub emails: &'a str,
    /// Which history it shows, and which of its rows is open.
    pub shown: HistoryState,
    /// The entry after which older ones follow, if any.
    pub next: Option<EventId>,
    /// The report just made, and what undoes its entry, if anything.
    pub reported: Option<Option<FollowUp>>,
    /// Whether the session needs no passkey confirmation to undo it.
    pub confirmed: bool,
}

/// The security history page: `rows`, newest first and grouped by day, naming
/// what the account `holds`, on `page`. An open report takes the focus.
#[component]
pub async fn history<'a>(
    rows: &'a [HistoryRow<'a>],
    holds: Holdings<'a>,
    page: HistoryPage<'a>,
) -> Result<impl View> {
    let before = page.shown.before;
    let back = HistoryState {
        before,
        ..HistoryState::default()
    }
    .on(page.page)?;
    let older = page
        .next
        .map(|next| {
            HistoryState {
                before: Some(next),
                ..HistoryState::default()
            }
            .on(page.page)
        })
        .transpose()?;
    Ok(view! {
        <p class="help">
            "Every sign-in and change to your account. If something wasn’t you, say so: we’ll sign out every other device and help you undo it."
        </p>
        if let Some(follow_up) = page.reported {
            <div class="notice stack" role="status">
                <strong>"Your account is secured."</strong>
                <p>"Every other device was signed out, and every app must sign in again, including on this device."</p>
                if let Some(undo) = follow_up.and_then(|follow_up| Undo::of(follow_up, &holds, &page)) {
                    <p>"Undo the change, too:"</p>
                    change_form(
                        action: undo.action,
                        change: undo.change.clone(),
                        label: undo.label.clone(),
                        class: "danger",
                        confirm: !page.confirmed,
                    )
                }
            </div>
        }
        for (day, entries) in HistoryRow::days(rows) {
            <section class="card" aria-label=(day.as_str())>
                <h2>(day.as_str())</h2>
                <ul class="list">
                    for row in entries {
                        <li>
                            entry(row: row, holds: &holds, page: &page, back: back.as_str())
                        </li>
                    }
                </ul>
            </section>
        }
        if rows.is_empty() && page.next.is_none() {
            if before.is_none() {
                <p class="empty">"Nothing has happened to your account yet."</p>
            } else {
                <p class="empty">"No older activity."</p>
            }
        }
        if let Some(older) = &older {
            <a class="button secondary full" href=(older.as_str())>"Show older activity"</a>
        }
        if before.is_some() {
            <a class="button secondary full" href=(page.page)>"Newest activity"</a>
        }
    })
}

/// One entry of [`history`]: what happened, when, where and by whom, and reporting
/// it, whose confirmation goes back to `back` and takes the focus once open.
#[component]
async fn entry<'a>(
    row: &'a HistoryRow<'a>,
    holds: &'a Holdings<'a>,
    page: &'a HistoryPage<'a>,
    back: &'a str,
) -> Result<impl View> {
    let before = page.shown.before;
    let description = row.describe(holds);
    let reporting = row.reportable() && page.shown.reporting == Some(row.id);
    Ok(view! {
        <div class="row between">
            <div>
                <strong>(description.as_str())</strong>
                <p class="help">
                    time(at: row.occurred_at, format: "%H:%M")
                    for part in row.details() {
                        " · " (part)
                    }
                </p>
                if let Some(by) = row.by() {
                    <p class="help">(by)</p>
                }
            </div>
            if row.reportable() && !reporting {
                open(
                    page: page.page,
                    opens: HistoryState { before, reporting: Some(row.id), reported: None },
                    label: "This wasn’t me",
                    aria_label: format!("This wasn’t me: {description}"),
                )
            }
        </div>
        if reporting {
            <div class="notice stack">
                <strong tabindex="-1" autofocus="">"Secure your account?"</strong>
                <p>
                    "This signs out every device but this one, and every app you use with Piquel must sign in again, including on this device. Your passkeys keep working."
                </p>
                if row.entry.follow_up().is_some() {
                    <p>"Afterwards, you can confirm with your passkey to undo this change."</p>
                }
                change_form(
                    action: page.page,
                    change: HistoryChange::Report { event_id: row.id, before },
                    label: "Sign out everywhere else",
                    class: "danger",
                    cancel: back.to_owned(),
                )
            </div>
        }
    })
}

/// The change undoing a reported entry, while what it added is still there.
struct Undo<'a> {
    /// The page whose form removes it.
    action: &'a str,
    /// The change.
    change: Fields,
    /// The button's label.
    label: String,
}

impl<'a> Undo<'a> {
    /// How to undo `follow_up` on the pages `page` names, if the account still
    /// `holds` what it removes.
    fn of(follow_up: FollowUp, holds: &Holdings<'_>, page: &HistoryPage<'a>) -> Option<Self> {
        match follow_up {
            FollowUp::RemovePasskey { passkey_id } => {
                let passkey = holds.find_passkey(passkey_id)?;
                Some(Self {
                    action: page.sign_in,
                    change: SignInChange::Remove { id: passkey_id }.into(),
                    label: format!("Remove passkey “{}”", passkey.friendly_name),
                })
            }
            FollowUp::UnlinkIdentity { provider } => {
                holds.linked.contains(&provider).then(|| Self {
                    action: page.sign_in,
                    change: SignInChange::Unlink { provider }.into(),
                    label: format!("Unlink {} sign-in", provider_name(provider)),
                })
            }
            FollowUp::RemoveEmail { email_id } => {
                let email = holds.find_email(email_id)?;
                Some(Self {
                    action: page.emails,
                    change: EmailChange::Remove { id: email_id }.into(),
                    label: format!("Remove {}", email.address),
                })
            }
        }
    }
}
