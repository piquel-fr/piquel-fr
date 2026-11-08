//! Domain events, as the dashboard lists them: each in words, with the facts
//! that matter beside it, and its stored JSON a click away.

use super::moment;
use crate::layout::{Pager, page_head, pager};
use piquel_common::{
    AlertId, AuthenticationMethod, Personal, Provider,
    admin::Event,
    alerts::Alert,
    events::{
        Actor, CodeRedemptionFailure, DomainEvent, GrantRevocation, JobName, RecordedOrigin,
        RevocationReason, SignInFailure,
    },
};
use serde_json::Value;
use std::fmt::Display;
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// An event, the link to the account it concerns, if any, and to the account that
/// caused it, when a user or administrator did.
#[derive(Clone, Debug)]
pub struct EventRow<'a> {
    /// The event.
    pub event: &'a Event,
    /// The page of the account it concerns.
    pub account: Option<String>,
    /// The page of the account that caused it.
    pub actor: Option<String>,
}

/// An event in words: what happened, and the facts worth a glance.
struct Description {
    /// What happened, in one line.
    summary: String,
    /// The facts, each named.
    facts: Vec<(&'static str, String)>,
}

impl Description {
    /// `summary` alone.
    fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            facts: Vec::new(),
        }
    }

    /// With the fact `name`, read `value`.
    fn with(mut self, name: &'static str, value: impl Display) -> Self {
        self.facts.push((name, value.to_string()));
        self
    }

    /// With the fact `name`, if `value` has one.
    fn maybe(self, name: &'static str, value: Option<impl Display>) -> Self {
        match value {
            Some(value) => self.with(name, value),
            None => self,
        }
    }

    /// With the personal `value` under `name`: the value while it is kept, or
    /// that it was erased.
    fn personal(self, name: &'static str, value: &Personal<impl Display>) -> Self {
        match value {
            Personal::Value(value) => self.with(name, value),
            Personal::Erased => self.with(name, "erased"),
        }
    }
}

impl EventRow<'_> {
    /// The event's kind, or `unknown`.
    fn kind(&self) -> &str {
        self.event
            .event
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    }

    /// The event, if this release knows its kind and payload.
    fn known(&self) -> Option<DomainEvent> {
        serde_json::from_value(self.event.event.clone()).ok()
    }

    /// Who caused it, in a few words, and whether that is an administrator's or
    /// operator's doing.
    fn actor(&self) -> (String, bool) {
        match serde_json::from_value(self.event.actor.clone()) {
            Ok(Actor::User { .. }) => ("the account".to_owned(), false),
            Ok(Actor::Admin { .. }) => ("an administrator".to_owned(), true),
            Ok(Actor::Cli { os_user, host }) => (format!("the terminal, {os_user}@{host}"), true),
            Ok(Actor::Client { client_id }) => (format!("the app {client_id}"), false),
            Ok(Actor::System { job }) => (format!("the {} job", Self::job(job)), false),
            Ok(Actor::Anonymous) => ("someone not signed in".to_owned(), false),
            Ok(Actor::Unrecorded) | Err(_) => ("nobody recorded".to_owned(), false),
        }
    }

    /// A job's name, as its event stores it.
    fn job(job: JobName) -> String {
        serde_json::to_value(job)
            .ok()
            .and_then(|name| name.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| format!("{job:?}").to_lowercase())
    }

    /// Its stored JSON, pretty-printed.
    fn raw(&self) -> String {
        serde_json::to_string_pretty(&self.event.event).unwrap_or_default()
    }

    /// Whether it is something to look at: a failure, a replay, a revocation,
    /// a report, or a change an administrator or operator made.
    fn worrying(&self) -> bool {
        let kind = self.kind();
        [
            "failed",
            "replayed",
            "revoked",
            "disabled",
            "compromise",
            "suspended",
            "purged",
        ]
        .iter()
        .any(|word| kind.contains(word))
            || self.actor().1
    }

    /// What happened, in words, and the facts beside it. An event this release
    /// does not know is named by its kind. Every kind is named, so a new one
    /// cannot be added without words for the dashboard.
    #[deny(clippy::wildcard_enum_match_arm)]
    #[expect(
        clippy::too_many_lines,
        reason = "One arm per event kind, so a new kind cannot skip its wording."
    )]
    fn describe(&self) -> Description {
        let Some(event) = self.known() else {
            return Description::new(self.kind().replace('_', " "));
        };
        let method = |method: AuthenticationMethod| match method {
            AuthenticationMethod::Passkey => "a passkey",
            AuthenticationMethod::Federation => "a social provider",
        };
        match event {
            DomainEvent::AccountCreated {
                method: how,
                invited,
            } => Description::new(format!("Account created with {}", method(how)))
                .with("invited", if invited { "yes" } else { "no" }),
            DomainEvent::SignedIn {
                session_id,
                method: how,
                inline,
            } => {
                let summary = match &inline {
                    Some(inline) => format!(
                        "Signed in with a passkey on {}, for {}",
                        Self::origin(&inline.origin),
                        inline.client_id
                    ),
                    None => format!("Signed in with {}", method(how)),
                };
                Description::new(summary).with("session", session_id)
            }
            DomainEvent::SignInFailed {
                method: how,
                reason,
            } => {
                let why = match reason {
                    SignInFailure::InvalidCredential => "the credential did not verify",
                    SignInFailure::CounterRegression => {
                        "the passkey's counter went backwards, so it may have been copied"
                    }
                    SignInFailure::UnknownAccount => "no account matched",
                    SignInFailure::AccountUnavailable => "the account cannot sign in this way",
                };
                Description::new(format!("Sign-in with {} failed: {why}", method(how)))
            }
            DomainEvent::SessionRevoked { session_id, reason } => {
                Description::new(format!("Session ended: {}", Self::revocation(&reason)))
                    .with("session", session_id)
            }
            DomainEvent::PasskeyConfirmed { session_id } => {
                Description::new("Passkey confirmed, for a protected change")
                    .with("session", session_id)
            }
            DomainEvent::PasskeyAdded { passkey_id } => {
                Description::new("Passkey added").with("passkey", passkey_id)
            }
            DomainEvent::PasskeyRenamed { passkey_id } => {
                Description::new("Passkey renamed").with("passkey", passkey_id)
            }
            DomainEvent::PasskeyRemoved { passkey_id } => {
                Description::new("Passkey removed").with("passkey", passkey_id)
            }
            DomainEvent::IdentityLinked { provider, subject } => {
                Description::new(format!("{} sign-in linked", provider.name()))
                    .personal("subject", &subject)
            }
            DomainEvent::IdentityUnlinked { provider } => {
                Description::new(format!("{} sign-in unlinked", provider.name()))
            }
            DomainEvent::EmailAdded {
                email_id,
                address,
                provider,
            } => Description::new("Email address added")
                .personal("address", &address)
                .with("email", email_id)
                .maybe("from", provider.map(Provider::name)),
            DomainEvent::EmailVerified { email_id } => {
                Description::new("Email address confirmed").with("email", email_id)
            }
            DomainEvent::PrimaryEmailChanged {
                email_id,
                previous_email_id,
            } => Description::new("Primary email address changed")
                .with("now", email_id)
                .maybe("before", previous_email_id),
            DomainEvent::EmailRemoved { email_id } => {
                Description::new("Email address removed").with("email", email_id)
            }
            DomainEvent::ConsentGranted { client_id, scopes } => {
                Description::new(format!("Access approved for {client_id}"))
                    .with("scopes", scopes.join(" "))
            }
            DomainEvent::ConsentRevoked { client_id } => {
                Description::new(format!("Access withdrawn from {client_id}"))
            }
            DomainEvent::GrantIssued {
                client_id,
                family_id,
                scopes,
            } => Description::new(format!("Tokens issued to {client_id}"))
                .with("scopes", scopes.join(" "))
                .maybe("refresh family", family_id),
            DomainEvent::GrantRevoked {
                client_id,
                family_id,
                reason,
            } => {
                let why = match reason {
                    GrantRevocation::ClientRevoked => "the app revoked it",
                    GrantRevocation::RefreshReplay => "a refresh token was used twice",
                    GrantRevocation::PolicyRejected => "the app's policy no longer allows it",
                    GrantRevocation::CodeReplay => "its authorization code was used twice",
                };
                Description::new(format!("Refresh grant of {client_id} revoked: {why}"))
                    .with("refresh family", family_id)
            }
            DomainEvent::CodeReplayed { client_id } => {
                Description::new(format!("{client_id} redeemed an authorization code twice"))
            }
            DomainEvent::CodeRedemptionFailed { client_id, reason } => {
                let why = match reason {
                    CodeRedemptionFailure::WrongClient => "it was issued to another app",
                    CodeRedemptionFailure::RedirectMismatch => "the redirect URI differed",
                    CodeRedemptionFailure::InvalidVerifier => "the PKCE verifier was wrong",
                };
                Description::new(format!(
                    "{client_id} failed to redeem an authorization code: {why}"
                ))
            }
            DomainEvent::InvitationCreated { expires_at } => {
                Description::new("Invitation created").with("valid until", expires_at.to_rfc3339())
            }
            DomainEvent::InvitationRevoked { invitation_id } => {
                Description::new("Invitation revoked").with("invitation", invitation_id)
            }
            DomainEvent::AccountDisabled { reason } => {
                Description::new("Account disabled").personal("reason", &reason)
            }
            DomainEvent::AccountEnabled {} => Description::new("Account enabled again"),
            DomainEvent::AccountViewed {} => Description::new("Account details viewed"),
            DomainEvent::AdministratorGranted {} => {
                Description::new("Administrator rights granted")
            }
            DomainEvent::AdministratorRevoked {} => {
                Description::new("Administrator rights revoked")
            }
            DomainEvent::HandleChanged { old, new } => Description::new("Handle changed")
                .personal("from", &old)
                .personal("to", &new),
            DomainEvent::DisplayNameChanged { old, new } => {
                Description::new("Display name changed")
                    .personal("from", &old)
                    .personal("to", &new)
            }
            DomainEvent::PictureChanged { picture_id } => {
                Description::new("Profile picture changed").with("picture", picture_id)
            }
            DomainEvent::PictureRemoved {} => Description::new("Profile picture removed"),
            DomainEvent::HandleReleased { handle } => {
                Description::new("Handle released for anyone to claim").personal("handle", &handle)
            }
            DomainEvent::HandleReserved { handle } => {
                Description::new(format!("Handle @{handle} reserved"))
            }
            DomainEvent::HandleUnreserved { handle } => {
                Description::new(format!("Handle @{handle} no longer reserved"))
            }
            DomainEvent::ClientRegistered { client_id, kind } => {
                Description::new(format!("Client {client_id} registered")).with("kind", kind)
            }
            DomainEvent::ClientUpdated { client_id, changed } => {
                let changed: Vec<_> = changed.iter().map(ToString::to_string).collect();
                Description::new(format!("Client {client_id} updated")).with(
                    "changed",
                    if changed.is_empty() {
                        "not recorded".to_owned()
                    } else {
                        changed.join(", ")
                    },
                )
            }
            DomainEvent::ClientEnabled { client_id } => {
                Description::new(format!("Client {client_id} enabled"))
            }
            DomainEvent::ClientDisabled { client_id } => {
                Description::new(format!("Client {client_id} disabled"))
            }
            DomainEvent::ClientSuspended { client_id } => {
                Description::new(format!("Client {client_id} suspended by an operator"))
            }
            DomainEvent::ClientSuspensionLifted { client_id } => {
                Description::new(format!("Client {client_id}'s suspension lifted"))
            }
            DomainEvent::ClientDeleted { client_id } => {
                Description::new(format!("Client {client_id} deleted"))
            }
            DomainEvent::ClientSecretRotated {
                client_id,
                previous_expire_at,
            } => Description::new(format!("Client {client_id} got a new secret")).with(
                "earlier secrets work until",
                previous_expire_at.to_rfc3339(),
            ),
            DomainEvent::RecoveryStarted {
                recovery_id,
                expires_at,
                revoke,
            } => {
                let summary = match &revoke {
                    Some(revoke) => format!(
                        "Account recovery started, revoking {} passkey{} and keeping {}",
                        revoke.revoked.len(),
                        if revoke.revoked.len() == 1 { "" } else { "s" },
                        revoke.kept.len()
                    ),
                    None => "Account recovery started".to_owned(),
                };
                Description::new(summary)
                    .with("recovery", recovery_id)
                    .with("link valid until", expires_at.to_rfc3339())
            }
            DomainEvent::RecoveryCompleted {
                recovery_id,
                passkey_id,
            } => Description::new("Recovery link used: a passkey was enrolled")
                .with("recovery", recovery_id)
                .with("passkey", passkey_id),
            DomainEvent::RecoveryUndone { recovery_id } => {
                Description::new("Account recovery undone").with("recovery", recovery_id)
            }
            DomainEvent::DeliveryRetried { delivery_id } => {
                Description::new("Delivery made due again").with("delivery", delivery_id)
            }
            DomainEvent::DeliveryCancelled { delivery_id } => {
                Description::new("Delivery cancelled").with("delivery", delivery_id)
            }
            DomainEvent::RelatedOriginApproved { client_id, origin } => Description::new(format!(
                "Origin {} approved for {client_id}'s passkey sign-in",
                Self::origin(&origin)
            )),
            DomainEvent::RelatedOriginRemoved { client_id, origin } => Description::new(format!(
                "Origin {} removed from {client_id}",
                Self::origin(&origin)
            )),
            DomainEvent::CompromiseReported { event_id } => {
                Description::new("The owner reported an event as not theirs")
                    .with("event", event_id)
            }
            DomainEvent::SigningKeyChanged { key_id, change } => {
                Description::new(format!("Signing key {change}")).with("key", key_id)
            }
            DomainEvent::AccountExported {} => Description::new("Account data downloaded"),
            DomainEvent::AccountDeletionScheduled { purge_after } => {
                Description::new("Account deletion scheduled")
                    .with("purged after", purge_after.to_rfc3339())
            }
            DomainEvent::AccountRestored {} => Description::new("Account restored"),
            DomainEvent::AccountPurged {} => Description::new("Account purged"),
            DomainEvent::AuditHistoryPruned { through, deleted } => Description::new(format!(
                "Audit history pruned through position {through}: {deleted} events deleted"
            )),
            DomainEvent::AuditChainVerified(verification) => {
                Description::new(match &verification.broken {
                    None => "Audit chain verified: intact".to_owned(),
                    Some(broken) => format!(
                        "Audit chain verified: broken at position {}: {}",
                        broken.position, broken.problem
                    ),
                })
                .with("events checked", verification.events_checked)
            }
            DomainEvent::AnnouncementSent {
                announcement_id,
                recipients,
                essential,
            } => Description::new(if essential {
                format!("Essential announcement sent to {recipients} accounts")
            } else {
                format!("Announcement sent to {recipients} accounts")
            })
            .with("announcement", announcement_id),
            DomainEvent::NotificationPreferenceChanged(preference) => {
                Description::new(preference.change())
            }
            DomainEvent::AlertRaised { alert_id, alert } => {
                Self::alert("Alert raised", alert_id, &alert)
            }
            DomainEvent::AlertUpdated {
                alert_id,
                alert,
                status,
            } => Self::alert("Alert updated", alert_id, &alert).with("status", status),
            DomainEvent::AlertCleared { alert_id, alert } => {
                Self::alert("Alert cleared", alert_id, &alert)
            }
            DomainEvent::Imported(audit) => {
                Description::new(format!("{} ({})", audit.action(), audit.outcome()))
            }
        }
    }

    /// What happened to the alert `id`, which says `alert`, with where it found the
    /// chain broken, for a broken chain.
    fn alert(what: &str, id: AlertId, alert: &Alert) -> Description {
        let description =
            Description::new(format!("{what}: {}", alert.subject())).with("alert", id);
        match alert {
            Alert::AuditChainBroken(broken) => description
                .with("position", broken.position)
                .with("problem", broken.problem),
        }
    }

    /// A recorded origin, or that it was erased.
    fn origin(origin: &RecordedOrigin) -> String {
        origin
            .value()
            .map_or_else(|| "an erased origin".to_owned(), ToString::to_string)
    }

    /// Why a session was ended, in words.
    fn revocation(reason: &RevocationReason) -> String {
        match reason {
            RevocationReason::Logout => "the user signed out".to_owned(),
            RevocationReason::AccountSwitched => {
                "the browser signed in to another account".to_owned()
            }
            RevocationReason::RelyingPartyLogout { client_id } => {
                format!("{client_id} asked to sign the user out")
            }
            RevocationReason::CredentialRemoved => "a passkey was removed".to_owned(),
            RevocationReason::IdentityUnlinked => "a social sign-in was unlinked".to_owned(),
            RevocationReason::Admin => "an administrator revoked it".to_owned(),
            RevocationReason::AccountDisabled => "the account was disabled".to_owned(),
            RevocationReason::AccountDeletion => "the account is being deleted".to_owned(),
            RevocationReason::Expired => "it expired".to_owned(),
            RevocationReason::CompromiseReported => {
                "the owner reported activity that was not theirs".to_owned()
            }
            RevocationReason::UserRevoked => {
                "the owner signed it out from another device".to_owned()
            }
        }
    }
}

/// Domain events, newest first: the filter form posting `user` and `kind` back to
/// `action` by `GET`, keeping whether administrators' `views` of accounts are
/// shown, a link to the same list with the views shown or hidden the other way,
/// `toggle_views`, offered only when no kind is chosen (a kind decides the views
/// by itself), the events, and the `pages` through them.
#[component]
pub async fn event_list<'a>(
    action: &'a str,
    #[into]
    #[default]
    user: Option<String>,
    #[into]
    #[default]
    kind: Option<&'a str>,
    #[default] views: bool,
    toggle_views: &'a str,
    rows: &'a [EventRow<'a>],
    pages: &'a Pager,
) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Events",
            lead: format!("{} recorded, newest first.", pages.paging.total),
        )
        <form method="get" action=(action) class="row search">
            <input name="user" value=(user) placeholder="Account ID" aria-label="Account ID">
            <input name="kind" value=(kind) placeholder="Kind, e.g. session_revoked" aria-label="Event kind">
            if views {
                <input type="hidden" name="views" value="on">
            }
            <button class="secondary">"Filter"</button>
            if kind.is_none() {
                <a class="button secondary" href=(toggle_views)>
                    (if views { "Hide views" } else { "Show views" })
                </a>
            }
        </form>
        <section class="card">
            event_rows(rows: rows)
        </section>
        pager(pages: pages, what: "events")
    })
}

/// A feed of events, each in words, linking the account it concerns and the one
/// that caused it, with its stored JSON behind a disclosure.
#[component]
pub async fn event_rows<'a>(rows: &'a [EventRow<'a>]) -> Result<impl View> {
    Ok(view! {
        if rows.is_empty() {
            <p class="empty">"No event."</p>
        } else {
            <ul class="events">
                for row in rows {
                    let described = row.describe();
                    let (actor, _) = row.actor();
                    <li>
                        moment(at: row.event.occurred_at)
                        <span class=(class!("dot", "warning" if row.worrying(), "ok" if !row.worrying()))></span>
                        <div class="text">
                            (described.summary.as_str())
                            <small class="wrap">
                                "by "
                                match &row.actor {
                                    Some(href) => <a href=(href.as_str())>(actor.as_str())</a>,
                                    None => (actor.as_str()),
                                }
                                // The account it concerns, unless that is who caused it.
                                if let Some(account) = row.account.as_ref().filter(|account| row.actor.as_ref() != Some(account)) {
                                    " · " <a href=(account.as_str())>"account"</a>
                                }
                                for (name, value) in &described.facts {
                                    " · " (*name) " " <span class="fact">(value.as_str())</span>
                                }
                            </small>
                            <details class="raw">
                                <summary>
                                    <code>(row.kind())</code>
                                    if let Some(trace_id) = row.event.trace_id {
                                        " · trace " <span title="Search Grafana for this trace ID">(trace_id.to_string())</span>
                                    }
                                </summary>
                                <pre><code>(row.raw())</code></pre>
                            </details>
                        </div>
                    </li>
                }
            </ul>
        }
    })
}
