//! The account's data, as its owner downloads it (GDPR Art. 20): one versioned
//! JSON document, read from one snapshot. It holds no secret, digest or key
//! material: passkeys show their label, dates and backup state only.

use crate::{
    clients::OwnedClientView, emails::EmailView, history::HistoryItem, sessions::SessionItem,
};
use chrono::{DateTime, Utc};
use piquel_common::admin::Consent;
use piquel_common::{AccountStatus, Handle, PasskeyId, Provider, RecoveryId, SessionId, UserId};
use piquel_repository::{
    DashboardSignIn, DatabaseError, DatabaseTransaction, RecentRecovery, RecoveryState,
    StoredExternalIdentity, StoredGrant, StoredHandle, StoredPasskey, StoredUser,
};
use serde::Serialize;
use serde_json::Value;

/// The `format` of every export.
const FORMAT: &str = "piquel.account-export";
/// The export's version; a change to its shape gets a new one.
const VERSION: u32 = 1;
/// Where the serialized credential holds whether the passkey may be synced.
const BACKUP_ELIGIBLE_POINTER: &str = "/cred/backup_eligible";
/// Where the serialized credential holds whether the passkey is synced.
const BACKED_UP_POINTER: &str = "/cred/backup_state";

/// Everything auth stores about an account, in one document:
/// `{"format": "piquel.account-export", "version": 1, …}`.
#[derive(Serialize)]
pub(crate) struct AccountExport {
    /// Always [`FORMAT`].
    format: &'static str,
    /// Always [`VERSION`].
    version: u32,
    /// When the export was read.
    exported_at: DateTime<Utc>,
    /// The account itself.
    profile: Profile,
    /// The handles the account holds or held, the current one first.
    handles: Vec<HandleHeld>,
    /// Whether the account is an administrator.
    administrator: bool,
    /// An administrator's sign-ins to the admin dashboard, newest first.
    dashboard_sessions: Vec<DashboardSession>,
    /// Email addresses, verified or not, primary first.
    emails: Vec<EmailView>,
    /// Active passkeys.
    passkeys: Vec<Passkey>,
    /// Linked social identities.
    identities: Vec<Identity>,
    /// Active browser sessions, most recently active first, with their devices
    /// and IP addresses. The one that downloaded the export is `current`.
    sessions: Vec<SessionItem>,
    /// The scopes approved for each application.
    consents: Vec<Consent>,
    /// Applications' refresh grants, revoked ones included until cleanup deletes them.
    grants: Vec<StoredGrant>,
    /// The OIDC clients the account manages, as its developer console shows them.
    clients: Vec<OwnedClientView>,
    /// The recoveries support started for the account, newest first.
    recoveries: Vec<Recovery>,
    /// The security history, newest first, as the account's history page shows it.
    history: Vec<HistoryItem>,
}

/// The account's profile.
#[derive(Debug, Serialize)]
struct Profile {
    /// Account ID, the `sub` applications know it by.
    id: UserId,
    /// Handle, also the login name.
    handle: Handle,
    /// Name shown to the user and to applications.
    display_name: String,
    /// Whether the account can sign in.
    status: AccountStatus,
    /// When the account was created.
    created_at: DateTime<Utc>,
    /// When the profile last changed.
    updated_at: DateTime<Utc>,
}

/// A passkey, without its credential.
#[derive(Debug, Serialize)]
struct Passkey {
    /// Passkey ID.
    id: PasskeyId,
    /// The label its owner chose.
    friendly_name: String,
    /// When it was added.
    created_at: DateTime<Utc>,
    /// When it last signed in, if it has.
    last_used_at: Option<DateTime<Utc>>,
    /// Whether its authenticator lets it sync to other devices, if recorded.
    backup_eligible: Option<bool>,
    /// Whether it is synced, as of its last use, if recorded.
    backed_up: Option<bool>,
}

/// A linked social identity.
#[derive(Debug, Serialize)]
struct Identity {
    /// The provider.
    provider: Provider,
    /// The provider's identifier of the person.
    subject: String,
    /// The email the provider reported when it was linked, if any.
    linked_email: Option<String>,
}

/// A handle the account holds or held.
#[derive(Debug, Serialize)]
struct HandleHeld {
    /// The handle.
    handle: Handle,
    /// When the account claimed it.
    claimed_at: DateTime<Utc>,
    /// When it stopped being the account's handle; `None` for the current one.
    released_at: Option<DateTime<Utc>>,
}

/// One of an administrator's sign-ins to the admin dashboard.
#[derive(Debug, Serialize)]
struct DashboardSession {
    /// The browser session it rests on.
    session_id: SessionId,
    /// When it started.
    created_at: DateTime<Utc>,
    /// When a passkey last confirmed it, if one did.
    confirmed_at: Option<DateTime<Utc>>,
}

impl From<StoredHandle> for HandleHeld {
    /// Keeps the handle and its dates.
    fn from(handle: StoredHandle) -> Self {
        Self {
            handle: handle.handle,
            claimed_at: handle.claimed_at,
            released_at: handle.released_at,
        }
    }
}

impl From<DashboardSignIn> for DashboardSession {
    /// Keeps its session and dates.
    fn from(signed_in: DashboardSignIn) -> Self {
        Self {
            session_id: signed_in.session_id,
            created_at: signed_in.created_at,
            confirmed_at: signed_in.confirmed_at,
        }
    }
}

/// A recovery support started for the account, without its link.
#[derive(Debug, Serialize)]
struct Recovery {
    /// Recovery ID.
    id: RecoveryId,
    /// When support started it.
    started_at: DateTime<Utc>,
    /// When its link stopped, or stops, working if unused.
    expires_at: DateTime<Utc>,
    /// When its link enrolled a passkey, if it did.
    completed_at: Option<DateTime<Utc>>,
    /// The passkey its link enrolled, if it did.
    passkey_id: Option<PasskeyId>,
    /// When it was cancelled before its link was used.
    cancelled_at: Option<DateTime<Utc>>,
    /// When it was undone.
    undone_at: Option<DateTime<Utc>>,
    /// Where it stands: `open`, `probation`, `settled` or `ended`.
    state: &'static str,
    /// When its probation ends, while it lasts.
    settles_at: Option<DateTime<Utc>>,
}

impl From<RecentRecovery> for Recovery {
    /// Keeps its dates, state and passkey.
    fn from(recovery: RecentRecovery) -> Self {
        let (state, settles_at) = match recovery.state {
            RecoveryState::Open => ("open", None),
            RecoveryState::Probation { settles_at } => ("probation", Some(settles_at)),
            RecoveryState::Settled => ("settled", None),
            RecoveryState::Ended => ("ended", None),
        };
        Self {
            id: recovery.id,
            started_at: recovery.started_at,
            expires_at: recovery.expires_at,
            completed_at: recovery.completed_at,
            passkey_id: recovery.passkey.map(|passkey| passkey.id),
            cancelled_at: recovery.cancelled_at,
            undone_at: recovery.undone_at,
            state,
            settles_at,
        }
    }
}

impl From<StoredUser> for Profile {
    /// Keeps every column.
    fn from(user: StoredUser) -> Self {
        Self {
            id: user.id,
            handle: user.handle,
            display_name: user.display_name,
            status: user.status,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl From<StoredPasskey> for Passkey {
    /// Reads the backup flags out of the credential, and leaves the rest of it.
    fn from(passkey: StoredPasskey) -> Self {
        let flag = |pointer| passkey.credential.pointer(pointer).and_then(Value::as_bool);
        Self {
            backup_eligible: flag(BACKUP_ELIGIBLE_POINTER),
            backed_up: flag(BACKED_UP_POINTER),
            id: passkey.id,
            friendly_name: passkey.friendly_name,
            created_at: passkey.created_at,
            last_used_at: passkey.last_used_at,
        }
    }
}

impl From<StoredExternalIdentity> for Identity {
    /// Keeps the provider, its subject and the linked email.
    fn from(identity: StoredExternalIdentity) -> Self {
        Self {
            provider: identity.provider,
            subject: identity.subject,
            linked_email: identity.linked_email,
        }
    }
}

impl AccountExport {
    /// Reads the account `user_id` for its session `current` in `tx`, which should
    /// be a snapshot, so every part is consistent with the others.
    pub(super) async fn read(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
        current: SessionId,
    ) -> Result<Self, DatabaseError> {
        let user = tx
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        Ok(Self {
            format: FORMAT,
            version: VERSION,
            exported_at: Utc::now(),
            handles: (tx.handles().of_user(user_id).await?)
                .into_iter()
                .map(HandleHeld::from)
                .collect(),
            administrator: tx.administrators().contains(user_id).await?,
            dashboard_sessions: (tx.dashboard().of_user(user_id).await?)
                .into_iter()
                .map(DashboardSession::from)
                .collect(),
            emails: (tx.emails().list(user_id).await?)
                .into_iter()
                .map(EmailView::from)
                .collect(),
            passkeys: (tx.passkeys().list_active(user_id).await?)
                .into_iter()
                .map(Passkey::from)
                .collect(),
            identities: (tx.federation().list_active(user_id).await?)
                .into_iter()
                .map(Identity::from)
                .collect(),
            sessions: (tx.sessions().list_active_for_user(user_id).await?)
                .into_iter()
                .map(|session| SessionItem::new(session, Some(current)))
                .collect(),
            consents: tx.oidc().list_consents(user_id).await?,
            grants: tx.tokens().list_for_user(user_id).await?,
            recoveries: (tx
                .recoveries()
                .recent(user_id, DateTime::UNIX_EPOCH)
                .await?)
                .into_iter()
                .map(Recovery::from)
                .collect(),
            clients: (tx.oidc().list_owned_clients(user_id).await?)
                .into_iter()
                .map(OwnedClientView::from)
                .collect(),
            history: HistoryItem::all(tx, user_id).await?,
            profile: user.into(),
        })
    }

    /// The download's file name, `piquel-account-<handle>-<date>.json`.
    /// Handles are lowercase ASCII letters, digits and `-`, so it needs no quoting
    /// in a header.
    pub(crate) fn file_name(&self) -> String {
        format!(
            "piquel-account-{}-{}.json",
            self.profile.handle,
            self.exported_at.format("%Y-%m-%d")
        )
    }
}

#[cfg(test)]
mod tests {
    //! The export's JSON shape, which downloads keep across releases.
    use super::*;
    use crate::history::{ClientView, HistoryItem};
    use chrono::TimeZone;
    use piquel_common::{
        AuthenticationMethod, ClientId, EmailId, EventId, TokenId,
        events::{Browser, HistoryActor, HistoryEntry, Platform, UserAgentFamily},
    };
    use piquel_repository::{RecoveryPasskey, StoredSession};
    use serde_json::json;

    /// Every category serializes under its documented name and shape.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "One literal per category of the document."
    )]
    fn serializes_every_category_in_its_documented_shape() {
        let at = Utc
            .with_ymd_and_hms(2026, 10, 22, 9, 30, 0)
            .single()
            .expect("time");
        let user = UserId::new();
        let passkey = PasskeyId::new();
        let email = EmailId::new();
        let recovery = RecoveryId::new();
        let session = SessionId::new();
        let grant = TokenId::new();
        let event = EventId::new();
        let client: ClientId = "notes".parse().expect("client");
        let device = UserAgentFamily {
            browser: Browser::Firefox,
            platform: Platform::Linux,
        };
        let export = AccountExport {
            format: FORMAT,
            version: VERSION,
            exported_at: at,
            profile: Profile {
                id: user,
                handle: "ada".parse().expect("handle"),
                display_name: "Ada".into(),
                status: AccountStatus::Active,
                created_at: at,
                updated_at: at,
            },
            handles: vec![HandleHeld::from(StoredHandle {
                handle: "ada".parse().expect("handle"),
                user_id: Some(user),
                claimed_at: at,
                released_at: None,
            })],
            administrator: true,
            dashboard_sessions: vec![DashboardSession::from(DashboardSignIn {
                session_id: session,
                created_at: at,
                confirmed_at: Some(at),
            })],
            emails: vec![EmailView {
                id: email,
                address: "ada@example.com".into(),
                verified: true,
                primary: true,
            }],
            passkeys: vec![Passkey {
                id: passkey,
                friendly_name: "Laptop".into(),
                created_at: at,
                last_used_at: None,
                backup_eligible: Some(true),
                backed_up: Some(false),
            }],
            identities: vec![Identity {
                provider: Provider::GitHub,
                subject: "1234".into(),
                linked_email: Some("ada@example.com".into()),
            }],
            sessions: vec![SessionItem::new(
                StoredSession {
                    id: session,
                    user_id: user,
                    authentication_methods: vec![AuthenticationMethod::Passkey],
                    authenticated_at: at,
                    expires_at: at,
                    last_seen_at: at,
                    revoked_at: None,
                    passkey_confirmed_at: Some(at),
                    user_agent_family: Some(device),
                    last_seen_ip: Some([192, 0, 2, 1].into()),
                },
                Some(session),
            )],
            consents: vec![Consent {
                client_id: client.to_string(),
                audience: "notes".into(),
                scopes: vec!["openid".into()],
            }],
            grants: vec![StoredGrant {
                id: grant,
                client_id: client.clone(),
                audience: "notes".into(),
                scopes: vec!["openid".into(), "offline_access".into()],
                created_at: at,
                revoked_at: None,
            }],
            clients: Vec::new(),
            recoveries: vec![Recovery::from(RecentRecovery {
                id: recovery,
                started_at: at,
                expires_at: at,
                completed_at: Some(at),
                cancelled_at: None,
                undone_at: None,
                state: RecoveryState::Probation { settles_at: at },
                passkey: Some(RecoveryPasskey {
                    id: passkey,
                    friendly_name: Some("Laptop".into()),
                    active: true,
                }),
            })],
            history: vec![HistoryItem {
                id: event,
                occurred_at: at,
                entry: HistoryEntry::SignedIn {
                    method: AuthenticationMethod::Passkey,
                },
                actor: HistoryActor::Account,
                reason: None,
                client: Some(ClientView {
                    id: client,
                    name: Some("Notes".into()),
                }),
                ip: Some([192, 0, 2, 1].into()),
                device: Some(device),
                erased: false,
            }],
        };
        assert_eq!(export.file_name(), "piquel-account-ada-2026-10-22.json");
        let time = "2026-10-22T09:30:00Z";
        assert_eq!(
            serde_json::to_value(&export).expect("export"),
            json!({
                "format": "piquel.account-export",
                "version": 1,
                "exported_at": time,
                "profile": {
                    "id": user,
                    "handle": "ada",
                    "display_name": "Ada",
                    "status": "active",
                    "created_at": time,
                    "updated_at": time,
                },
                "handles": [{"handle": "ada", "claimed_at": time, "released_at": null}],
                "administrator": true,
                "dashboard_sessions": [
                    {"session_id": session, "created_at": time, "confirmed_at": time}
                ],
                "emails": [{"id": email, "address": "ada@example.com", "verified": true, "primary": true}],
                "passkeys": [{
                    "id": passkey,
                    "friendly_name": "Laptop",
                    "created_at": time,
                    "last_used_at": null,
                    "backup_eligible": true,
                    "backed_up": false,
                }],
                "identities": [{
                    "provider": "github",
                    "subject": "1234",
                    "linked_email": "ada@example.com",
                }],
                "sessions": [{
                    "id": session,
                    "current": true,
                    "device": {"browser": "firefox", "platform": "linux"},
                    "ip": "192.0.2.1",
                    "methods": ["passkey"],
                    "authenticated_at": time,
                    "last_seen_at": time,
                    "expires_at": time,
                }],
                "consents": [{"client_id": "notes", "audience": "notes", "scopes": ["openid"]}],
                "grants": [{
                    "id": grant,
                    "client_id": "notes",
                    "audience": "notes",
                    "scopes": ["openid", "offline_access"],
                    "created_at": time,
                    "revoked_at": null,
                }],
                "clients": [],
                "recoveries": [{
                    "id": recovery,
                    "started_at": time,
                    "expires_at": time,
                    "completed_at": time,
                    "passkey_id": passkey,
                    "cancelled_at": null,
                    "undone_at": null,
                    "state": "probation",
                    "settles_at": time,
                }],
                "history": [{
                    "id": event,
                    "occurred_at": time,
                    "kind": "session.signed_in",
                    "method": "passkey",
                    "actor": "account",
                    "reason": null,
                    "client": {"id": "notes", "name": "Notes"},
                    "ip": "192.0.2.1",
                    "device": {"browser": "firefox", "platform": "linux"},
                    "erased": false,
                }],
            })
        );
    }
}
