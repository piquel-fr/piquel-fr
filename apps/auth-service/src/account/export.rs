//! The account's data, as its owner downloads it (GDPR Art. 20): one versioned
//! JSON document, read from one snapshot. It holds no secret, digest or key
//! material: passkeys show their label, dates and backup state only.

use crate::{history::HistoryItem, sessions::SessionItem};
use chrono::{DateTime, Utc};
use piquel_admin_api::{Consent, Email};
use piquel_common::{AccountStatus, PasskeyId, Provider, SessionId, UserId};
use piquel_repository::{
    DatabaseError, DatabaseTransaction, StoredExternalIdentity, StoredGrant, StoredOidcClient,
    StoredPasskey, StoredUser,
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
#[derive(Debug, Serialize)]
pub(super) struct AccountExport {
    /// Always [`FORMAT`].
    format: &'static str,
    /// Always [`VERSION`].
    version: u32,
    /// When the export was read.
    exported_at: DateTime<Utc>,
    /// The account itself.
    profile: Profile,
    /// Whether the account is an administrator.
    administrator: bool,
    /// Email addresses, verified or not, primary first.
    emails: Vec<Email>,
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
    /// The OIDC clients the account manages, as the account API shows them.
    clients: Vec<StoredOidcClient>,
    /// The security history, newest first, as the account's history page shows it.
    history: Vec<HistoryItem>,
}

/// The account's profile.
#[derive(Debug, Serialize)]
struct Profile {
    /// Account ID, the `sub` applications know it by.
    id: UserId,
    /// Login name.
    username: String,
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

impl From<StoredUser> for Profile {
    /// Keeps every column.
    fn from(user: StoredUser) -> Self {
        Self {
            id: user.id,
            username: user.username,
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
            administrator: tx.administrators().contains(user_id).await?,
            emails: (tx.emails().list(user_id).await?)
                .into_iter()
                .map(Email::from)
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
                .map(|session| SessionItem::new(session, current))
                .collect(),
            consents: tx.oidc().list_consents(user_id).await?,
            grants: tx.tokens().list_for_user(user_id).await?,
            clients: tx.oidc().list_owned_clients(user_id).await?,
            history: HistoryItem::all(tx, user_id).await?,
            profile: user.into(),
        })
    }

    /// The download's file name, `piquel-account-<username>-<date>.json`.
    /// Handles are lowercase ASCII letters, digits and `-`, so it needs no quoting
    /// in a header.
    pub(super) fn file_name(&self) -> String {
        format!(
            "piquel-account-{}-{}.json",
            self.profile.username,
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
        AuthenticationMethod, ClientId, EventId, TokenId,
        events::{Browser, HistoryActor, HistoryEntry, Platform, UserAgentFamily},
    };
    use piquel_repository::StoredSession;
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
                username: "ada".into(),
                display_name: "Ada".into(),
                status: AccountStatus::Active,
                created_at: at,
                updated_at: at,
            },
            administrator: false,
            emails: vec![Email {
                address: "ada@example.com".into(),
                verified_at: Some(at),
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
                session,
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
            history: vec![HistoryItem {
                id: event,
                occurred_at: at,
                entry: HistoryEntry::SignedIn {
                    method: AuthenticationMethod::Passkey,
                },
                actor: HistoryActor::Account,
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
                    "username": "ada",
                    "display_name": "Ada",
                    "status": "active",
                    "created_at": time,
                    "updated_at": time,
                },
                "administrator": false,
                "emails": [{"address": "ada@example.com", "verified_at": time, "primary": true}],
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
                "history": [{
                    "id": event,
                    "occurred_at": time,
                    "kind": "session.signed_in",
                    "method": "passkey",
                    "actor": "account",
                    "client": {"id": "notes", "name": "Notes"},
                    "ip": "192.0.2.1",
                    "device": {"browser": "firefox", "platform": "linux"},
                    "erased": false,
                }],
            })
        );
    }
}
