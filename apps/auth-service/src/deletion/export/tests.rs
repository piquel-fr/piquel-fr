//! The export's JSON shape, which downloads keep across releases.
use super::*;
use crate::history::{ClientView, HistoryItem};
use crate::notifications::NotificationItem;
use chrono::TimeZone;
use piquel_common::{
    AuthenticationMethod, ClientId, EmailId, EventId, NotificationId, TokenId,
    events::{Browser, HistoryActor, HistoryEntry, Platform, UserAgentFamily},
    notifications::{EmailCategory, Notification, NotificationPreference},
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
    let picture = PictureId::new();
    let notification = NotificationId::new();
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
        picture: Some(Picture::new(
            StoredPicture {
                id: picture,
                created_at: at,
            },
            b"jpeg",
        )),
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
                origin: None,
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
        notifications: vec![NotificationItem {
            id: notification,
            created_at: at,
            read_at: None,
            event_id: Some(event),
            notification: Notification::AccountEnabled,
            subject: Notification::AccountEnabled.subject().to_owned(),
            body: Notification::AccountEnabled.body(),
        }],
        notification_preferences: vec![NotificationPreference {
            category: EmailCategory::Announcements,
            email: false,
        }],
    };
    assert_eq!(export.file_name(), "piquel-account-ada-2026-10-22.json");
    let time = "2026-10-22T09:30:00Z";
    assert_eq!(
        serde_json::to_value(&export).expect("export"),
        json!({
            "format": "piquel.account-export",
            "version": 2,
            "exported_at": time,
            "profile": {
                "id": user,
                "handle": "ada",
                "display_name": "Ada",
                "status": "active",
                "created_at": time,
                "updated_at": time,
            },
            "picture": {
                "id": picture,
                "created_at": time,
                "content_type": "image/jpeg",
                "data": "anBlZw==",
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
            "notifications": [{
                "id": notification,
                "created_at": time,
                "read_at": null,
                "event_id": event,
                "kind": "account_enabled",
                "subject": "Your account was enabled again",
                "body": "You can sign in to it again.",
            }],
            "notification_preferences": [{"category": "announcements", "email": false}],
        })
    );
}
