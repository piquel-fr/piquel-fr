//! The export's JSON shape, which downloads keep across releases.
use super::*;
use chrono::TimeZone;
use piquel_common::{
    AnnouncementId, AuthenticationMethod, EmailId, EventId, NotificationId, Provider, TokenId,
    clients::ClientKind,
    events::{Browser, Platform, UserAgentFamily},
    notifications::{EmailCategory, NotificationPreference},
};
use piquel_repository::RecoveryPasskey;
use serde_json::json;

/// Every section but the events serializes under its documented name and shape.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "One literal per section of the document."
)]
fn serializes_every_section_in_its_documented_shape() {
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
    let (notification, newer) = (NotificationId::new(), NotificationId::new());
    let announcement = AnnouncementId::new();
    let client: ClientId = "notes".parse().expect("client");
    let device = UserAgentFamily {
        browser: Browser::Firefox,
        platform: Platform::Linux,
    };
    let ip: std::net::IpAddr = [192, 0, 2, 1].into();
    let records = Records {
        format: FORMAT,
        version: VERSION,
        exported_at: at,
        profile: Profile {
            id: user,
            handle: "ada".parse().expect("handle"),
            handle_changed_at: at,
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
        administrator: Some(Administrator { granted_at: at }),
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
            revoked_at: Some(at),
            backup_eligible: Some(true),
            backed_up: Some(false),
        }],
        identities: vec![IdentityRecord {
            provider: Provider::GitHub,
            subject: "1234".into(),
            linked_email: Some("ada@example.com".into()),
            linked_at: at,
            last_login_at: at,
            revoked_at: None,
        }],
        sessions: vec![Session {
            record: SessionRecord {
                id: session,
                authentication_methods: vec![AuthenticationMethod::Passkey],
                authenticated_at: at,
                device: Some(device),
                created_ip: Some(ip),
                last_seen_at: at,
                last_seen_ip: Some(ip),
                passkey_confirmed_at: Some(at),
                passkey_id: Some(passkey),
                expires_at: at,
                revoked_at: None,
                clients: vec![client.clone()],
            },
            current: true,
        }],
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
        clients: vec![Client {
            view: OwnedClientView {
                id: client.clone(),
                display_name: "Notes".into(),
                kind: ClientKind::Public,
                redirect_uris: vec!["https://notes.example/callback".into()],
                post_logout_uris: Vec::new(),
                allowed_scopes: vec!["openid".into()],
                allow_refresh: false,
                require_pushed_authorization_requests: false,
                backchannel_logout_uri: None,
                enabled: true,
                suspended_at: None,
                last_used_at: Some(at),
            },
            created_at: at,
            deleted_at: None,
            related_origins: vec![ApprovedOrigin {
                origin: "https://notes.example".parse().expect("origin"),
                client_id: client.clone(),
                approved_at: at,
            }],
        }],
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
        notifications: vec![
            Notification::from(NotificationRecord {
                id: notification,
                created_at: at,
                read_at: None,
                event_id: Some(event),
                payload: json!({"kind": "account_enabled"}),
            }),
            Notification::from(NotificationRecord {
                id: newer,
                created_at: at,
                read_at: Some(at),
                event_id: None,
                payload: json!({"kind": "from_a_newer_release", "detail": 1}),
            }),
        ],
        announcements: vec![AnnouncementRecord {
            id: announcement,
            subject: "Maintenance".into(),
            body: "Tonight.".into(),
            everyone: true,
            sent_at: at,
        }],
        notification_preferences: vec![NotificationPreference {
            category: EmailCategory::Announcements,
            email: false,
        }],
    };
    assert_eq!(records.file_name(), "piquel-account-ada-2026-10-22.json");
    let time = "2026-10-22T09:30:00Z";
    assert_eq!(
        serde_json::to_value(&records).expect("export"),
        json!({
            "format": "piquel.account-export",
            "version": 3,
            "exported_at": time,
            "profile": {
                "id": user,
                "handle": "ada",
                "handle_changed_at": time,
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
            "administrator": {"granted_at": time},
            "dashboard_sessions": [
                {"session_id": session, "created_at": time, "confirmed_at": time}
            ],
            "emails": [{"id": email, "address": "ada@example.com", "verified": true, "primary": true}],
            "passkeys": [{
                "id": passkey,
                "friendly_name": "Laptop",
                "created_at": time,
                "last_used_at": null,
                "revoked_at": time,
                "backup_eligible": true,
                "backed_up": false,
            }],
            "identities": [{
                "provider": "github",
                "subject": "1234",
                "linked_email": "ada@example.com",
                "linked_at": time,
                "last_login_at": time,
                "revoked_at": null,
            }],
            "sessions": [{
                "id": session,
                "authentication_methods": ["passkey"],
                "authenticated_at": time,
                "device": {"browser": "firefox", "platform": "linux"},
                "created_ip": "192.0.2.1",
                "last_seen_at": time,
                "last_seen_ip": "192.0.2.1",
                "passkey_confirmed_at": time,
                "passkey_id": passkey,
                "expires_at": time,
                "revoked_at": null,
                "clients": ["notes"],
                "current": true,
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
            "clients": [{
                "id": "notes",
                "display_name": "Notes",
                "kind": "public",
                "redirect_uris": ["https://notes.example/callback"],
                "post_logout_uris": [],
                "allowed_scopes": ["openid"],
                "allow_refresh": false,
                "require_pushed_authorization_requests": false,
                "backchannel_logout_uri": null,
                "enabled": true,
                "suspended_at": null,
                "last_used_at": time,
                "created_at": time,
                "deleted_at": null,
                "related_origins": [{
                    "origin": "https://notes.example",
                    "client_id": "notes",
                    "approved_at": time,
                }],
            }],
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
            "notifications": [{
                "id": notification,
                "created_at": time,
                "read_at": null,
                "event_id": event,
                "kind": "account_enabled",
                "subject": "Your account was enabled again",
                "body": "You can sign in to it again.",
            }, {
                "id": newer,
                "created_at": time,
                "read_at": time,
                "event_id": null,
                "kind": "from_a_newer_release",
                "detail": 1,
                "subject": null,
                "body": null,
            }],
            "announcements": [{
                "id": announcement,
                "subject": "Maintenance",
                "body": "Tonight.",
                "everyone": true,
                "sent_at": time,
            }],
            "notification_preferences": [{"category": "announcements", "email": false}],
        })
    );
}
