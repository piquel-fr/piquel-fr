//! Which events notify their subject, and how a notification is stored.
use super::Notification;
use crate::{
    EmailId, PasskeyId, Personal, SessionId, UserId,
    events::{Actor, DomainEvent},
};

/// The owner, signed in.
fn owner() -> Actor {
    Actor::User {
        user_id: UserId::new(),
        session_id: Some(SessionId::new()),
    }
}

/// An administrator, through the dashboard.
fn admin() -> Actor {
    Actor::Admin {
        user_id: UserId::new(),
        session_id: SessionId::new(),
    }
}

/// Support renaming an account or one of its passkeys, or removing its picture,
/// tells its owner; the owner doing so does not.
#[test]
fn only_support_renames_notify() {
    let renamed = DomainEvent::DisplayNameChanged {
        old: Personal::Value("Ada".to_owned()),
        new: Personal::Value("Ada L.".to_owned()),
    };
    assert_eq!(renamed.notification(&owner()), None);
    assert_eq!(
        renamed.notification(&admin()),
        Some(Notification::DisplayNameChanged)
    );
    let cli = Actor::Cli {
        os_user: "root".to_owned(),
        host: "host".to_owned(),
    };
    assert_eq!(
        renamed.notification(&cli),
        Some(Notification::DisplayNameChanged)
    );
    let passkey = DomainEvent::PasskeyRenamed {
        passkey_id: PasskeyId::new(),
    };
    assert_eq!(passkey.notification(&owner()), None);
    assert_eq!(
        passkey.notification(&admin()),
        Some(Notification::PasskeyRenamed)
    );
    assert_eq!(
        passkey.notification(&cli),
        Some(Notification::PasskeyRenamed)
    );
    let removed = DomainEvent::PictureRemoved {};
    assert_eq!(removed.notification(&owner()), None);
    assert_eq!(
        removed.notification(&admin()),
        Some(Notification::PictureRemoved)
    );
}

/// Only a primary address that replaced another tells the owner: the first
/// verified address replaced nothing.
#[test]
fn only_a_replaced_primary_notifies() {
    let first = DomainEvent::PrimaryEmailChanged {
        email_id: EmailId::new(),
        previous_email_id: None,
    };
    assert_eq!(first.notification(&owner()), None);
    let replaced = DomainEvent::PrimaryEmailChanged {
        email_id: EmailId::new(),
        previous_email_id: Some(EmailId::new()),
    };
    assert_eq!(
        replaced.notification(&owner()),
        Some(Notification::PrimaryEmailChanged)
    );
}

/// A notification is stored under a stable `kind`, with its facts beside it.
#[test]
fn notifications_serialize_by_kind() {
    let stored =
        serde_json::to_value(Notification::AccountSecured { kept: true }).expect("serializes");
    assert_eq!(
        stored,
        serde_json::json!({ "kind": "account_secured", "kept": true })
    );
    let unit = serde_json::to_value(Notification::EmailRemoved).expect("serializes");
    assert_eq!(unit, serde_json::json!({ "kind": "email_removed" }));
}

/// Each alerting event, as its actor causes it, with the notification it gives.
#[expect(
    clippy::too_many_lines,
    reason = "One entry per alerting event, so the list reads as the issue's."
)]
fn alerts() -> [(DomainEvent, Actor, Notification); 12] {
    use crate::{
        PasskeyId, Provider, RecoveryId, TokenId,
        events::{GrantRevocation, RevocationReason, SignInFailure},
    };
    use chrono::Utc;
    let passkey_id = PasskeyId::new();
    [
        (
            DomainEvent::SignedIn {
                session_id: SessionId::new(),
                method: crate::AuthenticationMethod::Passkey,
                inline: None,
                new_device: true,
            },
            owner(),
            Notification::NewDeviceSignIn,
        ),
        (
            DomainEvent::PasskeyAdded { passkey_id },
            owner(),
            Notification::PasskeyAdded,
        ),
        (
            DomainEvent::PasskeyRemoved { passkey_id },
            admin(),
            Notification::PasskeyRemoved,
        ),
        (
            DomainEvent::IdentityLinked {
                provider: Provider::GitHub,
                subject: Personal::Value("1".to_owned()),
            },
            owner(),
            Notification::IdentityLinked {
                provider: Provider::GitHub,
            },
        ),
        (
            DomainEvent::IdentityUnlinked {
                provider: Provider::Google,
            },
            owner(),
            Notification::IdentityUnlinked {
                provider: Provider::Google,
            },
        ),
        (
            DomainEvent::EmailAdded {
                email_id: EmailId::new(),
                address: Personal::Erased,
                provider: Some(Provider::Google),
            },
            owner(),
            Notification::EmailAdded {
                provider: Some(Provider::Google),
            },
        ),
        (
            DomainEvent::GrantRevoked {
                client_id: "notes".parse().expect("client ID"),
                family_id: TokenId::new(),
                reason: GrantRevocation::RefreshReplay,
            },
            Actor::Anonymous,
            Notification::TokenReused,
        ),
        (
            DomainEvent::RecoveryStarted {
                recovery_id: RecoveryId::new(),
                expires_at: Utc::now(),
                revoke: None,
            },
            admin(),
            Notification::RecoveryStarted,
        ),
        (
            DomainEvent::SessionRevoked {
                session_id: SessionId::new(),
                reason: RevocationReason::Admin,
            },
            admin(),
            Notification::SignedOutBySupport,
        ),
        (
            DomainEvent::CompromiseReported {
                event_id: crate::EventId::new(),
            },
            owner(),
            Notification::CompromiseReported,
        ),
        (
            DomainEvent::SignInFailed {
                method: crate::AuthenticationMethod::Passkey,
                reason: SignInFailure::CounterRegression,
            },
            Actor::Anonymous,
            Notification::PasskeyCopied,
        ),
        (
            DomainEvent::SignInFailed {
                method: crate::AuthenticationMethod::Federation,
                reason: SignInFailure::AccountUnavailable,
            },
            Actor::Anonymous,
            Notification::SignInRefused,
        ),
    ]
}

/// Every alerting event of the owner's or support's is a security notification,
/// emailed to the primary address, or to every verified one for a recovery.
#[test]
fn alerting_events_are_security_notifications() {
    use crate::notifications::Addressees;
    for (event, actor, expected) in alerts() {
        let notification = event.notification(&actor);
        assert_eq!(notification.as_ref(), Some(&expected), "{event:?}");
        assert!(expected.security(), "{expected:?}");
        let addressees = match expected {
            Notification::RecoveryStarted => Addressees::Verified,
            _ => Addressees::Primary,
        };
        assert_eq!(expected.addressees(), addressees, "{expected:?}");
    }
}

/// Signing up and a recovery's link add passkeys, identities and addresses
/// without a session; those steps alert no one, nor does a sign-in from a known
/// browser.
#[test]
fn sessionless_steps_and_known_browsers_alert_no_one() {
    let signing_up = Actor::User {
        user_id: UserId::new(),
        session_id: None,
    };
    let added = DomainEvent::PasskeyAdded {
        passkey_id: crate::PasskeyId::new(),
    };
    assert_eq!(added.notification(&signing_up), None);
    assert_eq!(added.notification(&Actor::Anonymous), None);
    let known = DomainEvent::SignedIn {
        session_id: SessionId::new(),
        method: crate::AuthenticationMethod::Passkey,
        inline: None,
        new_device: false,
    };
    assert_eq!(known.notification(&owner()), None);
}

/// Only announcements, messages and raised alerts are outside the security
/// category: every other notification is about the account itself.
#[test]
fn only_administrators_words_are_outside_security() {
    let outside = [
        Notification::Announcement {
            announcement_id: crate::AnnouncementId::new(),
            title: String::new(),
            text: String::new(),
        },
        Notification::AlertRaised {
            alert_id: crate::AlertId::new(),
            title: String::new(),
            text: String::new(),
        },
        Notification::Message {
            title: String::new(),
            text: String::new(),
        },
    ];
    for notification in outside {
        assert!(!notification.security(), "{notification:?}");
    }
    assert!(Notification::NewDeviceSignIn.security());
}
