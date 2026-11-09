//! Which events notify their subject, and how a notification is stored.
use super::Notification;
use crate::{
    EmailId, Personal, SessionId, UserId,
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

/// Support renaming an account, or removing its picture, tells its owner; the
/// owner doing so does not.
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
