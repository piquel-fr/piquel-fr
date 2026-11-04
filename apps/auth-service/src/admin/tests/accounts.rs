//! Disabling and enabling an account, and reading its event history.

use super::*;
use piquel_common::events::RevocationReason;
use serde_json::json;

/// Disabling an account ends its sessions at once and records why; enabling it
/// restores it, and both show in the events, attributed to the administrator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn disabling_ends_sessions_and_is_recorded() {
    let capture = piquel_telemetry::Telemetry::capture(crate::TELEMETRY_FILTER);
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let user = harness.account().await;
    let administrator = operator(admin, Utc::now());
    assert!(matches!(
        Reason::parse(String::new()),
        Err(AdminError::InvalidReason)
    ));
    service
        .disable_user(&administrator, user.user_id, reason("Spam"))
        .await
        .expect("disable");
    let stored = harness
        .database
        .users()
        .find_by_id(user.user_id)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.status, AccountStatus::Disabled);
    let id = admin.user_id.to_string();
    assert!(
        capture.logs().iter().any(|log| {
            let has = |key: &str, value: &str| {
                log.attributes_iter().any(|(name, logged)| {
                    name.as_str() == key && format!("{logged:?}").contains(value)
                })
            };
            has("event.kind", "account_disabled") && has("event.administrator", &id)
        }),
        "the disablement's log line names its administrator"
    );
    assert!(
        harness
            .database
            .sessions()
            .find_by_id(user.session_id)
            .await
            .expect("lookup")
            .expect("session")
            .revoked_at
            .is_some()
    );
    service
        .enable_user(&administrator, user.user_id)
        .await
        .expect("enable");
    assert_eq!(
        harness.events(user.user_id).await[..3],
        [
            DomainEvent::AccountEnabled {},
            DomainEvent::SessionRevoked {
                session_id: user.session_id,
                reason: RevocationReason::AccountDisabled,
            },
            DomainEvent::AccountDisabled {
                reason: Personal::Value("Spam".into()),
            },
        ]
    );
    let page = service
        .events(
            &administrator,
            EventSearch {
                user: Some(user.user_id),
                kind: Some("account_disabled".into()),
                page: None,
            },
        )
        .await
        .expect("events");
    assert_eq!(page.events[0].actor["user_id"], id);
    assert_eq!(
        page.events[0].event["data"]["reason"],
        json!({"$personal": "Spam"})
    );
}

/// An event a newer release wrote, of a kind this one does not know, is listed
/// with its kind, version and data rather than failing the page.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn events_a_newer_release_wrote_are_listed() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let data = json!({"client_id": "deleted"});
    harness
        .database
        .events()
        .insert_written_elsewhere(user.user_id, "from_a_newer_release", 1, &data)
        .await
        .expect("event");
    let filter = EventSearch {
        user: Some(user.user_id),
        ..EventSearch::default()
    };
    let page = harness
        .service()
        .events(&operator(admin, Utc::now()), filter)
        .await
        .expect("events");
    assert_eq!(
        page.events[0].event,
        json!({"kind": "from_a_newer_release", "version": 1, "data": data})
    );
}
