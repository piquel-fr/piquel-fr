//! Disabling and enabling an account, and reading its event history.

use super::*;
use axum::http::{Method, StatusCode};
use serde_json::json;
use sourceorigin_common::events::RevocationReason;

/// The event list shows changes: an administrator's views of an account only
/// when asked for.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn views_are_listed_only_when_asked_for() {
    let harness = Harness::new().await;
    let service = harness.service();
    let administrator = operator(harness.admin().await, Utc::now());
    let user = harness.account().await.user_id;
    service.view_user(&administrator, user).await.expect("view");
    let kinds = async |views| {
        let search = EventSearch {
            user: Some(user),
            views,
            ..EventSearch::default()
        };
        let page = service
            .events(&administrator, search)
            .await
            .expect("events");
        page.events
            .into_iter()
            .map(|event| event.event["kind"].clone())
            .collect::<Vec<_>>()
    };
    assert!(!kinds(false).await.contains(&json!("account_viewed")));
    assert!(kinds(true).await.contains(&json!("account_viewed")));
}

/// Disabling an account ends its sessions at once and records why; enabling it
/// restores it, and both show in the events, attributed to the administrator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn disabling_ends_sessions_and_is_recorded() {
    let capture = sourceorigin_telemetry::Telemetry::capture(crate::TELEMETRY_FILTER);
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let user = harness.account().await;
    let administrator = operator(admin, Utc::now());
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
        .enable_user(&administrator, user.user_id, reason("Asked by email"))
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
                ..EventSearch::default()
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

/// Every change an administrator makes to an account records their reason, which
/// the owner reads in their own security history: enabling it, signing out
/// one session or every one, and granting and revoking its rights.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_change_to_an_account_shows_its_reason_to_the_owner() {
    let harness = Harness::new().await;
    let service = harness.service();
    let administrator = operator(harness.admin().await, Utc::now());
    let user = harness.account().await;
    let id = user.user_id;
    service
        .disable_user(&cli(), id, reason("Spam"))
        .await
        .expect("disable");
    service
        .enable_user(&administrator, id, reason("Appealed"))
        .await
        .expect("enable");
    let laptop = Browser::sign_in(&harness.database, id).await;
    Browser::sign_in(&harness.database, id).await;
    service
        .revoke_session(
            &administrator,
            id,
            laptop.session_id,
            reason("Laptop stolen"),
        )
        .await
        .expect("revoke one");
    service
        .revoke_user_sessions(&administrator, id, reason("Phone stolen too"))
        .await
        .expect("revoke all");
    service
        .grant_administrator(&cli(), id, reason("Joined support"))
        .await
        .expect("grant");
    service
        .revoke_administrator(&cli(), id, reason("Left support"))
        .await
        .expect("revoke rights");

    // The owner reads them in their own history, signed in again.
    let browser = Browser::sign_in(&harness.database, id).await;
    let routes = crate::account::AccountApplication::new(harness.database.clone()).routes();
    let (status, page) = browser
        .call(&routes, Method::GET, crate::routes::history::LIST)
        .await;
    assert_eq!(status, StatusCode::OK);
    let entries = page["entries"].as_array().expect("entries");
    let reasons = |kind: &str| {
        entries
            .iter()
            .filter(|entry| entry["kind"] == kind)
            .map(|entry| entry["reason"].as_str().expect("a reason"))
            .collect::<Vec<_>>()
    };
    assert_eq!(reasons("account.disabled"), ["Spam"]);
    assert_eq!(reasons("account.enabled"), ["Appealed"]);
    assert_eq!(
        reasons("session.revoked"),
        ["Phone stolen too", "Laptop stolen", "Spam"]
    );
    assert_eq!(reasons("administrator.granted"), ["Joined support"]);
    assert_eq!(reasons("administrator.revoked"), ["Left support"]);
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
