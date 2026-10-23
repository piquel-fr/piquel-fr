//! Database-backed session scenarios: whose sessions the list shows, and which
//! ones each sign-out ends.

use super::*;
use crate::{
    account::AccountApplication,
    routes,
    tests::{Browser, Replicas},
};
use axum::{
    Router,
    http::{Method, StatusCode},
};
use piquel_common::events::{Actor, DomainEvent, RevocationReason};
use piquel_repository::Database;
use serde_json::{Value, json};

/// The session routes over the test database.
struct Harness {
    /// Routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
}

impl Harness {
    /// Builds the session routes over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            router: AccountApplication::new(database.clone()).routes(),
            database,
        }
    }

    /// The `(id, current)` pairs of `browser`'s session list, in its order.
    async fn list(&self, browser: &Browser) -> Vec<(Value, bool)> {
        let (status, list) = browser
            .call(&self.router, Method::GET, routes::sessions::LIST)
            .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        list.as_array()
            .expect("a list")
            .iter()
            .map(|item| (item["id"].clone(), item["current"] == true))
            .collect()
    }

    /// Signs `session` out as `browser`.
    async fn revoke(&self, browser: &Browser, session: SessionId) -> StatusCode {
        let path = routes::sessions::ITEM.replace("{id}", &session.to_string());
        browser.call(&self.router, Method::DELETE, &path).await.0
    }

    /// Whether `session` is still active.
    async fn active(&self, session: SessionId) -> bool {
        self.database
            .sessions()
            .find_active_by_id(session)
            .await
            .expect("lookup")
            .is_some()
    }
}

/// The list shows the caller's active sessions, most recently active first, with
/// the device, IP and methods of each, and marks the caller's own.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_list_shows_only_the_callers_sessions() {
    let harness = Harness::new().await;
    let laptop = Browser::new_account(&harness.database).await;
    let phone = Browser::sign_in(&harness.database, laptop.user_id).await;
    let stranger = Browser::new_account(&harness.database).await;

    assert_eq!(
        harness.list(&laptop).await,
        [
            (json!(phone.session_id), false),
            (json!(laptop.session_id), true)
        ]
    );
    let (_, list) = laptop
        .call(&harness.router, Method::GET, routes::sessions::LIST)
        .await;
    assert_eq!(
        list[0]["device"],
        json!({"browser": "firefox", "platform": "linux"})
    );
    assert_eq!(list[0]["ip"], "192.0.2.1");
    assert_eq!(list[0]["methods"], json!(["passkey"]));
    assert_eq!(
        harness.list(&stranger).await,
        [(json!(stranger.session_id), true)]
    );
}

/// One session is signed out with its own sign-out event, attributed to the
/// caller. The caller's own session and another account's are refused.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_out_one_session_ends_only_that_one() {
    let harness = Harness::new().await;
    let laptop = Browser::new_account(&harness.database).await;
    let phone = Browser::sign_in(&harness.database, laptop.user_id).await;
    let stranger = Browser::new_account(&harness.database).await;

    assert_eq!(
        harness.revoke(&laptop, laptop.session_id).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        harness.revoke(&laptop, stranger.session_id).await,
        StatusCode::NOT_FOUND
    );
    assert!(harness.active(stranger.session_id).await);

    assert_eq!(
        harness.revoke(&laptop, phone.session_id).await,
        StatusCode::NO_CONTENT
    );
    assert!(!harness.active(phone.session_id).await);
    assert!(harness.active(laptop.session_id).await);
    assert_eq!(
        harness.revoke(&laptop, phone.session_id).await,
        StatusCode::NOT_FOUND,
        "a signed-out session is gone"
    );
    let latest = harness
        .database
        .events()
        .history_for_user(laptop.user_id, 1)
        .await
        .expect("history")
        .remove(0);
    assert_eq!(
        latest.actor,
        Actor::User {
            user_id: laptop.user_id,
            session_id: Some(laptop.session_id),
        }
    );
    assert_eq!(
        latest.event.known(),
        Some(&DomainEvent::SessionRevoked {
            session_id: phone.session_id,
            reason: RevocationReason::UserRevoked,
        })
    );
}

/// Signing out everywhere else ends every other session of the account, says how
/// many, and keeps the caller's and other accounts' sessions.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_out_others_keeps_the_current_session() {
    let harness = Harness::new().await;
    let laptop = Browser::new_account(&harness.database).await;
    let phone = Browser::sign_in(&harness.database, laptop.user_id).await;
    let tablet = Browser::sign_in(&harness.database, laptop.user_id).await;
    let stranger = Browser::new_account(&harness.database).await;

    let (status, body) = laptop
        .call(
            &harness.router,
            Method::POST,
            routes::sessions::REVOKE_OTHERS,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"revoked": 2}));
    for session in [phone.session_id, tablet.session_id] {
        assert!(!harness.active(session).await);
    }
    assert_eq!(
        harness.list(&laptop).await,
        [(json!(laptop.session_id), true)]
    );
    assert!(harness.active(stranger.session_id).await);
}
