//! Database-backed availability and rename scenarios.

use super::*;
use crate::tests::{Browser, Replicas};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

/// The handle routes over the test database.
struct Harness {
    /// Routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
}

impl Harness {
    /// Builds the handle routes over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            router: HandleApplication::new(database.clone()).routes(),
            database,
        }
    }

    /// `browser`'s answer for `handle`: `None` when it is available, else its code.
    async fn availability(&self, browser: &Browser, handle: &str) -> Option<String> {
        let path = routes::handles::AVAILABILITY.replace("{handle}", handle);
        let (status, body) = browser.call(&self.router, Method::GET, &path).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["available"], body.get("code").is_none(), "{body}");
        body["code"].as_str().map(str::to_owned)
    }

    /// Renames `browser`'s account to `handle`.
    async fn rename(&self, browser: &Browser, handle: &str) -> (StatusCode, Value) {
        browser
            .send(
                &self.router,
                Method::PUT,
                routes::handles::ACCOUNT,
                Some(json!({ "handle": handle })),
            )
            .await
    }

    /// Ends `browser`'s rename cooldown.
    async fn wait_out_cooldown(&self, browser: &Browser) {
        self.database
            .users()
            .age_handle_change(browser.user_id, 31)
            .await
            .expect("age");
    }

    /// `browser`'s account.
    async fn user(&self, browser: &Browser) -> StoredUser {
        self.database
            .users()
            .find_by_id(browser.user_id)
            .await
            .expect("lookup")
            .expect("user")
    }
}

/// Availability reports each refusal with the code a claim would fail with, and
/// lets an account take back its own released handle.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn availability_names_why_a_handle_is_refused() {
    let harness = Harness::new().await;
    let browser = Browser::new_account(&harness.database).await;
    let other = Browser::new_account(&harness.database).await;
    let own = harness.user(&browser).await.handle;
    let taken = harness.user(&other).await.handle;
    let suffix = &browser.user_id.to_string()[24..];
    for (handle, code) in [
        ("a_b".to_owned(), Some("handle_invalid")),
        ("adm1n".to_owned(), Some("handle_reserved")),
        (taken.to_string(), Some("handle_taken")),
        (taken.as_str().replace('-', ""), Some("handle_confusable")),
        (own.to_string(), Some("handle_current")),
        (format!("Free-{suffix}"), None),
    ] {
        assert_eq!(
            harness.availability(&browser, &handle).await.as_deref(),
            code,
            "{handle}"
        );
    }
    harness.wait_out_cooldown(&browser).await;
    let renamed = format!("renamed-{suffix}");
    assert_eq!(harness.rename(&browser, &renamed).await.0, StatusCode::OK);
    assert_eq!(harness.availability(&browser, own.as_str()).await, None);
    assert_eq!(
        harness.availability(&other, own.as_str()).await.as_deref(),
        Some("handle_retired")
    );
}

/// A rename needs the cooldown to have passed since the last change, reclaims
/// included, and bumps the profile version and records the change.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn renames_wait_out_the_cooldown() {
    let harness = Harness::new().await;
    let browser = Browser::new_account(&harness.database).await;
    let original = harness.user(&browser).await;
    let renamed = format!("renamed-{}", &browser.user_id.to_string()[24..]);
    // A new account's handle has just been chosen.
    let (status, body) = harness.rename(&browser, &renamed).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "handle_cooldown");
    let retry_after: chrono::DateTime<Utc> =
        serde_json::from_value(body["retry_after"].clone()).expect("retry_after");
    assert_eq!(retry_after, original.handle_changed_at + COOLDOWN);

    harness.wait_out_cooldown(&browser).await;
    let (status, body) = harness.rename(&browser, &format!(" {renamed} ")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["handle"], renamed);
    let user = harness.user(&browser).await;
    assert_eq!(user.handle.as_str(), renamed);
    assert_eq!(user.profile_version, original.profile_version + 1);
    let history = harness
        .database
        .events()
        .history_for_user(browser.user_id, 1)
        .await
        .expect("history");
    assert_eq!(
        history[0].event.known(),
        Some(&DomainEvent::HandleChanged {
            old: Personal::Value(original.handle.to_string()),
            new: Personal::Value(user.handle.clone()),
        })
    );
    assert_eq!(
        harness.rename(&browser, original.handle.as_str()).await.1["code"],
        "handle_cooldown"
    );

    // Taking back the old handle restarts the cooldown too.
    harness.wait_out_cooldown(&browser).await;
    assert_eq!(
        harness.rename(&browser, original.handle.as_str()).await.0,
        StatusCode::OK
    );
    assert_eq!(
        harness.rename(&browser, &renamed).await.1["code"],
        "handle_cooldown"
    );
}
