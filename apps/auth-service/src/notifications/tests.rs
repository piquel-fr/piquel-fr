//! Database-backed inbox scenarios: what an event tells its owner, reading
//! without marking, marking as the owner only, and whose inbox a call reaches.

use super::*;
use crate::{
    account::AccountApplication,
    tests::{Browser, Replicas},
};
use axum::http::{Method, StatusCode};
use serde_json::Value;
use sourceorigin_common::{
    UserId,
    events::{Actor, DomainEvent, EventContext, RequestOrigin},
};

/// The inbox routes, shared and the owner's, over the test database.
struct Harness {
    /// Routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
}

impl Harness {
    /// Builds the inbox routes over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            router: NotificationApplication::new(database.clone())
                .routes()
                .merge(AccountApplication::new(database.clone()).routes()),
            database,
        }
    }

    /// An administrator enabling `account`, which tells its owner.
    async fn enable(&self, account: &Browser) {
        let context = EventContext {
            actor: Actor::Admin {
                user_id: UserId::new(),
                session_id: account.session_id,
            },
            origin: RequestOrigin::default(),
            reason: None,
        };
        let mut tx = self.database.begin().await.expect("transaction");
        tx.record(
            &context,
            Some(account.user_id),
            DomainEvent::AccountEnabled {},
        )
        .await
        .expect("record");
        tx.commit().await.expect("commit");
    }

    /// `account`'s inbox, through the API.
    async fn inbox(&self, account: &Browser) -> Value {
        let (status, page) = account
            .call(&self.router, Method::GET, routes::notifications::LIST)
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        page
    }

    /// How many of `account`'s notifications are unread, through the API.
    async fn unread(&self, account: &Browser) -> u64 {
        let (status, unread) = account
            .call(&self.router, Method::GET, routes::notifications::UNREAD)
            .await;
        assert_eq!(status, StatusCode::OK, "{unread}");
        unread["unread"].as_u64().expect("count")
    }

    /// Calls `template`'s route for the notification `id` as `account`.
    async fn on(
        &self,
        account: &Browser,
        method: Method,
        template: &str,
        id: &str,
    ) -> (StatusCode, Value) {
        let path = template.replace("{id}", id);
        account.call(&self.router, method, &path).await
    }
}

/// An event that tells its owner lands in their inbox, unread, with what it
/// says and the event it came from. Reading it through the API marks nothing;
/// the owner marks it read and unread, one at a time or all at once.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_read_and_mark_their_notifications() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    harness.enable(&alice).await;
    harness.enable(&alice).await;

    let inbox = harness.inbox(&alice).await;
    let notifications = inbox["notifications"].as_array().expect("notifications");
    assert_eq!(notifications.len(), 2);
    assert_eq!(notifications[0]["kind"], "account_enabled");
    assert_eq!(
        notifications[0]["subject"],
        "Your account was enabled again"
    );
    assert!(notifications[0]["event_id"].is_string());
    assert!(notifications[0]["read_at"].is_null());
    let id = notifications[0]["id"].as_str().expect("id");

    let (status, shown) = harness
        .on(&alice, Method::GET, routes::notifications::ITEM, id)
        .await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["history"]["kind"], "account.enabled");
    assert_eq!(harness.unread(&alice).await, 2, "reading marks nothing");

    let (status, _) = harness
        .on(&alice, Method::POST, routes::notifications::READ, id)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(harness.unread(&alice).await, 1);
    let (status, _) = harness
        .on(&alice, Method::POST, routes::notifications::MARK_UNREAD, id)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(harness.unread(&alice).await, 2);
    let (status, _) = alice
        .call(
            &harness.router,
            Method::POST,
            routes::notifications::READ_ALL,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(harness.unread(&alice).await, 0);
}

/// Nobody reads or marks another account's notification: it is not found, and
/// stays unread.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn notifications_stay_their_owners() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    let mallory = Browser::new_account(&harness.database).await;
    harness.enable(&alice).await;
    let inbox = harness.inbox(&alice).await;
    let id = inbox["notifications"][0]["id"].as_str().expect("id");

    assert_eq!(
        harness.inbox(&mallory).await["notifications"],
        serde_json::json!([])
    );
    for (method, template) in [
        (Method::GET, routes::notifications::ITEM),
        (Method::POST, routes::notifications::READ),
        (Method::POST, routes::notifications::MARK_UNREAD),
    ] {
        let (status, _) = harness.on(&mallory, method, template, id).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{template}");
    }
    let (status, _) = mallory
        .call(
            &harness.router,
            Method::POST,
            routes::notifications::READ_ALL,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(harness.unread(&alice).await, 1);
}

/// A notification renders from itself: once audit pruning deleted its event, its
/// page still says what happened, without a history entry.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn notifications_outlive_their_event() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    let pruned = EventId::new();
    let id = harness
        .database
        .notifications()
        .insert(alice.user_id, Some(pruned), &Notification::AccountRestored)
        .await
        .expect("insert")
        .expect("the account exists");
    let (status, shown) = harness
        .on(
            &alice,
            Method::GET,
            routes::notifications::ITEM,
            &id.to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["body"], "It is no longer scheduled for deletion.");
    assert!(shown["history"].is_null());
}

/// The owner turns a category's email off and on through the API, each change
/// recorded once, and anyone who may read the inbox reads the preferences. An
/// unsubscribe link works only for its own account, and turns the email off as
/// the owner, without a session.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_choose_which_notifications_are_emailed() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    let bob = Browser::new_account(&harness.database).await;
    let preferences = async |account: &Browser| {
        let path = routes::notifications::PREFERENCES;
        let (status, preferences) = account.call(&harness.router, Method::GET, path).await;
        assert_eq!(status, StatusCode::OK, "{preferences}");
        preferences
    };
    let announcements = |email| serde_json::json!([{"category": "announcements", "email": email}]);
    assert_eq!(
        preferences(&alice).await,
        announcements(true),
        "on by default"
    );
    for email in [false, false, true] {
        let preference = serde_json::json!({"category": "announcements", "email": email});
        let (status, _) = alice
            .send(
                &harness.router,
                Method::PUT,
                routes::notifications::PREFERENCES,
                Some(preference),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let changes = async |user: UserId| -> Vec<(bool, Actor)> {
        harness
            .database
            .events()
            .history_for_user(user, 20)
            .await
            .expect("history")
            .into_iter()
            .filter_map(|stored| match stored.event.known() {
                Some(DomainEvent::NotificationPreferenceChanged(preference)) => {
                    Some((preference.email, stored.actor))
                }
                _ => None,
            })
            .collect()
    };
    let emails: Vec<_> = changes(alice.user_id)
        .await
        .into_iter()
        .map(|(email, _)| email)
        .collect();
    assert_eq!(emails, [true, false], "a repeat changes nothing");

    let links = UnsubscribeLinks::new(
        "https://auth.sourceorigin.dev".parse().expect("origin"),
        crate::config::LinkKeys::generate(),
    );
    let link = url::Url::parse(&links.link(alice.user_id).expect("link")).expect("URL");
    assert_eq!(link.path(), routes::page::UNSUBSCRIBE);
    let query = |name: &str| {
        link.query_pairs()
            .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
            .expect("query")
    };
    let token = query("token");
    assert_eq!(query("account"), alice.user_id.to_string());
    let checked = |account, token: &str| {
        links
            .check(&Unsubscribe {
                account,
                token: token.to_owned(),
            })
            .expect("check")
    };
    assert_eq!(checked(alice.user_id, &token), Some(alice.user_id));
    assert_eq!(checked(bob.user_id, &token), None, "another account's");
    assert_eq!(checked(alice.user_id, "garbage"), None);

    let service = AccountService::new(harness.database.clone());
    service
        .unsubscribe(alice.user_id, crate::security::RequestContext::TEST)
        .await
        .expect("unsubscribe");
    assert_eq!(preferences(&alice).await, announcements(false));
    let (_, actor) = changes(alice.user_id).await.remove(0);
    assert_eq!(
        actor,
        Actor::User {
            user_id: alice.user_id,
            session_id: None
        }
    );
    assert_eq!(preferences(&bob).await, announcements(true));
}
