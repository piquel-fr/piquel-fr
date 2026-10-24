//! Database-backed recovery scenarios: what a link enrolls, what stops it, who
//! sees it, and who may undo a recovery.

use super::*;
use crate::{
    AdminError, AdminService, Operator, Reason,
    admin::tests::{Harness, cli, operator},
    passkey::tests::Fixture,
    tests::{AUTH_ORIGIN, Browser},
};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use piquel_common::{AuthenticationMethod, EmailId, PasskeyId};
use piquel_repository::{Database, InsertVerifiedEmail};
use serde_json::{Value, json};

/// Links with a key of their own: the routes find a recovery by its token's
/// digest, so they need no key.
fn links() -> RecoveryLinks {
    RecoveryLinks::new(
        AUTH_ORIGIN.parse().expect("origin"),
        Secret::generate().expect("recovery key"),
    )
}

/// Why the scenarios recover an account.
fn reason() -> Reason {
    Reason::parse("Lost every passkey".into()).expect("reason")
}

/// Adds a verified primary address to `user`, and returns its ID.
async fn reachable(database: &Database, user: UserId) -> EmailId {
    let mut tx = database.begin().await.expect("transaction");
    let email = tx
        .emails()
        .insert_verified(&InsertVerifiedEmail {
            id: EmailId::new(),
            user_id: user,
            normalized_email: format!("{user}@example.com"),
            is_primary: true,
            verified_at: Utc::now(),
        })
        .await
        .expect("address");
    tx.commit().await.expect("commit");
    email.id
}

/// How many messages were queued to `user`'s address `email`.
async fn sent(database: &Database, user: UserId, email: EmailId) -> usize {
    let destination = format!("account {user}, address {email}");
    database
        .deliveries()
        .list(None, Some("email"), 1000)
        .await
        .expect("deliveries")
        .iter()
        .filter(|delivery| delivery.destination == destination)
        .count()
}

/// An account with a passkey, recovered by an operator at the terminal, and its
/// browsers.
struct Scenario {
    /// The account, its original passkey and the recovery routes.
    keys: Fixture,
    /// Derives the links.
    links: RecoveryLinks,
}

impl Scenario {
    /// An account with one passkey, not recovered yet.
    async fn new() -> Self {
        Self {
            keys: Fixture::new().await,
            links: links(),
        }
    }

    /// Recovers the account as an operator at the terminal, and returns the
    /// link's token.
    async fn recover(&self) -> String {
        let link = AdminService::new(self.keys.database().clone())
            .recover_account(&cli(), self.keys.user_id, reason(), &self.links)
            .await
            .expect("recovery")
            .expect("the terminal sees the link");
        let fragment = link.fragment().expect("fragment");
        fragment.strip_prefix("token=").expect("token").to_owned()
    }

    /// Sends `body` to `path` from a browser holding `cookies`.
    async fn send(&self, method: Method, path: &str, cookies: &str, body: Value) -> Response {
        self.keys.request(path, method, cookies, body).await
    }

    /// Describes the account `token` recovers, as its page does on load.
    async fn check(&self, token: &str) -> (StatusCode, Value) {
        let body = json!({ "token": token });
        let response = self
            .send(Method::POST, routes::recovery::CHECK, "", body)
            .await;
        (response.status(), Fixture::json(response).await)
    }

    /// Starts enrolling a passkey with `token`, returning the challenge and the
    /// browser's ceremony cookie.
    async fn start(&self, token: &str) -> (Value, String) {
        let body = json!({ "token": token });
        self.keys.start(routes::recovery::START, "", body).await
    }

    /// Answers `started` with a new passkey from the browser holding `browser`.
    async fn finish(&self, started: &Value, browser: &str) -> Response {
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": self.keys.credential(started),
            "friendly_name": "Recovered",
        });
        self.send(Method::POST, routes::recovery::FINISH, browser, body)
            .await
    }

    /// Enrolls a passkey with `token`, and returns the session cookie it signs
    /// in with.
    async fn enroll(&self, token: &str) -> String {
        let (started, browser) = self.start(token).await;
        let response = self.finish(&started, &browser).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Fixture::cookie(&response)
    }

    /// The newest recovery the browser holding `cookie` could undo.
    async fn status(&self, cookie: &str) -> Value {
        let response = self
            .send(Method::GET, routes::recovery::STATUS, cookie, Value::Null)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        Fixture::json(response).await
    }

    /// Undoes the newest recovery from the browser holding `cookie`.
    async fn undo(&self, cookie: &str) -> StatusCode {
        self.send(Method::POST, routes::recovery::UNDO, cookie, Value::Null)
            .await
            .status()
    }

    /// The account's active passkeys.
    async fn passkeys(&self) -> Vec<PasskeyId> {
        let database = self.keys.database();
        let passkeys = database.passkeys().list_active(self.keys.user_id).await;
        passkeys
            .expect("passkeys")
            .into_iter()
            .map(|passkey| passkey.id)
            .collect()
    }
}

/// A recovery signs the account out everywhere and emails its link. The link
/// names the account, enrolls one passkey and signs the browser in with it, then
/// stops working; every verified address hears of it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_link_enrolls_one_passkey_and_signs_in_with_it() {
    let mut scenario = Scenario::new().await;
    let database = scenario.keys.database().clone();
    let user = scenario.keys.user_id;
    let address = reachable(&database, user).await;
    let before = scenario.keys.login().await;

    let token = scenario.recover().await;
    assert!(scenario.keys.session(&before).await.is_none(), "signed out");
    assert_eq!(sent(&database, user, address).await, 1, "the link");
    let (status, account) = scenario.check(&token).await;
    assert_eq!(status, StatusCode::OK);
    let username = database.users().find_by_id(user).await.expect("user");
    assert_eq!(account["username"], username.expect("user").username);
    let cookie = scenario.enroll(&token).await;

    let session = scenario.keys.session(&cookie).await.expect("signed in");
    let recovered = database.sessions().passkey(session.id).await;
    let recovered = recovered
        .expect("passkey")
        .expect("signed in with a passkey");
    assert_eq!(scenario.passkeys().await.len(), 2);
    assert!(scenario.passkeys().await.contains(&recovered));
    assert_ne!(recovered, scenario.keys.key_id);
    assert!(scenario.keys.events().await.iter().any(|event| matches!(
        event,
        DomainEvent::RecoveryCompleted { passkey_id, .. } if *passkey_id == recovered
    )));
    assert_eq!(sent(&database, user, address).await, 2, "the notice");
    assert_eq!(scenario.check(&token).await.0, StatusCode::BAD_REQUEST);
    let response = scenario
        .send(
            Method::POST,
            routes::recovery::START,
            "",
            json!({ "token": token }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "used once");
}

/// A link stops working when a newer recovery replaces it, even mid-ceremony,
/// and when the owner undoes the recovery before using it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn replaced_or_undone_links_stop_working() {
    let mut scenario = Scenario::new().await;
    let replaced = scenario.recover().await;
    let (started, browser) = scenario.start(&replaced).await;
    let token = scenario.recover().await;

    let response = scenario.finish(&started, &browser).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(scenario.check(&replaced).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id]);
    assert_eq!(scenario.check(&token).await.0, StatusCode::OK);

    let older = scenario.keys.login().await;
    let pending = scenario.status(&older).await;
    assert_eq!(pending["completed_at"], Value::Null);
    assert_eq!(pending["can_undo"], true);
    assert_eq!(scenario.undo(&older).await, StatusCode::NO_CONTENT);
    assert_eq!(scenario.check(&token).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id]);
}

/// Only a session a passkey enrolled before the recovery signed in may undo it:
/// not one the recovered passkey or a social sign-in signed in. Undoing it
/// removes the recovered passkey and signs out every other session, and leaves
/// nothing to undo.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn only_an_older_passkey_undoes_a_recovery() {
    let mut scenario = Scenario::new().await;
    let database = scenario.keys.database().clone();
    let user = scenario.keys.user_id;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;
    let social = Browser::sign_in_with(&database, user, AuthenticationMethod::Federation).await;

    for refused in [&recovered, &social.cookie] {
        assert_eq!(scenario.status(refused).await["can_undo"], false);
        assert_eq!(scenario.undo(refused).await, StatusCode::FORBIDDEN);
    }
    assert_eq!(scenario.passkeys().await.len(), 2, "nothing undone");
    let older = scenario.keys.login().await;
    let view = scenario.status(&older).await;
    assert_eq!(view["can_undo"], true);
    let session = scenario.keys.session(&recovered).await.expect("session");
    let passkey = database.sessions().passkey(session.id).await;
    let passkey = passkey.expect("passkey").expect("recovered passkey");
    assert_eq!(view["passkey"]["id"], passkey.to_string());

    assert_eq!(scenario.undo(&older).await, StatusCode::NO_CONTENT);
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id]);
    assert!(scenario.keys.session(&recovered).await.is_none(), "ended");
    assert!(
        scenario.keys.session(&social.cookie).await.is_none(),
        "ended"
    );
    assert!(scenario.keys.session(&older).await.is_some(), "kept");
    let events = scenario.keys.events().await;
    assert!(events.contains(&DomainEvent::PasskeyRemoved {
        passkey_id: passkey
    }));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, DomainEvent::RecoveryUndone { .. }))
    );
    assert_eq!(scenario.status(&older).await, Value::Null);
    assert_eq!(scenario.undo(&older).await, StatusCode::NOT_FOUND);
}

/// Only an operator at the terminal sees a recovery's link, so an administrator
/// may recover only an account with a verified address, where the link goes.
/// Nobody recovers a disabled account.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_never_see_the_link() {
    let harness = Harness::new().await;
    let admin = operator(harness.admin().await, Utc::now());
    let user = harness.account().await.user_id;
    let service = AdminService::new(harness.database.clone());
    let links = links();
    let recover = async |operator: &Operator| {
        service
            .recover_account(operator, user, reason(), &links)
            .await
    };

    assert!(matches!(
        recover(&admin).await,
        Err(AdminError::RecoveryNeedsEmail)
    ));
    assert!(recover(&cli()).await.expect("terminal").is_some());
    let address = reachable(&harness.database, user).await;
    assert_eq!(recover(&admin).await.expect("administrator"), None);
    assert_eq!(sent(&harness.database, user, address).await, 1);
    service
        .disable_user(&cli(), user, reason())
        .await
        .expect("disable");
    assert!(matches!(
        recover(&cli()).await,
        Err(AdminError::RecoveryOfDisabledAccount)
    ));
}
