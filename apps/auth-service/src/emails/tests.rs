//! Database-backed address scenarios: what needs a passkey confirmation, how a
//! verification link works, and what an address another account owns gets.

use super::*;
use crate::security::{BrowserCookie, Session, tests::assert_step_up_required};
use crate::{account::AccountApplication, tests::Replicas};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, header},
    response::Response,
};
use piquel_common::{AuthenticationMethod, Handle, config::PublicUrl};
use piquel_repository::{DeliverySummary, InsertUser};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv6Addr};
use tower::ServiceExt;

/// Largest response body the scenarios read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A scenario account with one signed-in browser.
struct Account {
    /// The account.
    user_id: UserId,
    /// The browser's session cookie pair.
    cookie: String,
}

/// The address routes over the test database, as requests from one client IP of
/// their own, so no other test shares its verification limit.
struct Harness {
    /// Routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
    /// Settings, with the verification key.
    config: EmailConfig,
    /// Every request's context.
    context: RequestContext,
}

impl Harness {
    /// Builds the routes over a migrated test database, sending email or not.
    async fn new(enabled: bool) -> Self {
        let database = Replicas::database().await;
        let settings: PublicUrl = "https://piquel.fr/settings".parse().expect("settings URL");
        let config = EmailConfig::test(&settings, enabled);
        Self {
            router: EmailApplication::new(database.clone(), &config)
                .routes()
                .merge(AccountApplication::new(database.clone()).routes()),
            database,
            config,
            context: RequestContext::from_ip(IpAddr::V6(Ipv6Addr::from(
                UserId::new().as_uuid().as_u128(),
            ))),
        }
    }

    /// Creates an account and signs a browser in to it with `method`. Only a
    /// passkey sign-in confirms the session.
    async fn account(&self, method: AuthenticationMethod) -> Account {
        let user_id = UserId::new();
        self.database
            .users()
            .insert(&InsertUser {
                id: user_id,
                handle: Handle::parse(&format!("email-{}", &user_id.to_string()[24..]))
                    .expect("handle"),
                display_name: "Email test".into(),
            })
            .await
            .expect("user");
        let mut tx = self.database.begin().await.expect("transaction");
        let secret = Session::create(&mut tx, self.context, user_id, method)
            .await
            .expect("session");
        tx.commit().await.expect("commit");
        Account {
            user_id,
            cookie: format!("{}={}", BrowserCookie::Session.as_str(), secret.encoded()),
        }
    }

    /// Sends a request, as `account`'s browser if any.
    async fn send(
        &self,
        account: Option<&Account>,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Response {
        let mut request = Request::builder()
            .extension(self.context)
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(account) = account {
            request = request.header(header::COOKIE, &account.cookie);
        }
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        self.router
            .clone()
            .oneshot(request.body(body).expect("request"))
            .await
            .expect("response")
    }

    /// Sends a request and returns its status and JSON body.
    async fn call(
        &self,
        account: Option<&Account>,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let response = self.send(account, method, path, body).await;
        let status = response.status();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .expect("body");
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// Adds `address` to `account`, returning the status and body.
    async fn add(&self, account: &Account, address: &str) -> (StatusCode, Value) {
        let body = json!({ "email": address });
        self.call(
            Some(account),
            Method::POST,
            routes::emails::LIST,
            Some(body),
        )
        .await
    }

    /// Adds `address` to `account` and returns its ID.
    async fn added(&self, account: &Account, address: &str) -> EmailId {
        let (status, body) = self.add(account, address).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().expect("id").parse().expect("email ID")
    }

    /// Presents the token of `id`'s verification link, signed out.
    async fn verify(&self, id: EmailId) -> (StatusCode, Value) {
        let token = self.config.verification_key.token(id).expect("token");
        self.verify_token(&token.encoded()).await
    }

    /// Presents `token`, signed out.
    async fn verify_token(&self, token: &str) -> (StatusCode, Value) {
        let body = json!({ "token": token });
        self.call(None, Method::POST, routes::emails::VERIFY, Some(body))
            .await
    }

    /// Makes `id` the primary address of `account`.
    async fn make_primary(&self, account: &Account, id: EmailId) -> (StatusCode, Value) {
        let path = routes::emails::PRIMARY.replace("{id}", &id.to_string());
        self.call(Some(account), Method::POST, &path, None).await
    }

    /// Removes `id` from `account`.
    async fn remove(&self, account: &Account, id: EmailId) -> (StatusCode, Value) {
        let path = routes::emails::ITEM.replace("{id}", &id.to_string());
        self.call(Some(account), Method::DELETE, &path, None).await
    }

    /// `account`'s addresses, as it lists them.
    async fn list(&self, account: &Account) -> Vec<Value> {
        let (status, body) = self
            .call(Some(account), Method::GET, routes::emails::LIST, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body.as_array().expect("addresses").clone()
    }

    /// The email deliveries queued for `account`.
    async fn deliveries(&self, account: &Account) -> Vec<DeliverySummary> {
        let destination = format!("account {}", account.user_id);
        self.database
            .deliveries()
            .list(None, Some("email"), 1000)
            .await
            .expect("deliveries")
            .into_iter()
            .filter(|delivery| delivery.destination.starts_with(&destination))
            .collect()
    }
}

/// Adding an address asks an unconfirmed session to confirm before anything
/// else, so the browser confirms first: even an invalid address, or one that
/// email is off for, answers `step_up_required`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn adding_asks_for_confirmation_first() {
    for enabled in [true, false] {
        let harness = Harness::new(enabled).await;
        let social = harness.account(AuthenticationMethod::Federation).await;
        let body = json!({ "email": "not an address" });
        assert_step_up_required(
            harness
                .send(
                    Some(&social),
                    Method::POST,
                    routes::emails::LIST,
                    Some(body),
                )
                .await,
        )
        .await;
    }
}

/// Adding, changing the primary address and removing need a passkey
/// confirmation; a link verifies its address once, without a session, and makes
/// the first one primary. A new primary address notifies the previous one, which
/// can then be removed; the primary one only once no other could replace it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn addresses_need_confirmation_and_links_verify_once() {
    let harness = Harness::new(true).await;
    let social = harness.account(AuthenticationMethod::Federation).await;
    let body = json!({ "email": "ada@example.com" });
    assert_step_up_required(
        harness
            .send(
                Some(&social),
                Method::POST,
                routes::emails::LIST,
                Some(body),
            )
            .await,
    )
    .await;

    let account = harness.account(AuthenticationMethod::Passkey).await;
    let (status, added) = harness.add(&account, "Ada@Example.COM").await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    assert_eq!(added["address"], "Ada@example.com");
    assert_eq!(added["verified"], false);
    let first: EmailId = added["id"].as_str().expect("id").parse().expect("ID");
    // The delivery names the account and the address's ID, never the address.
    let queued = harness.deliveries(&account).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued[0].destination,
        format!("account {}, address {first}", account.user_id)
    );

    let (status, _) = harness.verify_token("not-a-token").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, verified) = harness.verify(first).await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(
        verified,
        json!({ "address": "Ada@example.com", "primary": true })
    );
    let (status, _) = harness.verify(first).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a link works once");

    let second = harness.added(&account, "ada@example.org").await;
    let (status, verified) = harness.verify(second).await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(verified["primary"], false);
    let (status, _) = harness.make_primary(&account, second).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let listed = harness.list(&account).await;
    assert_eq!(listed[0]["id"], second.to_string());
    assert_eq!(listed[0]["primary"], true);
    assert!(
        harness
            .deliveries(&account)
            .await
            .iter()
            .any(
                |delivery| delivery.destination.ends_with(&format!("address {first}"))
                    && delivery.id != queued[0].id
            ),
        "the previous primary address is told"
    );

    let (status, _) = harness.remove(&account, second).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "another address could replace it"
    );
    let (status, _) = harness.remove(&account, first).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let to_first = harness
        .deliveries(&account)
        .await
        .into_iter()
        .filter(|delivery| delivery.destination.ends_with(&format!("address {first}")))
        .count();
    assert_eq!(
        to_first, 3,
        "its link, then notices of its replacement and removal"
    );
    let (status, _) = harness.remove(&account, second).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(harness.list(&account).await, Vec::<Value>::new());
    let kinds: Vec<_> = harness
        .database
        .events()
        .history_for_user(account.user_id, 20)
        .await
        .expect("history")
        .into_iter()
        .filter_map(|event| event.event.known()?.history_entry())
        .map(|entry| serde_json::to_value(entry).expect("entry")["kind"].clone())
        .collect();
    assert_eq!(
        kinds[..8],
        [
            "email.removed",
            "email.removed",
            "email.primary_changed",
            "email.verified",
            "email.added",
            "email.primary_changed",
            "email.verified",
            "email.added",
        ]
    );
}

/// An address another active account verified cannot be verified again. Adding it
/// succeeds, so adding reveals nothing; verifying answers `409` without naming
/// the owner, and the address stays unverified.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn verification_rejects_an_address_another_account_owns() {
    let harness = Harness::new(true).await;
    let owner = harness.account(AuthenticationMethod::Passkey).await;
    let other = harness.account(AuthenticationMethod::Passkey).await;
    let address = format!("{}@example.com", owner.user_id);
    let verified = harness.added(&owner, &address).await;
    assert_eq!(harness.verify(verified).await.0, StatusCode::OK);

    let claimed = harness.added(&other, &address).await;
    let (status, body) = harness.verify(claimed).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"],
        "This address is already used by another Piquel account."
    );
    assert_eq!(harness.list(&other).await[0]["verified"], false);
}

/// A verification link works signed out, and a browser signed in to the account
/// confirms it as the owner. A browser signed in to another account is refused,
/// and the link still works afterwards.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn verification_checks_the_signed_in_account() {
    let harness = Harness::new(true).await;
    let owner = harness.account(AuthenticationMethod::Passkey).await;
    let other = harness.account(AuthenticationMethod::Passkey).await;
    let verify = async |browser, id| {
        let token = harness.config.verification_key.token(id).expect("token");
        let body = json!({ "token": token.encoded() });
        harness
            .call(browser, Method::POST, routes::emails::VERIFY, Some(body))
            .await
    };

    let first = format!("{}-first@example.com", owner.user_id);
    let first = harness.added(&owner, &first).await;
    let (status, body) = verify(Some(&other), first).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"],
        "This link adds the address to a Piquel account other than the one you are signed in \
         to. Sign out first if you meant to confirm it."
    );
    assert_eq!(harness.list(&owner).await[0]["verified"], false);
    assert_eq!(verify(None, first).await.0, StatusCode::OK, "link kept");

    let second = format!("{}-second@example.com", owner.user_id);
    let second = harness.added(&owner, &second).await;
    assert_eq!(verify(Some(&owner), second).await.0, StatusCode::OK);
    let verified = harness
        .database
        .events()
        .history_for_user(owner.user_id, 1)
        .await
        .expect("history")
        .remove(0);
    assert_eq!(
        verified.event.known(),
        Some(&DomainEvent::EmailVerified { email_id: second })
    );
    assert!(
        matches!(verified.actor, Actor::User { user_id, .. } if user_id == owner.user_id),
        "{:?}",
        verified.actor
    );
}

/// An expired link verifies nothing. Adding a pending address again replaces it
/// with a new link. Each account may send five verification emails an hour, and
/// none while email is disabled.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn expired_links_replacements_and_limits() {
    let harness = Harness::new(true).await;
    let account = harness.account(AuthenticationMethod::Passkey).await;
    let expired = EmailId::new();
    let token = harness
        .config
        .verification_key
        .token(expired)
        .expect("token");
    harness
        .database
        .emails()
        .insert_unverified(&InsertUnverifiedEmail {
            id: expired,
            user_id: account.user_id,
            normalized_email: "late@example.com",
            secret_digest: token.digest().as_bytes(),
            expires_at: Utc::now() - Duration::seconds(1),
        })
        .await
        .expect("expired address");
    assert_eq!(harness.verify(expired).await.0, StatusCode::BAD_REQUEST);

    let first = harness.added(&account, "again@example.com").await;
    let second = harness.added(&account, "again@example.com").await;
    assert_ne!(first, second);
    assert_eq!(harness.verify(first).await.0, StatusCode::BAD_REQUEST);
    // Cleanup, which other tests run, may have deleted the expired address already.
    let addresses = harness.list(&account).await;
    assert!(
        addresses
            .iter()
            .any(|email| email["id"] == second.to_string())
    );

    for index in 0..3 {
        harness
            .added(&account, &format!("{index}@example.com"))
            .await;
    }
    let response = harness
        .send(
            Some(&account),
            Method::POST,
            routes::emails::LIST,
            Some(json!({ "email": "sixth@example.com" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "3600");

    let disabled = Harness::new(false).await;
    let account = disabled.account(AuthenticationMethod::Passkey).await;
    assert_eq!(
        disabled.add(&account, "ada@example.com").await.0,
        StatusCode::FORBIDDEN
    );
}
