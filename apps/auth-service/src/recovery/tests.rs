//! Database-backed recovery scenarios: what a link enrolls, what stops it, who
//! sees it, who may undo a recovery, and what undoing it takes back.

use super::*;
use crate::{
    AdminError, AdminService, Operator, Reason,
    account::Subject,
    admin::tests::{Harness, cli, operator},
    passkey::tests::Fixture,
    tests::{AUTH_ORIGIN, Browser, verified_address},
};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use piquel_common::events::Actor;
use piquel_common::{AuthenticationMethod, EmailId, PasskeyId, Provider, TokenId};
use piquel_repository::{Database, InsertExternalIdentity, InsertUnverifiedEmail};
use serde_json::{Value, json};
use std::collections::HashSet;

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

/// The token of a recovery `link`.
fn token(link: &Url) -> String {
    let fragment = link.fragment().expect("fragment");
    fragment.strip_prefix("token=").expect("token").to_owned()
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

    /// The scenario database.
    fn database(&self) -> &Database {
        self.keys.database()
    }

    /// The account.
    const fn user(&self) -> UserId {
        self.keys.user_id
    }

    /// Recovers the account as an operator at the terminal, and returns the
    /// link's token.
    async fn recover(&self) -> String {
        let link = AdminService::new(self.database().clone())
            .recover_account(&cli(), self.user(), reason(), &self.links)
            .await
            .expect("recovery")
            .expect("the terminal sees the link");
        token(&link)
    }

    /// Describes the account `token` recovers, as its page does on load.
    async fn check(&self, token: &str) -> (StatusCode, Value) {
        let body = json!({ "token": token });
        let response = self
            .keys
            .request(routes::recovery::CHECK, Method::POST, "", body)
            .await;
        (response.status(), Fixture::json(response).await)
    }

    /// Starts enrolling a passkey at `path` from the browser holding `cookies`,
    /// and finishes it with a new software passkey. Returns the finish response.
    async fn register(&self, path: &str, cookies: &str, body: Value) -> Response {
        let (started, browser) = self.keys.start(path, cookies, body).await;
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": self.keys.credential(&started),
            "friendly_name": "Added",
        });
        let finish = path.replace("start", "finish");
        let cookies = format!("{cookies}; {browser}");
        self.keys
            .request(&finish, Method::POST, &cookies, body)
            .await
    }

    /// Enrolls a passkey with `token`, and returns the session cookie it signs
    /// in with.
    async fn enroll(&self, token: &str) -> String {
        let body = json!({ "token": token });
        let response = self.register(routes::recovery::START, "", body).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Fixture::cookie(&response)
    }

    /// The newest recovery the browser holding `cookie` could undo.
    async fn status(&self, cookie: &str) -> Value {
        let response = self
            .keys
            .request(routes::recovery::STATUS, Method::GET, cookie, Value::Null)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        Fixture::json(response).await
    }

    /// Undoes recovery `id` from the browser holding `cookie`.
    async fn undo(&self, cookie: &str, id: &Value) -> StatusCode {
        let body = json!({ "recovery_id": id });
        let response = self
            .keys
            .request(routes::recovery::UNDO, Method::POST, cookie, body)
            .await;
        response.status()
    }

    /// The account's active passkeys.
    async fn passkeys(&self) -> HashSet<PasskeyId> {
        let passkeys = self.database().passkeys().list_active(self.user()).await;
        let passkeys = passkeys.expect("passkeys").into_iter();
        passkeys.map(|passkey| passkey.id).collect()
    }

    /// The passkey that signed in, or last confirmed, the browser holding
    /// `cookie`.
    async fn passkey(&self, cookie: &str) -> PasskeyId {
        let session = self.keys.session(cookie).await.expect("session");
        let passkey = self.database().sessions().passkey(session.id).await;
        passkey.expect("passkey").expect("a passkey session")
    }

    /// The providers of the account's linked identities.
    async fn identities(&self) -> Vec<Provider> {
        let identities = self.database().federation().list_active(self.user()).await;
        let identities = identities.expect("identities").into_iter();
        identities.map(|identity| identity.provider).collect()
    }

    /// The account's addresses, primary first, and whether each is primary.
    async fn emails(&self) -> Vec<(EmailId, bool)> {
        let emails = self.database().emails().list(self.user()).await;
        let emails = emails.expect("emails").into_iter();
        emails.map(|email| (email.id, email.is_primary)).collect()
    }

    /// Links an identity of `provider` to the account.
    async fn link(&self, provider: Provider) {
        self.database()
            .federation()
            .insert_identity(&InsertExternalIdentity {
                id: TokenId::new(),
                user_id: self.user(),
                provider,
                issuer: format!("https://{provider}.example"),
                subject: TokenId::new().to_string(),
                linked_email: None,
            })
            .await
            .expect("identity");
    }

    /// Makes `email` the primary address, then removes `removed`, if any, as
    /// settings do.
    async fn make_primary(&self, email: EmailId, removed: Option<EmailId>) {
        let mut tx = self.database().begin().await.expect("transaction");
        tx.emails()
            .set_primary(self.user(), email)
            .await
            .expect("primary");
        if let Some(removed) = removed {
            tx.emails()
                .remove(self.user(), removed)
                .await
                .expect("remove");
        }
        tx.commit().await.expect("commit");
    }

    /// Adds a verified address named `name`, primary if `is_primary`.
    async fn address(&self, name: &str, is_primary: bool) -> EmailId {
        let address = format!("{name}-{}@example.com", self.user());
        verified_address(self.database(), self.user(), &address, is_primary).await
    }
}

/// A recovery signs the account out everywhere and emails its link to the
/// primary address only. The link names the account, enrolls one passkey and
/// signs the browser in with it, then stops working; every verified address
/// hears of it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_link_enrolls_one_passkey_and_signs_in_with_it() {
    let mut scenario = Scenario::new().await;
    let database = scenario.database().clone();
    let user = scenario.user();
    let primary = scenario.address("primary", true).await;
    let secondary = scenario.address("secondary", false).await;
    let before = scenario.keys.login().await;

    let token = scenario.recover().await;
    assert!(scenario.keys.session(&before).await.is_none(), "signed out");
    assert_eq!(sent(&database, user, primary).await, 1, "the link");
    assert_eq!(sent(&database, user, secondary).await, 0, "no link");
    let (status, account) = scenario.check(&token).await;
    assert_eq!(status, StatusCode::OK);
    let stored = database.users().find_by_id(user).await.expect("user");
    let stored = stored.expect("user");
    assert_eq!(account["username"], stored.username);
    assert_eq!(account["display_name"], stored.display_name);
    assert!(account["expires_at"].is_string());
    let cookie = scenario.enroll(&token).await;

    let recovered = scenario.passkey(&cookie).await;
    let expected = HashSet::from([scenario.keys.key_id, recovered]);
    assert_eq!(scenario.passkeys().await, expected);
    assert!(scenario.keys.events().await.iter().any(|event| matches!(
        event,
        DomainEvent::RecoveryCompleted { passkey_id, .. } if *passkey_id == recovered
    )));
    assert_eq!(sent(&database, user, primary).await, 2, "and the notice");
    assert_eq!(sent(&database, user, secondary).await, 1, "the notice");
    assert_eq!(scenario.check(&token).await.0, StatusCode::BAD_REQUEST);
}

/// A link stops working when a newer recovery replaces it, even mid-ceremony,
/// when the owner undoes the recovery before using it, and when the account is
/// disabled, even once it is enabled again.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn replaced_undone_or_disabled_links_stop_working() {
    let mut scenario = Scenario::new().await;
    let replaced = scenario.recover().await;
    let body = json!({ "token": replaced });
    let (started, browser) = scenario.keys.start(routes::recovery::START, "", body).await;
    let token = scenario.recover().await;

    let body = json!({
        "ceremony_id": started["ceremony_id"],
        "credential": scenario.keys.credential(&started),
        "friendly_name": "Replaced",
    });
    let response = scenario
        .keys
        .request(routes::recovery::FINISH, Method::POST, &browser, body)
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(scenario.check(&replaced).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(scenario.passkeys().await.len(), 1);
    assert_eq!(scenario.check(&token).await.0, StatusCode::OK);

    let older = scenario.keys.login().await;
    let pending = scenario.status(&older).await;
    assert_eq!(pending["completed_at"], Value::Null);
    assert_eq!(pending["can_undo"], true);
    assert_eq!(
        scenario.undo(&older, &pending["id"]).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(scenario.check(&token).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(scenario.passkeys().await.len(), 1);

    let token = scenario.recover().await;
    let service = AdminService::new(scenario.database().clone());
    service
        .disable_user(&cli(), scenario.user(), reason())
        .await
        .expect("disable");
    service
        .enable_user(&cli(), scenario.user())
        .await
        .expect("enable");
    assert_eq!(scenario.check(&token).await.0, StatusCode::BAD_REQUEST);
}

/// Only a session a passkey enrolled before the recovery signed in may undo it:
/// not one the recovered passkey or a social sign-in signed in. Undoing names
/// the recovery its page showed, removes the recovered passkey and signs out
/// every other session, and leaves nothing to undo.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn only_an_older_passkey_undoes_a_recovery() {
    let mut scenario = Scenario::new().await;
    let database = scenario.database().clone();
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;
    let social =
        Browser::sign_in_with(&database, scenario.user(), AuthenticationMethod::Federation).await;

    for refused in [&recovered, &social.cookie] {
        let view = scenario.status(refused).await;
        assert_eq!(view["can_undo"], false);
        assert_eq!(
            scenario.undo(refused, &view["id"]).await,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(scenario.passkeys().await.len(), 2, "nothing undone");
    let older = scenario.keys.login().await;
    let view = scenario.status(&older).await;
    assert_eq!(view["can_undo"], true);
    let passkey = scenario.passkey(&recovered).await;
    let listed = &view["rollback"]["passkeys"];
    assert_eq!(listed[0]["id"], passkey.to_string());
    let other = json!(RecoveryId::new());
    assert_eq!(scenario.undo(&older, &other).await, StatusCode::CONFLICT);

    assert_eq!(
        scenario.undo(&older, &view["id"]).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id].into());
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
    assert_eq!(
        scenario.undo(&older, &view["id"]).await,
        StatusCode::NOT_FOUND
    );
}

/// Whoever used the link cannot remove the passkeys from before the recovery, so
/// it always stays possible to undo; an operator still can.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_link_cannot_remove_older_passkeys() {
    let scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;
    let older = scenario.keys.key_id;

    let path = routes::passkey::ITEM.replace("{id}", &older.to_string());
    let response = scenario
        .keys
        .request(&path, Method::DELETE, &recovered, Value::Null)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(scenario.passkeys().await.contains(&older), "kept");
    let subject = Subject::operator(scenario.user(), cli(), reason());
    let service = AccountService::new(scenario.database().clone());
    service
        .revoke_passkey(&subject, older)
        .await
        .expect("an operator removes it");
}

/// The recovered passkey's sign-in counts as a fresh confirmation, so the link's
/// holder can add ways in at once. Undoing takes back every passkey, identity and
/// address added since, restores the primary address, and leaves everything from
/// before untouched, recording each change as the owner's. The undo page lists
/// exactly that.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undo_takes_back_every_way_in_added_since() {
    let mut scenario = Scenario::new().await;
    let database = scenario.database().clone();
    let user = scenario.user();
    scenario.link(Provider::GitHub).await;
    // The recovery's primary address is not the oldest, which only a fallback
    // would choose.
    let secondary = scenario.address("secondary", true).await;
    let primary = scenario.address("primary", false).await;
    scenario.make_primary(primary, None).await;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;

    let response = scenario
        .register("/account/passkeys/enroll/start", &recovered, json!({}))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "confirmed");
    scenario.link(Provider::Google).await;
    let added = scenario.address("added", false).await;
    scenario.make_primary(added, None).await;
    let address = format!("pending-{user}@example.com");
    let pending = EmailId::new();
    database
        .emails()
        .insert_unverified(&InsertUnverifiedEmail {
            id: pending,
            user_id: user,
            normalized_email: &address,
            secret_digest: Secret::generate().expect("token").digest().as_bytes(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .expect("unverified address");
    let since: HashSet<_> = &scenario.passkeys().await - &[scenario.keys.key_id].into();
    assert_eq!(since.len(), 2, "the recovered passkey and another");

    let older = scenario.keys.login().await;
    let view = scenario.status(&older).await;
    let rollback = &view["rollback"];
    let ids = |list: &Value, key: &str| -> HashSet<String> {
        let list = list.as_array().expect("list").iter();
        list.map(|item| item[key].as_str().expect("string").to_owned())
            .collect()
    };
    let listed = since.iter().map(ToString::to_string).collect();
    assert_eq!(ids(&rollback["passkeys"], "id"), listed);
    assert_eq!(
        ids(&rollback["identities"], "provider"),
        ["google".into()].into()
    );
    let emails = [added.to_string(), pending.to_string()].into();
    assert_eq!(ids(&rollback["emails"], "id"), emails);
    assert_eq!(rollback["primary"]["id"], primary.to_string());

    assert_eq!(
        scenario.undo(&older, &view["id"]).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id].into());
    assert_eq!(scenario.identities().await, [Provider::GitHub]);
    assert_eq!(
        scenario.emails().await,
        [(primary, true), (secondary, false)]
    );
    let history = database.events().history_for_user(user, 50).await;
    let history = history.expect("history");
    let removed = since
        .into_iter()
        .map(|passkey_id| DomainEvent::PasskeyRemoved { passkey_id });
    let undone = removed.chain([
        DomainEvent::IdentityUnlinked {
            provider: Provider::Google,
        },
        DomainEvent::PrimaryEmailChanged {
            email_id: primary,
            previous_email_id: Some(added),
        },
        DomainEvent::EmailRemoved { email_id: added },
        DomainEvent::EmailRemoved { email_id: pending },
    ]);
    for event in undone {
        let recorded = history
            .iter()
            .find(|stored| stored.event.known() == Some(&event));
        let actor = recorded.map(|stored| &stored.actor);
        assert!(
            matches!(actor, Some(Actor::User { user_id, .. }) if *user_id == user),
            "{event:?} by the owner"
        );
    }
}

/// When the recovery's primary address is gone, undoing it makes the oldest
/// address verified before the recovery primary again, while it removes the one
/// that replaced it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undo_falls_back_to_the_oldest_address_left() {
    let mut scenario = Scenario::new().await;
    let primary = scenario.address("primary", true).await;
    let oldest = scenario.address("oldest", false).await;
    let newer = scenario.address("newer", false).await;
    let token = scenario.recover().await;
    scenario.enroll(&token).await;
    let added = scenario.address("added", false).await;
    scenario.make_primary(added, Some(primary)).await;

    let older = scenario.keys.login().await;
    let view = scenario.status(&older).await;
    assert_eq!(view["rollback"]["primary"]["id"], oldest.to_string());
    assert_eq!(
        scenario.undo(&older, &view["id"]).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(scenario.emails().await, [(oldest, true), (newer, false)]);
}

/// Only an operator at the terminal sees a recovery's link, so an administrator
/// may recover only an account with a primary address, where the link goes.
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
    let address = format!("{user}@example.com");
    let address = verified_address(&harness.database, user, &address, true).await;
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
