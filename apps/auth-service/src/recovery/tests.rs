//! Database-backed recovery scenarios: what a link enrolls, what stops it, who
//! sees it, who may undo a recovery, what undoing it takes back, what it
//! protects meanwhile, and when it settles.

use super::*;
use crate::{
    AdminError, AdminService, Operator, Reason,
    account::Subject,
    admin::tests::{Harness, assert_refused, cli, operator},
    passkey::tests::Fixture,
    security::{BrowserCookie, Credential, Session},
    tests::{AUTH_ORIGIN, Browser, register, registration, verified_address},
};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use piquel_common::events::Actor;
use piquel_common::{
    AuthenticationMethod, ClientId, EmailId, PasskeyId, Provider, TokenId, clients::ClientKind,
};
use piquel_repository::{Database, InsertExternalIdentity, InsertUnverifiedEmail, StoredEvent};
use serde_json::{Value, json};
use std::collections::HashSet;

/// Links with a key of their own: the routes find a recovery by its token's
/// digest, so they need no key.
fn links() -> RecoveryLinks {
    RecoveryLinks::new(
        AUTH_ORIGIN.parse().expect("origin"),
        Secret::generate().expect("recovery key"),
        None,
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

    /// Recovers the account as an operator at the terminal, even while another
    /// recovery can be undone, as the scenarios' repeated recoveries need, and
    /// returns the link's token.
    async fn recover(&self) -> String {
        let link = AdminService::new(self.database().clone())
            .recover_account(
                &cli(),
                self.user(),
                reason(),
                &self.links,
                WhileUndoable::Proceed,
            )
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

    /// Starts undoing recovery `id` from a browser with no session. Returns the
    /// refusal, or the challenge and the browser's ceremony cookie.
    async fn undo_start(&self, id: &Value) -> Result<(Value, String), StatusCode> {
        let body = json!({ "recovery_id": id });
        let response = self
            .keys
            .request(routes::recovery::UNDO_START, Method::POST, "", body)
            .await;
        if response.status() != StatusCode::OK {
            return Err(response.status());
        }
        let browser = Fixture::cookie(&response);
        Ok((Fixture::json(response).await, browser))
    }

    /// Answers the `started` undo with the fixture's passkey from the browser
    /// holding `browser`.
    async fn undo_finish(&mut self, started: &Value, browser: &str) -> Response {
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": self.keys.assertion(started),
        });
        self.keys
            .request(routes::recovery::UNDO_FINISH, Method::POST, browser, body)
            .await
    }

    /// Undoes recovery `id` with the fixture's passkey, from a browser with no
    /// session. Returns the status, and the session cookie it signs in with.
    async fn undo(&mut self, id: &Value) -> (StatusCode, Option<String>) {
        let (started, browser) = match self.undo_start(id).await {
            Ok(started) => started,
            Err(status) => return (status, None),
        };
        let response = self.undo_finish(&started, &browser).await;
        let signed_in =
            (response.status() == StatusCode::NO_CONTENT).then(|| Fixture::cookie(&response));
        (response.status(), signed_in)
    }

    /// Sends `method` to `path` from the browser holding `cookie`.
    async fn call(&self, method: Method, path: &str, cookie: &str) -> StatusCode {
        let response = self.keys.request(path, method, cookie, Value::Null).await;
        response.status()
    }

    /// Removes `passkey` from the browser holding `cookie`.
    async fn remove(&self, cookie: &str, passkey: PasskeyId) -> StatusCode {
        let path = routes::passkey::ITEM.replace("{id}", &passkey.to_string());
        self.call(Method::DELETE, &path, cookie).await
    }

    /// Signs a browser in with `passkey`, as its sign-in would, and returns its
    /// session cookie.
    async fn signed_in_with(&self, passkey: PasskeyId) -> String {
        let mut tx = self.database().begin().await.expect("transaction");
        let credential = Credential::Passkey(passkey);
        let secret = Session::create(&mut tx, RequestContext::TEST, self.user(), credential).await;
        tx.commit().await.expect("commit");
        let secret = secret.expect("session").encoded();
        format!("{}={secret}", BrowserCookie::Session.as_str())
    }

    /// Registers a client and records the account's consent to it, and returns
    /// the client.
    async fn consent(&self) -> ClientId {
        let client = registration(ClientKind::Public, "https://notes.example");
        register(self.database(), &client).await.expect("client");
        let scopes = ["openid".to_owned()];
        self.database()
            .oidc()
            .save_consent(self.user(), &client.id, client.id.as_str(), &scopes)
            .await
            .expect("consent");
        client.id
    }

    /// Extends the account's consent to `client`, as approving it again does.
    async fn extend(&self, client: &ClientId) {
        let scopes = ["openid".to_owned(), "email".to_owned()];
        self.database()
            .oidc()
            .save_consent(self.user(), client, client.as_str(), &scopes)
            .await
            .expect("consent");
    }

    /// The clients the account consented to.
    async fn consents(&self) -> Vec<String> {
        let consents = self.database().oidc().list_consents(self.user()).await;
        let consents = consents.expect("consents").into_iter();
        consents.map(|consent| consent.client_id).collect()
    }

    /// The account's newest undoable recovery, as the database has it.
    async fn newest(&self) -> RecoveryId {
        let settled_before = Utc::now() - SETTLE_WINDOW;
        let mut recoveries = self.database().recoveries();
        let undoable = recoveries.undoable(self.user(), settled_before).await;
        undoable.expect("undoable")[0].id
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

    /// Adds an unverified address named `name`, and returns it and its
    /// verification token.
    async fn unverified(&self, name: &str) -> (EmailId, Secret) {
        let id = EmailId::new();
        let token = Secret::generate().expect("token");
        let address = format!("{name}-{}@example.com", self.user());
        self.database()
            .emails()
            .insert_unverified(&InsertUnverifiedEmail {
                id,
                user_id: self.user(),
                normalized_email: &address,
                secret_digest: token.digest().as_bytes(),
                expires_at: Utc::now() + Duration::hours(1),
            })
            .await
            .expect("unverified address");
        (id, token)
    }

    /// Verifies the address waiting for `token`, as its link does.
    async fn verify(&self, token: &Secret) {
        let digest = token.digest();
        let mut tx = self.database().begin().await.expect("transaction");
        let pending = tx.emails().find_verification(digest.as_bytes()).await;
        let pending = pending.expect("lookup").expect("pending");
        tx.emails()
            .consume_verification(&pending, digest.as_bytes())
            .await
            .expect("verify");
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
    let expires_at: DateTime<Utc> =
        serde_json::from_value(account["expires_at"].clone()).expect("expiry");
    let lifetime = expires_at - Utc::now();
    assert!(lifetime <= LINK_LIFETIME && lifetime > LINK_LIFETIME - Duration::minutes(1));
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
/// disabled, even once it is enabled again. An undo names the newest recovery:
/// a replaced one answers `409`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn replaced_undone_or_disabled_links_stop_working() {
    let mut scenario = Scenario::new().await;
    let replaced = scenario.recover().await;
    let replaced_id = json!(scenario.newest().await);
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
    assert_eq!(scenario.undo(&replaced_id).await.0, StatusCode::CONFLICT);

    let signed_in = scenario.keys.login().await;
    let pending = scenario.status(&signed_in).await;
    assert_eq!(pending["completed_at"], Value::Null);
    let undo_with = &pending["undo_with"];
    assert_eq!(undo_with[0]["id"], scenario.keys.key_id.to_string());
    assert_eq!(
        scenario.undo(&pending["id"]).await.0,
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

/// Only a passkey from before the recovery undoes it: not the recovered one,
/// whose session may still read what undoing would take back. Undoing is its own
/// ceremony: it removes the recovered passkey, ends every session, signs the
/// undoing browser in with its passkey, and leaves nothing to undo.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn only_an_older_passkey_undoes_a_recovery() {
    let mut scenario = Scenario::new().await;
    let database = scenario.database().clone();
    scenario.address("primary", true).await;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;
    let social =
        Browser::sign_in_with(&database, scenario.user(), AuthenticationMethod::Federation).await;
    let passkey = scenario.passkey(&recovered).await;

    for cookie in [&recovered, &social.cookie] {
        let view = scenario.status(cookie).await;
        assert_eq!(view["undo_with"].as_array().map(Vec::len), Some(1));
        assert_eq!(view["undo_with"][0]["id"], scenario.keys.key_id.to_string());
    }
    let view = scenario.status(&recovered).await;
    assert_eq!(view["rollback"]["passkeys"][0]["id"], passkey.to_string());
    assert_eq!(view["rollback"]["primary"], Value::Null, "unchanged");
    let id: RecoveryId = serde_json::from_value(view["id"].clone()).expect("id");
    let mut tx = database.begin().await.expect("transaction");
    let refused =
        AccountService::undo_recovery(&mut tx, RequestContext::TEST, scenario.user(), id, passkey)
            .await;
    assert!(matches!(
        refused,
        Err(AccountError::Recovery(RecoveryError::OlderPasskeyRequired))
    ));
    drop(tx);
    assert_eq!(scenario.passkeys().await.len(), 2, "nothing undone");

    let (status, signed_in) = scenario.undo(&view["id"]).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id].into());
    for ended in [&recovered, &social.cookie] {
        assert!(scenario.keys.session(ended).await.is_none(), "ended");
    }
    let signed_in = signed_in.expect("signed in");
    assert_eq!(scenario.passkey(&signed_in).await, scenario.keys.key_id);
    let events = scenario.keys.events().await;
    assert!(events.contains(&DomainEvent::PasskeyRemoved {
        passkey_id: passkey
    }));
    assert!(events.contains(&DomainEvent::RecoveryUndone { recovery_id: id }));
    let primary = |event: &DomainEvent| matches!(event, DomainEvent::PrimaryEmailChanged { .. });
    assert!(!events.iter().any(primary), "the primary stays");
    assert_eq!(scenario.status(&signed_in).await, Value::Null);
    assert_eq!(scenario.undo(&view["id"]).await.0, StatusCode::NOT_FOUND);
}

/// The undo needs no session, so signing the owner out cannot stop it: every
/// session ending between its start and its finish changes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undo_needs_no_session() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;
    let id = json!(scenario.newest().await);

    let (started, browser) = scenario.undo_start(&id).await.expect("started");
    AdminService::new(scenario.database().clone())
        .revoke_user_sessions(&cli(), scenario.user())
        .await
        .expect("every session ends");
    let response = scenario.undo_finish(&started, &browser).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(scenario.keys.session(&recovered).await.is_none());
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id].into());
}

/// While a recovery can be undone, a session that does not predate it cannot
/// remove the passkeys, identities or addresses the account had before it. A
/// session such a passkey signed in can, and so can an operator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn what_predates_a_recovery_is_protected() {
    let mut scenario = Scenario::new().await;
    let older = scenario.keys.key_id;
    let other = scenario.keys.switch_passkey("Other key").await;
    scenario.link(Provider::GitHub).await;
    let first = scenario.address("primary", true).await;
    let address = scenario.address("secondary", false).await;
    let another = scenario.address("another", false).await;
    let (prior, verified_since) = scenario.unverified("prior").await;
    let (unverified, _) = scenario.unverified("unverified").await;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;
    scenario.verify(&verified_since).await;
    let identity = routes::federation::IDENTITY.replace("{provider}", "github");
    let email = routes::emails::ITEM.replace("{id}", &address.to_string());
    let primary = routes::emails::PRIMARY.replace("{id}", &another.to_string());

    assert_eq!(
        scenario.remove(&recovered, older).await,
        StatusCode::FORBIDDEN
    );
    let unlink = scenario.call(Method::DELETE, &identity, &recovered).await;
    assert_eq!(unlink, StatusCode::FORBIDDEN);
    let removed = scenario.call(Method::DELETE, &email, &recovered).await;
    assert_eq!(removed, StatusCode::FORBIDDEN);
    let pending = routes::emails::ITEM.replace("{id}", &unverified.to_string());
    let removed = scenario.call(Method::DELETE, &pending, &recovered).await;
    assert_eq!(
        removed,
        StatusCode::FORBIDDEN,
        "unverified, but from before"
    );
    let moved = scenario.call(Method::POST, &primary, &recovered).await;
    assert_eq!(moved, StatusCode::FORBIDDEN, "the primary stays");
    assert!(scenario.passkeys().await.contains(&older), "kept");
    assert_eq!(scenario.identities().await, [Provider::GitHub]);
    // Verified only since, so it is undo's to take back, not protected.
    let since = routes::emails::ITEM.replace("{id}", &prior.to_string());
    let removed = scenario.call(Method::DELETE, &since, &recovered).await;
    assert_eq!(removed, StatusCode::NO_CONTENT);
    assert_eq!(scenario.emails().await.len(), 4);

    let signed_in = scenario.signed_in_with(other).await;
    let unlink = scenario.call(Method::DELETE, &identity, &signed_in).await;
    assert_eq!(unlink, StatusCode::NO_CONTENT);
    let signed_in = scenario.signed_in_with(other).await;
    let removed = scenario.call(Method::DELETE, &email, &signed_in).await;
    assert_eq!(removed, StatusCode::NO_CONTENT);
    let signed_in = scenario.signed_in_with(other).await;
    assert_eq!(
        scenario.remove(&signed_in, older).await,
        StatusCode::NO_CONTENT
    );
    let signed_in = scenario.signed_in_with(other).await;
    let moved = scenario.call(Method::POST, &primary, &signed_in).await;
    assert_eq!(moved, StatusCode::NO_CONTENT);
    let subject = Subject::operator(scenario.user(), cli(), reason());
    let service = AccountService::new(scenario.database().clone());
    service
        .make_primary_email(&subject, first)
        .await
        .expect("an operator moves it");
    service
        .revoke_passkey(&subject, other)
        .await
        .expect("an operator removes it");
}

/// With two recoveries to undo, only what predates both is trusted. Whoever used
/// the first cannot, once a second started, remove what the account had before
/// the first, nor undo the second with the first one's passkey. The owner
/// undoes the second, then the first.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_second_recovery_trusts_only_what_predates_both() {
    let mut scenario = Scenario::new().await;
    let older = scenario.keys.key_id;
    let first = scenario.recover().await;
    let first_session = scenario.enroll(&first).await;
    let first_passkey = scenario.passkey(&first_session).await;
    scenario.recover().await;
    let attacker = scenario.signed_in_with(first_passkey).await;

    assert_eq!(
        scenario.remove(&attacker, older).await,
        StatusCode::FORBIDDEN
    );
    let view = scenario.status(&attacker).await;
    assert_eq!(view["undo_with"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["undo_with"][0]["id"], older.to_string());
    let id: RecoveryId = serde_json::from_value(view["id"].clone()).expect("id");
    let mut tx = scenario.database().begin().await.expect("transaction");
    let user = scenario.user();
    let refused =
        AccountService::undo_recovery(&mut tx, RequestContext::TEST, user, id, first_passkey).await;
    assert!(matches!(
        refused,
        Err(AccountError::Recovery(RecoveryError::OlderPasskeyRequired))
    ));
    drop(tx);
    let service = AdminService::new(scenario.database().clone());
    let recent = service
        .recent_recoveries(&cli(), user)
        .await
        .expect("recent");
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].recovery.passkey, None, "the second is unused");
    let enrolled = recent[1]
        .recovery
        .passkey
        .as_ref()
        .expect("the first enrolled one");
    assert_eq!((enrolled.id, enrolled.active), (first_passkey, true));

    assert_eq!(scenario.undo(&view["id"]).await.0, StatusCode::NO_CONTENT);
    let (status, signed_in) = scenario.undo(&json!(scenario.newest().await)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(scenario.passkeys().await, [older].into());
    assert_eq!(
        scenario.status(&signed_in.expect("signed in")).await,
        Value::Null
    );
    let recent = service
        .recent_recoveries(&cli(), user)
        .await
        .expect("recent");
    let removed = recent[1]
        .recovery
        .passkey
        .as_ref()
        .expect("the first enrolled one");
    assert!(!removed.active, "removed by the undo");
}

/// A used recovery settles after [`SETTLE_WINDOW`]: until then it can be undone
/// and protects what the account had before it; after, it cannot, and its
/// passkey is an ordinary one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_used_recovery_settles_after_its_window() {
    let scenario = Scenario::new().await;
    let older = scenario.keys.key_id;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;
    let id = scenario.newest().await;
    let moment = Duration::minutes(1);
    let backdate = async |by| {
        let database = scenario.database();
        let backdated = database.recoveries().backdate_completion(id, by).await;
        backdated.expect("backdate");
    };

    let view = scenario.status(&recovered).await;
    let at = |key: &str| -> DateTime<Utc> { serde_json::from_value(view[key].clone()).expect(key) };
    assert_eq!(at("settles_at") - at("completed_at"), SETTLE_WINDOW);
    backdate(SETTLE_WINDOW - moment).await;
    let view = scenario.status(&recovered).await;
    assert_eq!(view["id"], id.to_string(), "still undoable");
    assert_eq!(
        scenario.remove(&recovered, older).await,
        StatusCode::FORBIDDEN
    );
    backdate(moment * 2).await;
    assert_eq!(scenario.status(&recovered).await, Value::Null, "settled");
    assert_eq!(
        scenario.remove(&recovered, older).await,
        StatusCode::NO_CONTENT
    );
}

/// An unused link protects what the account had before it only until it
/// expires; then there is nothing to undo.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_expired_link_neither_undoes_nor_protects() {
    let mut scenario = Scenario::new().await;
    let older = scenario.keys.key_id;
    scenario.recover().await;
    let id = scenario.newest().await;
    let newer = scenario.keys.switch_passkey("Newer key").await;
    let signed_in = scenario.signed_in_with(newer).await;

    assert_eq!(
        scenario.remove(&signed_in, older).await,
        StatusCode::FORBIDDEN
    );
    let expired = scenario.database().recoveries().expire(id).await;
    expired.expect("expire");
    assert_eq!(scenario.status(&signed_in).await, Value::Null);
    assert_eq!(
        scenario.remove(&signed_in, older).await,
        StatusCode::NO_CONTENT
    );
}

/// The recovered passkey's sign-in counts as a fresh confirmation, so the link's
/// holder can add ways in at once. Undoing takes back every passkey, identity,
/// consent and address added or verified since, restores the primary address,
/// and leaves everything from before untouched, recording each change as the
/// owner's. The undo page lists exactly that.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undo_takes_back_every_way_in_added_since() {
    let mut scenario = Scenario::new().await;
    let database = scenario.database().clone();
    let user = scenario.user();
    scenario.link(Provider::GitHub).await;
    let consented = scenario.consent().await;
    let extended = scenario.consent().await;
    // The recovery's primary address is not the oldest, which only a fallback
    // would choose.
    let secondary = scenario.address("secondary", true).await;
    let primary = scenario.address("primary", false).await;
    scenario.make_primary(primary, None).await;
    // Added before the recovery, but verified only after it.
    let (prior, verified_since) = scenario.unverified("prior").await;
    let token = scenario.recover().await;
    let recovered = scenario.enroll(&token).await;

    let response = scenario
        .register("/account/passkeys/enroll/start", &recovered, json!({}))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "confirmed");
    scenario.link(Provider::Google).await;
    let client = scenario.consent().await;
    scenario.extend(&extended).await;
    let added = scenario.address("added", false).await;
    scenario.make_primary(added, None).await;
    let (pending, _) = scenario.unverified("pending").await;
    scenario.verify(&verified_since).await;
    let since: HashSet<_> = &scenario.passkeys().await - &[scenario.keys.key_id].into();
    assert_eq!(since.len(), 2, "the recovered passkey and another");

    let view = scenario.status(&recovered).await;
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
    let consents = [client.to_string(), extended.to_string()].into();
    assert_eq!(ids(&rollback["consents"], "client_id"), consents);
    let emails = [added, pending, prior].map(|id| id.to_string()).into();
    assert_eq!(ids(&rollback["emails"], "id"), emails);
    assert_eq!(rollback["primary"]["id"], primary.to_string());

    assert_eq!(scenario.undo(&view["id"]).await.0, StatusCode::NO_CONTENT);
    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id].into());
    assert_eq!(scenario.identities().await, [Provider::GitHub]);
    assert_eq!(scenario.consents().await, [consented.to_string()]);
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
        DomainEvent::ConsentRevoked { client_id: client },
        DomainEvent::ConsentRevoked {
            client_id: extended,
        },
        DomainEvent::PrimaryEmailChanged {
            email_id: primary,
            previous_email_id: Some(added),
        },
        DomainEvent::EmailRemoved { email_id: added },
        DomainEvent::EmailRemoved { email_id: pending },
        DomainEvent::EmailRemoved { email_id: prior },
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

/// Whoever used a recovery's link, when the owner has no passkey from before it
/// left, cannot keep the account. They cannot move the primary address to their
/// own, so a new link would still go to the owner. Support cannot start another
/// recovery without seeing all they added, and undoes this one for the owner:
/// each change records the reason and sends the notice an owner's undo would.
/// The next recovery's link then goes to the owner's address.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn support_undoes_a_hijacked_recovery() {
    let scenario = Scenario::new().await;
    let database = scenario.database().clone();
    let user = scenario.user();
    let owners = scenario.address("owner", true).await;
    let token = scenario.recover().await;
    let attacker = scenario.enroll(&token).await;
    let spare = scenario
        .register("/account/passkeys/enroll/start", &attacker, json!({}))
        .await;
    assert_eq!(spare.status(), StatusCode::NO_CONTENT, "a spare passkey");
    scenario.link(Provider::GitHub).await;
    let theirs = scenario.address("theirs", false).await;
    let primary = routes::emails::PRIMARY.replace("{id}", &theirs.to_string());
    let moved = scenario.call(Method::POST, &primary, &attacker).await;
    assert_eq!(
        moved,
        StatusCode::FORBIDDEN,
        "the next link stays the owner's"
    );

    let service = AdminService::new(database.clone());
    let links = links();
    let refused = service
        .recover_account(&cli(), user, reason(), &links, WhileUndoable::Refuse)
        .await;
    assert!(matches!(refused, Err(AdminError::RecoveryUndoable)));
    let recent = service
        .recent_recoveries(&cli(), user)
        .await
        .expect("recent");
    let rollback = recent[0].rollback.as_ref().expect("still undoable");
    assert_eq!(
        rollback.passkeys.len(),
        2,
        "the link's passkey and the spare"
    );
    assert_eq!(rollback.identities.len(), 1);
    assert_eq!(rollback.emails.len(), 1);
    let told = sent(&database, user, theirs).await;
    let stale = service
        .undo_recovery(&cli(), user, RecoveryId::new(), reason())
        .await;
    assert!(matches!(stale, Err(AdminError::RecoveryChanged)));
    service
        .undo_recovery(&cli(), user, recent[0].recovery.id, reason())
        .await
        .expect("support undoes it");

    assert_eq!(scenario.passkeys().await, [scenario.keys.key_id].into());
    assert_eq!(scenario.identities().await, []);
    assert_eq!(scenario.emails().await, [(owners, true)]);
    assert!(
        scenario.keys.session(&attacker).await.is_none(),
        "signed out"
    );
    assert_eq!(
        sent(&database, user, theirs).await,
        told + 1,
        "its removal notice"
    );
    let history = database.events().history_for_user(user, 50).await;
    let history = history.expect("history");
    let kind = |event: &StoredEvent| match event.event.known()? {
        DomainEvent::RecoveryUndone { .. } => Some("undone"),
        DomainEvent::PasskeyRemoved { .. } => Some("passkey"),
        DomainEvent::IdentityUnlinked { .. } => Some("identity"),
        DomainEvent::EmailRemoved { .. } => Some("address"),
        DomainEvent::SessionRevoked { .. } => Some("session"),
        _ => None,
    };
    let mut kinds = HashSet::new();
    for event in &history {
        if let Some(kind) = kind(event) {
            assert_eq!(
                event.reason.as_deref(),
                Some("Lost every passkey"),
                "{kind}"
            );
            kinds.insert(kind);
        }
    }
    let expected = ["undone", "passkey", "identity", "address", "session"].into();
    assert_eq!(kinds, expected, "every change records the reason");
    let before = sent(&database, user, owners).await;
    service
        .recover_account(&cli(), user, reason(), &links, WhileUndoable::Refuse)
        .await
        .expect("nothing left to undo");
    assert_eq!(
        sent(&database, user, owners).await,
        before + 1,
        "to the owner"
    );
}

/// Support's undo takes back every passkey added since the recovery, even when
/// support removed the older ones meanwhile, as whoever used the link may have
/// asked: they keep none, and support starts a new recovery.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn support_takes_back_every_passkey_added_since() {
    let scenario = Scenario::new().await;
    let database = scenario.database().clone();
    let user = scenario.user();
    let token = scenario.recover().await;
    let attacker = scenario.enroll(&token).await;
    let spare = scenario
        .register("/account/passkeys/enroll/start", &attacker, json!({}))
        .await;
    assert_eq!(spare.status(), StatusCode::NO_CONTENT, "a spare passkey");
    let subject = Subject::operator(user, cli(), reason());
    AccountService::new(database.clone())
        .revoke_passkey(&subject, scenario.keys.key_id)
        .await
        .expect("support removes the older one");

    let id = scenario.newest().await;
    AdminService::new(database)
        .undo_recovery(&cli(), user, id, reason())
        .await
        .expect("support undoes it");
    assert_eq!(scenario.passkeys().await, HashSet::new(), "none left");
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
    let recovered = scenario.enroll(&token).await;
    let added = scenario.address("added", false).await;
    scenario.make_primary(added, Some(primary)).await;

    let view = scenario.status(&recovered).await;
    assert_eq!(view["rollback"]["primary"]["id"], oldest.to_string());
    assert_eq!(scenario.undo(&view["id"]).await.0, StatusCode::NO_CONTENT);
    assert_eq!(scenario.emails().await, [(oldest, true), (newer, false)]);
}

/// Only an operator at the terminal sees a recovery's link, so an administrator
/// may recover only an account with a primary address, where the link goes.
/// Nobody recovers a disabled account or an administrator's, nor starts another
/// recovery while one can be undone unless asked to. Support sees the recent
/// recoveries, and reading them checks the administrator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_never_see_the_link() {
    let harness = Harness::new().await;
    let admin = operator(harness.admin().await, Utc::now());
    let user = harness.account().await.user_id;
    let service = AdminService::new(harness.database.clone());
    let links = links();
    let recover = async |operator: &Operator| {
        let proceed = WhileUndoable::Proceed;
        service
            .recover_account(operator, user, reason(), &links, proceed)
            .await
    };

    assert!(matches!(
        recover(&admin).await,
        Err(AdminError::RecoveryNeedsEmail)
    ));
    assert!(recover(&cli()).await.expect("terminal").is_some());
    let refused = service
        .recover_account(&cli(), user, reason(), &links, WhileUndoable::Refuse)
        .await;
    assert!(matches!(refused, Err(AdminError::RecoveryUndoable)));
    let administrator = harness.admin().await.user_id;
    let refused = service
        .recover_account(
            &cli(),
            administrator,
            reason(),
            &links,
            WhileUndoable::Proceed,
        )
        .await;
    assert!(matches!(refused, Err(AdminError::RecoveryOfAdministrator)));
    let address = format!("{user}@example.com");
    let address = verified_address(&harness.database, user, &address, true).await;
    assert_eq!(recover(&admin).await.expect("administrator"), None);
    assert_eq!(sent(&harness.database, user, address).await, 1);
    let recent = service
        .recent_recoveries(&admin, user)
        .await
        .expect("recent");
    assert_eq!(recent.len(), 2);
    assert!(recent[1].recovery.cancelled_at.is_some(), "replaced");
    for (refused, expected) in harness.refused_readers().await {
        let read = service.recent_recoveries(&refused, user).await;
        assert_refused(&read.expect_err("refused"), &expected, "recent recoveries");
    }
    service
        .disable_user(&cli(), user, reason())
        .await
        .expect("disable");
    assert!(matches!(
        recover(&cli()).await,
        Err(AdminError::RecoveryOfDisabledAccount)
    ));
}
