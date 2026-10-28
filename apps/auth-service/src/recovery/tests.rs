//! Database-backed recovery scenarios: what starting one does and refuses, what a
//! link enrolls, what a probation passkey can and cannot do, who may undo a
//! recovery and what undoing it takes back, and what nobody may remove meanwhile.

use super::*;
use crate::{
    AdminError, AdminService,
    account::Subject,
    admin::tests::{Harness, cli, operator},
    passkey::{VerifiedRecoveryUndo, tests::Fixture},
    security::{BrowserCookie, Credential, Session},
    tests::{
        Browser, recovery_links, recovery_reason, recovery_token, refresh_grant, register,
        registration, until_blocked, verified_address,
    },
};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use piquel_common::{
    AuthenticationMethod, ClientId, EmailId, Provider, TokenId,
    clients::ClientKind,
    events::{RecoveryRevocation, SignInFailure},
    protocol::claims::Acr,
};
use piquel_repository::{
    Database, InsertExternalIdentity, InsertUnverifiedEmail, SessionAuthentication, StoredSession,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

/// An error body's `code`.
async fn code(response: Response) -> Value {
    Fixture::json(response).await["code"].clone()
}

/// An account with a passkey, recovered by an operator at the terminal, and the
/// browsers that act on it.
struct Scenario {
    /// The account, its original passkey and the routes. Its authenticator is the
    /// one that signs.
    keys: Fixture,
    /// Derives the links.
    links: RecoveryLinks,
    /// The authenticator not signing now: the recovery's, or the original one
    /// while the recovery's signs ([`Self::swap`]).
    other: Option<WebauthnAuthenticator<SoftPasskey>>,
}

impl Scenario {
    /// An account with one passkey, not recovered yet.
    async fn new() -> Self {
        Self {
            keys: Fixture::new().await,
            links: recovery_links(),
            other: None,
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

    /// The support operations.
    fn admin(&self) -> AdminService {
        AdminService::new(self.database().clone(), true)
    }

    /// Starts recovering the account as an operator at the terminal, with
    /// `revoke`, and returns the link it prints.
    async fn start(&self, revoke: Option<Revoke>) -> Result<Url, AdminError> {
        let link = self
            .admin()
            .recover_account(&cli(), self.user(), recovery_reason(), &self.links, revoke)
            .await?;
        Ok(link.expect("the terminal sees the link"))
    }

    /// Recovers the account as an operator at the terminal, and returns the
    /// link's token.
    async fn recover(&self) -> String {
        recovery_token(&self.start(None).await.expect("recovery"))
    }

    /// Whether the link holding `token` still works, as its page reads it.
    async fn works(&self, token: &str) -> bool {
        let service = AccountService::new(self.database().clone());
        service.open_recovery(token).await.is_ok()
    }

    /// Enrolls a passkey with `token` from the browser holding `cookies`, keeping
    /// its authenticator as [`Self::other`]. Returns the finish response.
    async fn enroll_from(&mut self, token: &str, cookies: &str) -> Response {
        let body = json!({ "token": token });
        let (started, browser) = self
            .keys
            .start(routes::recovery::START, cookies, body)
            .await;
        let (credential, authenticator) = self.keys.new_authenticator(&started);
        self.other = Some(authenticator);
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": credential,
            "friendly_name": "Recovered",
        });
        let cookies = format!("{cookies}; {browser}");
        self.keys
            .request(routes::recovery::FINISH, Method::POST, &cookies, body)
            .await
    }

    /// Enrolls a passkey with `token` from a browser with no session, and returns
    /// the session cookie it signs in with.
    async fn enroll(&mut self, token: &str) -> String {
        let response = self.enroll_from(token, "").await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Fixture::cookie(&response)
    }

    /// Signs with the other authenticator from now on: the recovery's after
    /// [`Self::enroll`], then the original one again.
    fn swap(&mut self) {
        let other = self.other.take().expect("another authenticator");
        self.other = Some(self.keys.replace_authenticator(other));
    }

    /// Signs in with the signing authenticator from the browser holding
    /// `session`. Returns the finish response.
    async fn login(&mut self, session: &str) -> Response {
        let body = json!({ "handle": self.keys.username });
        let (started, browser) = self
            .keys
            .start("/webauthn/authenticate/start", "", body)
            .await;
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": self.keys.assertion(&started),
        });
        let cookies = format!("{session}; {browser}");
        self.keys
            .request(
                "/webauthn/authenticate/finish",
                Method::POST,
                &cookies,
                body,
            )
            .await
    }

    /// Confirms the session of the browser holding `cookie` with the signing
    /// authenticator. Returns the finish response.
    async fn confirm(&mut self, cookie: &str) -> Response {
        let (started, browser) = self
            .keys
            .start("/account/passkeys/confirm/start", cookie, json!({}))
            .await;
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": self.keys.assertion(&started),
        });
        let cookies = format!("{cookie}; {browser}");
        self.keys
            .request(
                "/account/passkeys/confirm/finish",
                Method::POST,
                &cookies,
                body,
            )
            .await
    }

    /// The account's recovery that can still be undone, as the browser holding
    /// `cookie` sees it.
    async fn status(&self, cookie: &str) -> Value {
        let response = self
            .keys
            .request(routes::recovery::STATUS, Method::GET, cookie, Value::Null)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        Fixture::json(response).await
    }

    /// The account's latest recovery.
    async fn latest(&self) -> StoredRecovery {
        let latest = self.database().recoveries().latest(self.user()).await;
        latest.expect("lookup").expect("a recovery")
    }

    /// Starts undoing recovery `id` from a browser with no session. Returns the
    /// refusal, or the challenge and the browser's ceremony cookie.
    async fn undo_start(&self, id: RecoveryId) -> Result<(Value, String), StatusCode> {
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

    /// Undoes recovery `id` with the signing authenticator, from a browser with
    /// no session. Returns the status, the body, and the session cookie it signs
    /// in with, if any.
    async fn undo(&mut self, id: RecoveryId) -> (StatusCode, Value, Option<String>) {
        let (started, browser) = match self.undo_start(id).await {
            Ok(started) => started,
            Err(status) => return (status, Value::Null, None),
        };
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": self.keys.assertion(&started),
        });
        let response = self
            .keys
            .request(routes::recovery::UNDO_FINISH, Method::POST, &browser, body)
            .await;
        let status = response.status();
        let cookie = response
            .headers()
            .contains_key(axum::http::header::SET_COOKIE)
            .then(|| Fixture::cookie(&response));
        (status, Fixture::json(response).await, cookie)
    }

    /// Removes `passkey` from the browser holding `cookie`.
    async fn remove(&self, cookie: &str, passkey: PasskeyId) -> Response {
        let path = routes::passkey::ITEM.replace("{id}", &passkey.to_string());
        self.keys
            .request(&path, Method::DELETE, cookie, Value::Null)
            .await
    }

    /// Signs a browser in with `passkey`, which confirms its session, and returns
    /// its session cookie.
    async fn signed_in_with(&self, passkey: PasskeyId) -> String {
        let mut tx = self.database().begin().await.expect("transaction");
        let credential = Credential::Passkey(passkey);
        let secret = Session::create(&mut tx, RequestContext::TEST, self.user(), credential).await;
        tx.commit().await.expect("commit");
        let secret = secret.expect("session").encoded();
        format!("{}={secret}", BrowserCookie::Session.as_str())
    }

    /// The live session of the browser holding `cookie`, if any.
    async fn session(&self, cookie: &str) -> Option<StoredSession> {
        self.keys.session(cookie).await
    }

    /// Registers a client at `origin` and records the account's consent to it.
    async fn consent(&self, origin: &str) -> ClientId {
        let client = registration(ClientKind::Public, origin);
        register(self.database(), &client).await.expect("client");
        let scopes = ["openid".to_owned()];
        self.database()
            .oidc()
            .save_consent(self.user(), &client.id, client.id.as_str(), &scopes)
            .await
            .expect("consent");
        client.id
    }

    /// The clients the account consented to.
    async fn consents(&self) -> Vec<String> {
        let consents = self.database().oidc().list_consents(self.user()).await;
        let consents = consents.expect("consents").into_iter();
        consents.map(|consent| consent.client_id).collect()
    }

    /// The account's active passkeys.
    async fn passkeys(&self) -> HashSet<PasskeyId> {
        let passkeys = self.database().passkeys().list_active(self.user()).await;
        let passkeys = passkeys.expect("passkeys").into_iter();
        passkeys.map(|passkey| passkey.id).collect()
    }

    /// The providers of the account's linked identities.
    async fn identities(&self) -> Vec<Provider> {
        let identities = self.database().federation().list_active(self.user()).await;
        let identities = identities.expect("identities").into_iter();
        identities.map(|identity| identity.provider).collect()
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

    /// Adds a verified address named `name`, primary if `is_primary`.
    async fn address(&self, name: &str, is_primary: bool) -> EmailId {
        let address = format!("{name}-{}@example.com", self.user());
        verified_address(self.database(), self.user(), &address, is_primary).await
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

    /// How many messages were queued to the account's address `email`.
    async fn sent(&self, email: EmailId) -> usize {
        let destination = format!("account {}, address {email}", self.user());
        self.database()
            .deliveries()
            .list(None, Some("email"), 1000)
            .await
            .expect("deliveries")
            .iter()
            .filter(|delivery| delivery.destination == destination)
            .count()
    }

    /// The kinds of the messages queued to the account's address `email`, oldest
    /// first, with whether a `--revoke` start's notice says a passkey was kept.
    async fn messages(&self, email: EmailId) -> Vec<(String, Option<bool>)> {
        let destination = format!("account {}, address {email}", self.user());
        let payloads = self.database().deliveries().payloads(&destination).await;
        let payloads = payloads.expect("payloads").into_iter();
        payloads
            .map(|payload| {
                let kind = payload["type"].as_str().expect("type").to_owned();
                (kind, payload["kept"].as_bool())
            })
            .collect()
    }

    /// The account's events, newest first.
    async fn events(&self) -> Vec<DomainEvent> {
        self.keys.events().await
    }
}

/// Starting a recovery signs the account out everywhere, ends its refresh grants
/// and removes its unverified addresses, so an older verification link stops
/// working. Its link goes to the primary address only. The link enrolls one
/// passkey, once, and signs in with it without confirming the session: no
/// confirmed change accepts it, and confirming with it is refused until the
/// recovery settles. Every verified address hears of it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_link_enrolls_one_passkey_that_signs_in_without_confirming() {
    let mut scenario = Scenario::new().await;
    let primary = scenario.address("primary", true).await;
    let other = scenario.address("other", false).await;
    let (pending, _) = scenario.unverified("pending").await;
    let before = scenario.signed_in_with(scenario.keys.key_id).await;
    let before_id = scenario.session(&before).await.expect("session").id;
    let client = scenario.consent("https://notes.example").await;
    let family = TokenId::new();
    refresh_grant(
        scenario.database(),
        scenario.user(),
        before_id,
        &client,
        family,
    )
    .await;

    let token = scenario.recover().await;
    assert!(scenario.session(&before).await.is_none(), "signed out");
    let mut tokens = scenario.database().tokens();
    let grants = tokens.revoke_for_user(scenario.user(), None).await;
    assert_eq!(grants.expect("grants"), 0, "already ended");
    let emails = scenario.database().emails().list(scenario.user()).await;
    let emails: Vec<_> = emails
        .expect("emails")
        .iter()
        .map(|email| email.id)
        .collect();
    assert!(!emails.contains(&pending), "the unverified address is gone");
    assert_eq!(
        (scenario.sent(primary).await, scenario.sent(other).await),
        (1, 0),
        "the link goes to the primary address only"
    );
    assert!(scenario.works(&token).await);
    let service = AccountService::new(scenario.database().clone());
    let opened = service.open_recovery(&token).await.expect("open");
    let account = opened.account();
    assert_eq!(
        account.handle.as_str(),
        scenario.keys.username,
        "names the account"
    );

    let cookie = scenario.enroll(&token).await;
    let session = scenario.session(&cookie).await.expect("session");
    assert_eq!(session.passkey_confirmed_at, None, "not confirmed");
    assert_eq!(SessionAuthentication::from(&session).acr, Acr::Social);
    let recovered = scenario.latest().await.passkey_id.expect("its passkey");
    let signed_by = scenario.database().sessions().passkey(session.id).await;
    assert_eq!(signed_by.expect("passkey"), Some(recovered));
    assert_eq!(
        (scenario.sent(primary).await, scenario.sent(other).await),
        (2, 1),
        "every verified address hears of it"
    );
    assert!(!scenario.works(&token).await, "used");

    let response = scenario
        .keys
        .request(
            "/account/passkeys/enroll/start",
            Method::POST,
            &cookie,
            json!({}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(code(response).await, "step_up_required");
    scenario.swap();
    let response = scenario.confirm(&cookie).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(code(response).await, "recovery_probation");
    let session = scenario.session(&cookie).await.expect("session");
    assert_eq!(session.passkey_confirmed_at, None, "still not confirmed");

    // The probation lasts 15 days: a minute before, still refused; after, it
    // settled.
    let recovery = scenario.latest().await.id;
    let database = scenario.database().clone();
    let almost = Duration::days(15) - Duration::minutes(1);
    database
        .recoveries()
        .backdate_completion(recovery, almost)
        .await
        .expect("backdate");
    let response = scenario.confirm(&cookie).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "a minute before");
    database
        .recoveries()
        .backdate_completion(recovery, Duration::minutes(2))
        .await
        .expect("settle");
    let response = scenario.confirm(&cookie).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "once settled");
}

/// A link enrolls one passkey even when two of its ceremonies started before
/// either finished: the second finish fails, stores no passkey, and leaves the
/// recovery bound to the first, which stays in probation.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_link_enrolls_once_however_many_ceremonies_started() {
    let scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let body = json!({ "token": token });
    let mut started = Vec::new();
    for _ in 0..2 {
        let start = scenario
            .keys
            .start(routes::recovery::START, "", body.clone())
            .await;
        started.push(start);
    }
    let finish = async |(started, browser): &(Value, String)| {
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": scenario.keys.credential(started),
            "friendly_name": "Recovered",
        });
        scenario
            .keys
            .request(routes::recovery::FINISH, Method::POST, browser, body)
            .await
    };
    let first = finish(&started[0]).await;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    let bound = scenario.latest().await.passkey_id;
    let second = finish(&started[1]).await;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    assert_eq!(code(second).await, "invalid_link");
    assert_eq!(scenario.passkeys().await.len(), 2, "no second passkey");
    assert_eq!(scenario.latest().await.passkey_id, bound, "still the first");
}

/// A link signs its browser in with a new session, whatever session the browser
/// had. A probation passkey signing in again renews an unconfirmed session,
/// recording itself and its method without confirming it, and never downgrades a
/// confirmed one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_probation_passkey_signs_in_anew_and_never_confirms() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let social = Browser::sign_in_with(
        scenario.database(),
        scenario.user(),
        AuthenticationMethod::Federation,
    )
    .await;
    let response = scenario.enroll_from(&token, &social.cookie).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = Fixture::cookie(&response);
    let session = scenario.session(&cookie).await.expect("session");
    assert_ne!(session.id, social.session_id, "a new session");
    let social_session = scenario
        .database()
        .sessions()
        .find_by_id(social.session_id)
        .await;
    let revoked = social_session.expect("lookup").expect("session").revoked_at;
    assert!(revoked.is_some(), "the browser's session is revoked");
    let recovered = scenario.latest().await.passkey_id.expect("its passkey");
    scenario.swap();

    let social = Browser::sign_in_with(
        scenario.database(),
        scenario.user(),
        AuthenticationMethod::Federation,
    )
    .await;
    let response = scenario.login(&social.cookie).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let renewed = Fixture::cookie(&response);
    let session = scenario.session(&renewed).await.expect("session");
    assert_eq!(session.id, social.session_id, "renewed");
    assert_eq!(session.passkey_confirmed_at, None, "not confirmed");
    assert_eq!(
        session.authentication_methods,
        [
            AuthenticationMethod::Federation,
            AuthenticationMethod::Passkey
        ]
    );
    let signed_by = scenario.database().sessions().passkey(session.id).await;
    assert_eq!(signed_by.expect("passkey"), Some(recovered));

    let confirmed = scenario.signed_in_with(scenario.keys.key_id).await;
    let response = scenario.login(&confirmed).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = Fixture::json(response).await;
    assert_eq!(body["code"], "passkey_required");
    let says = body["error"].as_str().expect("message");
    assert!(says.ends_with("Sign out first."), "{says}");
    let session = scenario.session(&confirmed).await.expect("session");
    assert!(session.passkey_confirmed_at.is_some(), "not downgraded");

    // A link used in a browser an older passkey confirmed still signs in anew.
    let token = {
        scenario.swap();
        let undoable = scenario.latest().await.id;
        let (status, ..) = scenario.undo(undoable).await;
        assert_eq!(status, StatusCode::OK);
        scenario.recover().await
    };
    let confirmed = scenario.signed_in_with(scenario.keys.key_id).await;
    let response = scenario.enroll_from(&token, &confirmed).await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "from a confirmed browser"
    );
}

/// Undoing a recovery in probation, with a passkey from before it and no
/// session, takes back what whoever used its link could keep: its passkey, every
/// session and refresh grant, and every consent, old and new. It signs the
/// undoing browser in, and leaves nothing to undo.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undo_takes_back_the_passkey_sessions_grants_and_consents() {
    let mut scenario = Scenario::new().await;
    scenario.consent("https://notes.example").await;
    let token = scenario.recover().await;
    let cookie = scenario.enroll(&token).await;
    let recovery = scenario.latest().await;
    let recovered = recovery.passkey_id.expect("its passkey");
    let probation_session = scenario.session(&cookie).await.expect("session").id;
    let client = scenario.consent("https://photos.example").await;
    let family = TokenId::new();
    refresh_grant(
        scenario.database(),
        scenario.user(),
        probation_session,
        &client,
        family,
    )
    .await;

    let status = scenario.status(&cookie).await;
    assert_eq!(status["state"], "probation");
    assert_eq!(status["passkey"]["id"], json!(recovered));
    let undo_with: Vec<_> = status["undo_with"]
        .as_array()
        .expect("undo_with")
        .iter()
        .map(|passkey| passkey["id"].clone())
        .collect();
    assert_eq!(undo_with, [json!(scenario.keys.key_id)]);

    let (status, body, signed_in) = scenario.undo(recovery.id).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": true }))
    );
    assert_eq!(
        scenario.passkeys().await,
        HashSet::from([scenario.keys.key_id])
    );
    assert!(scenario.consents().await.is_empty(), "every consent");
    assert!(scenario.session(&cookie).await.is_none(), "signed out");
    let mut tokens = scenario.database().tokens();
    let grants = tokens.revoke_for_user(scenario.user(), None).await;
    assert_eq!(grants.expect("grants"), 0, "already revoked");
    let events = scenario.events().await;
    assert!(events.contains(&DomainEvent::PasskeyRemoved {
        passkey_id: recovered
    }));
    assert!(events.contains(&DomainEvent::RecoveryUndone {
        recovery_id: recovery.id
    }));
    let signed_in = signed_in.expect("signed in");
    assert_eq!(
        scenario.status(&signed_in).await,
        Value::Null,
        "nothing left"
    );
}

/// An undo and a client's deletion lock the account's refresh families before
/// its consents, so they never deadlock. Here a transaction locks the client's
/// families, as a deletion does first, while the undo waits for them, then
/// deletes the client and its consents: the undo must not be holding them yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_undo_and_a_client_deletion_never_deadlock() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let cookie = scenario.enroll(&token).await;
    let session = scenario.session(&cookie).await.expect("session").id;
    let client = scenario.consent("https://photos.example").await;
    let (database, user) = (scenario.database(), scenario.user());
    refresh_grant(database, user, session, &client, TokenId::new()).await;

    let mut holder = database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_client_families(&client)
        .await
        .expect("hold the client's families");
    let undo = tokio::spawn({
        let admin = scenario.admin();
        async move { admin.undo_recovery(&cli(), user, recovery_reason()).await }
    });
    until_blocked(&mut holder, 1).await;
    holder
        .oidc()
        .delete_client(&client)
        .await
        .expect("the undo holds no consent yet");
    holder.commit().await.expect("commit");
    undo.await
        .expect("task")
        .expect("the undo follows the deletion");
    assert!(scenario.consents().await.is_empty(), "every consent");
}

/// The pages read the account's recovery that can still be undone by its owner's
/// session, or by its ID alone, a disabled account's too: its stage, the passkey
/// its link enrolled, by ID and enrollment time only, and whether a passkey from
/// before it can undo it. Neither finds one that settled, nor an unknown one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pages_read_an_undoable_recovery_by_session_or_id() {
    let mut scenario = Scenario::new().await;
    let service = AccountService::new(scenario.database().clone());
    let token = scenario.recover().await;
    let owner = Browser::sign_in(scenario.database(), scenario.user())
        .await
        .owner(scenario.database())
        .await;
    let read = async |id: RecoveryId| {
        let by_session = service
            .recovery_notice(&(&owner).into())
            .await
            .expect("by session");
        let by_id = service.undoable_recovery(id).await.expect("by ID");
        assert_eq!(by_session, by_id, "the same either way");
        by_id
    };
    let recovery = scenario.latest().await;
    let open = RecoveryNotice {
        id: recovery.id,
        started_at: recovery.started_at,
        stage: RecoveryStage::Open {
            expires_at: recovery.expires_at,
        },
        undoable: true,
    };
    assert_eq!(read(recovery.id).await, Some(open));

    scenario.enroll(&token).await;
    let recovery = scenario.latest().await;
    let passkey = recovery.passkey_id.expect("its passkey");
    let passkeys = scenario
        .database()
        .passkeys()
        .list_active(scenario.user())
        .await;
    let created_at = passkeys
        .expect("passkeys")
        .into_iter()
        .find(|stored| stored.id == passkey)
        .expect("active")
        .created_at;
    let probation = RecoveryNotice {
        stage: RecoveryStage::Probation {
            completed_at: recovery.completed_at.expect("completed"),
            settles_at: recovery.settles_at.expect("in probation"),
            passkey: Some(EnrolledPasskey {
                id: passkey,
                created_at,
            }),
        },
        ..open
    };
    assert_eq!(read(recovery.id).await, Some(probation));
    let disabled = scenario
        .database()
        .users()
        .set_status(scenario.user(), AccountStatus::Disabled)
        .await;
    assert!(disabled.expect("disable"));
    assert_eq!(
        service.undoable_recovery(recovery.id).await.expect("by ID"),
        Some(probation),
        "disabled"
    );

    let unknown = service.undoable_recovery(RecoveryId::new()).await;
    assert_eq!(unknown.expect("by ID"), None, "unknown");
    let mut recoveries = scenario.database().recoveries();
    recoveries
        .backdate_completion(recovery.id, PROBATION)
        .await
        .expect("settle");
    assert_eq!(read(recovery.id).await, None, "settled");
}

/// Only a passkey other than the recovery's own undoes it: the undo challenges
/// every other active one, a passkey enrolled during the probation by a session
/// an older passkey confirmed included, never the recovery's own, which the undo
/// refuses again under the lock. It finds nothing to undo once the recovery
/// settled, or for an unknown recovery.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn only_another_passkey_undoes_a_recovery() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    scenario.enroll(&token).await;
    let recovery = scenario.latest().await;
    let recovered = recovery.passkey_id.expect("its passkey");

    let mut tx = scenario.database().begin().await.expect("transaction");
    let undo = VerifiedRecoveryUndo::unverified(scenario.user(), recovery.id, recovered);
    let refused = AccountService::undo_recovery(&mut tx, RequestContext::TEST, &undo).await;
    assert!(
        matches!(
            refused,
            Err(AccountError::Recovery(RecoveryError::OlderPasskeyRequired))
        ),
        "the recovery's own passkey"
    );
    drop(tx);

    let confirmed = scenario.signed_in_with(scenario.keys.key_id).await;
    let (started, browser) = scenario
        .keys
        .start("/account/passkeys/enroll/start", &confirmed, json!({}))
        .await;
    let body = json!({
        "ceremony_id": started["ceremony_id"],
        "credential": scenario.keys.credential(&started),
        "friendly_name": "Added during probation",
    });
    let cookies = format!("{confirmed}; {browser}");
    let response = scenario
        .keys
        .request(
            "/account/passkeys/enroll/finish",
            Method::POST,
            &cookies,
            body,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let (started, _) = scenario.undo_start(recovery.id).await.expect("undo");
    let allowed = started["public_key"]["publicKey"]["allowCredentials"]
        .as_array()
        .map(Vec::len);
    assert_eq!(allowed, Some(2), "every passkey but the recovery's");
    assert_eq!(scenario.passkeys().await.len(), 3);

    let (status, ..) = scenario.undo(RecoveryId::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown");
    let mut recoveries = scenario.database().recoveries();
    recoveries
        .backdate_completion(recovery.id, PROBATION)
        .await
        .expect("settle");
    let (status, ..) = scenario.undo(recovery.id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "settled");
}

/// Undoing a recovery whose link was not used only cancels the link: nobody got
/// in with it, so sessions and consents stay. An undo applies only to the
/// recovery its ceremony named.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn undoing_an_unused_link_only_cancels_it() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let elsewhere = scenario.signed_in_with(scenario.keys.key_id).await;
    scenario.consent("https://notes.example").await;

    let recovery = scenario.latest().await;
    let (status, body, _) = scenario.undo(recovery.id).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": true }))
    );
    assert!(!scenario.works(&token).await, "cancelled");
    assert!(
        scenario.session(&elsewhere).await.is_some(),
        "still signed in"
    );
    assert_eq!(scenario.consents().await.len(), 1, "consent kept");

    // An undo started for a recovery that a newer one replaced before it
    // finished undoes nothing: the proof names the recovery it was started for.
    scenario.recover().await;
    let replaced = scenario.latest().await.id;
    let (started, browser) = scenario.undo_start(replaced).await.expect("undo");
    let token = scenario.recover().await;
    let body = json!({
        "ceremony_id": started["ceremony_id"],
        "credential": scenario.keys.assertion(&started),
    });
    let response = scenario
        .keys
        .request(routes::recovery::UNDO_FINISH, Method::POST, &browser, body)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "replaced meanwhile"
    );
    assert!(scenario.works(&token).await, "the newer one stands");
}

/// The owner undoes a recovery of a disabled account, so asking support to
/// disable it cannot outlast the undo: it signs nobody in, and the account stays
/// disabled, refusing a sign-in started before it was disabled. Once enabled, the
/// older passkey signs in.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_owner_undoes_a_disabled_accounts_recovery() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    scenario.enroll(&token).await;
    let recovery = scenario.latest().await.id;
    // A sign-in started before the account is disabled.
    let body = json!({ "handle": scenario.keys.username });
    let login = scenario
        .keys
        .start("/webauthn/authenticate/start", "", body)
        .await;
    // Written as a release older than this one would, which knows nothing of
    // recoveries.
    let disabled = scenario
        .database()
        .users()
        .set_status(scenario.user(), AccountStatus::Disabled)
        .await;
    assert!(disabled.expect("disable"));

    let (status, body, cookie) = scenario.undo(recovery).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": false }))
    );
    assert!(cookie.is_none(), "nobody signed in");
    assert_eq!(
        scenario.passkeys().await,
        HashSet::from([scenario.keys.key_id])
    );
    let user = scenario
        .database()
        .users()
        .find_by_id(scenario.user())
        .await;
    let status = user.expect("lookup").expect("user").status;
    assert_eq!(status, AccountStatus::Disabled, "still disabled");
    let (started, browser) = login;
    let body = json!({
        "ceremony_id": started["ceremony_id"],
        "credential": scenario.keys.assertion(&started),
    });
    let response = scenario
        .keys
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            body,
        )
        .await;
    assert!(response.status().is_client_error(), "sign-in refused");
    let cookie = response.headers().get(axum::http::header::SET_COOKIE);
    assert!(cookie.is_none(), "no session");
    let refused = DomainEvent::SignInFailed {
        method: AuthenticationMethod::Passkey,
        reason: SignInFailure::AccountUnavailable,
    };
    assert!(scenario.events().await.contains(&refused), "recorded");

    scenario
        .admin()
        .enable_user(&cli(), scenario.user())
        .await
        .expect("enable");
    let response = scenario.login("").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "once enabled");
}

/// Support undoes a recovery for an owner with no passkey left from before it,
/// and takes back its passkey even when it is the account's last; support then
/// starts another recovery. The listing shows the undone one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn support_undoes_and_takes_the_last_passkey() {
    let mut scenario = Scenario::new().await;
    let address = scenario.address("address", true).await;
    let link = scenario
        .start(Some(Revoke::default()))
        .await
        .expect("recovery");
    let notice = ("recovery_revoked".to_owned(), Some(false));
    assert_eq!(scenario.messages(address).await, [notice], "nothing kept");
    scenario.enroll(&recovery_token(&link)).await;
    assert_eq!(scenario.passkeys().await.len(), 1, "only the recovery's");
    let recovery = scenario.latest().await.id;

    scenario
        .admin()
        .undo_recovery(&cli(), scenario.user(), recovery_reason())
        .await
        .expect("support undoes");
    assert!(scenario.passkeys().await.is_empty(), "the last one too");
    let recent = scenario
        .admin()
        .recent_recoveries(&cli(), scenario.user())
        .await;
    let recent = recent.expect("recent");
    assert_eq!(recent[0].id, recovery);
    assert_eq!(recent[0].state, RecoveryState::Ended);
    assert!(recent[0].undone_at.is_some(), "listed as undone");
    scenario.recover().await;
}

/// A recovery started with `--revoke` takes back every way in but the kept
/// passkeys, in its own transaction: every other passkey, every identity and
/// every consent. Its link is only printed, and every verified address hears of
/// it at once. A kept passkey can still cancel it. A kept passkey the account
/// does not have fails the whole start.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoke_takes_back_every_way_in_but_the_kept_passkeys() {
    let mut scenario = Scenario::new().await;
    let stolen = scenario.keys.key_id;
    let primary = scenario.address("primary", true).await;
    let other = scenario.address("other", false).await;
    // The owner's other passkey, which signs from now on.
    let kept = scenario.keys.switch_passkey("Kept").await;
    scenario.link(Provider::GitHub).await;
    scenario.consent("https://notes.example").await;
    // A link already sent does not stand in the way.
    scenario.recover().await;

    let unknown = Revoke {
        keep: vec![PasskeyId::new()],
    };
    let refused = scenario.start(Some(unknown)).await;
    assert!(matches!(refused, Err(AdminError::UnknownPasskey(_))));
    assert_eq!(scenario.passkeys().await, HashSet::from([kept, stolen]));

    let (primary_before, other_before) = (scenario.sent(primary).await, scenario.sent(other).await);
    scenario
        .start(Some(Revoke { keep: vec![kept] }))
        .await
        .expect("recovery");
    assert_eq!(scenario.passkeys().await, HashSet::from([kept]));
    assert!(
        scenario.identities().await.is_empty(),
        "identities unlinked"
    );
    assert!(scenario.consents().await.is_empty(), "consents withdrawn");
    let recovery = scenario.latest().await.id;
    let started = scenario
        .events()
        .await
        .into_iter()
        .find_map(|event| match event {
            DomainEvent::RecoveryStarted {
                recovery_id,
                revoke,
                ..
            } if recovery_id == recovery => Some(revoke),
            _ => None,
        });
    let revocation = RecoveryRevocation {
        revoked: vec![stolen],
        kept: vec![kept],
    };
    assert_eq!(started, Some(Some(revocation)), "recorded on the start");
    assert_eq!(
        (
            scenario.sent(primary).await - primary_before,
            scenario.sent(other).await - other_before,
        ),
        (1, 1),
        "a notice to every verified address, and no link"
    );
    let notice = ("recovery_revoked".to_owned(), Some(true));
    assert_eq!(scenario.messages(other).await.last(), Some(&notice), "kept");

    let (status, body, _) = scenario.undo(recovery).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, json!({ "signed_in": true }))
    );
    let cancelled = scenario.database().recoveries().find(recovery).await;
    let cancelled = cancelled.expect("lookup").expect("recovery").cancelled_at;
    assert!(cancelled.is_some(), "the kept passkey cancelled it");
}

/// While a recovery can be undone, nobody removes a passkey but the recovery's
/// own: not the owner from a session an older passkey confirmed, not support.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn nothing_removes_an_older_passkey_mid_recovery() {
    let mut scenario = Scenario::new().await;
    let older = scenario.keys.key_id;
    let other = scenario.keys.switch_passkey("Other key").await;
    let token = scenario.recover().await;
    let confirmed = scenario.signed_in_with(older).await;

    let response = scenario.remove(&confirmed, other).await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "while the link works"
    );
    assert_eq!(code(response).await, "recovery_in_progress");
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let subject = Subject::operator(
        scenario.user(),
        operator(admin, Utc::now()),
        recovery_reason(),
    );
    let service = AccountService::new(scenario.database().clone());
    let refused = service.revoke_passkey(&subject, other).await;
    assert!(
        matches!(
            refused,
            Err(AccountError::Recovery(RecoveryError::InProgress))
        ),
        "support either"
    );

    scenario.enroll(&token).await;
    let recovered = scenario.latest().await.passkey_id.expect("its passkey");
    let response = scenario.remove(&confirmed, older).await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "during the probation"
    );
    let response = scenario.remove(&confirmed, recovered).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "its own may go");
}

/// A start is refused while a recovery is in probation, for a disabled account,
/// and for an administrator; it replaces an unused link, expired or not. Only an
/// operator at the terminal starts one that would not be mailed. Disabling an
/// account cancels its unused link.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn what_a_start_replaces_and_refuses() {
    let mut scenario = Scenario::new().await;
    let first = scenario.recover().await;
    let second = scenario.recover().await;
    assert!(!scenario.works(&first).await, "replaced");
    assert!(scenario.works(&second).await);
    let expired = scenario.latest().await.id;
    let mut recoveries = scenario.database().recoveries();
    recoveries.expire(expired).await.expect("expire");
    let third = scenario.recover().await;
    scenario.enroll(&third).await;
    let refused = scenario.start(None).await;
    assert!(matches!(refused, Err(AdminError::RecoveryInProbation)));

    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let admin_id = admin.user_id;
    let administrator = operator(admin, Utc::now());
    let account = harness.account().await.user_id;
    let service = AdminService::new(harness.database.clone(), true);
    let links = recovery_links();
    let unmailed = service
        .recover_account(&administrator, account, recovery_reason(), &links, None)
        .await;
    assert!(
        matches!(unmailed, Err(AdminError::RecoveryNeedsEmail)),
        "no address"
    );
    let address = format!("{account}@example.com");
    verified_address(&harness.database, account, &address, true).await;
    let revoked = service
        .recover_account(
            &administrator,
            account,
            recovery_reason(),
            &links,
            Some(Revoke::default()),
        )
        .await;
    assert!(
        matches!(revoked, Err(AdminError::RecoveryNeedsEmail)),
        "printed only"
    );
    let mailed = service
        .recover_account(&administrator, account, recovery_reason(), &links, None)
        .await;
    assert_eq!(
        mailed.expect("mailed"),
        None,
        "an administrator never sees it"
    );
    let to_admin = service
        .recover_account(&cli(), admin_id, recovery_reason(), &links, None)
        .await;
    assert!(matches!(to_admin, Err(AdminError::RecoveryOfAdministrator)));

    let link = service
        .recover_account(&cli(), account, recovery_reason(), &links, None)
        .await
        .expect("recovery")
        .expect("link");
    service
        .disable_user(&cli(), account, recovery_reason())
        .await
        .expect("disable");
    let disabled = service
        .recover_account(&cli(), account, recovery_reason(), &links, None)
        .await;
    assert!(matches!(
        disabled,
        Err(AdminError::RecoveryOfDisabledAccount)
    ));
    service.enable_user(&cli(), account).await.expect("enable");
    let accounts = AccountService::new(harness.database.clone());
    let opened = accounts.open_recovery(&recovery_token(&link)).await;
    assert!(
        opened.is_err(),
        "disabling cancelled it, so enabling does not revive it"
    );
}

/// While email is disabled, a recovery whose link would only be mailed is
/// refused before anything changes: the account keeps its session, and nothing
/// starts. The terminal, which prints its link, still recovers it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn no_recovery_starts_while_email_is_disabled() {
    let harness = Harness::new().await;
    let administrator = operator(harness.admin().await, Utc::now());
    let owner = harness.account().await;
    let account = owner.user_id;
    let address = format!("{account}@example.com");
    verified_address(&harness.database, account, &address, true).await;
    let service = AdminService::new(harness.database.clone(), false);
    let links = recovery_links();
    let refused = service
        .recover_account(&administrator, account, recovery_reason(), &links, None)
        .await;
    assert!(matches!(refused, Err(AdminError::RecoveryNeedsEmail)));
    let session = harness
        .database
        .sessions()
        .find_by_id(owner.session_id)
        .await
        .expect("lookup")
        .expect("session");
    assert!(session.revoked_at.is_none(), "still signed in");
    let recent = service
        .recent_recoveries(&cli(), account)
        .await
        .expect("recoveries");
    assert!(recent.is_empty(), "nothing started");
    let printed = service
        .recover_account(&cli(), account, recovery_reason(), &links, None)
        .await
        .expect("recovery");
    assert!(printed.is_some(), "the terminal prints its link");
}
