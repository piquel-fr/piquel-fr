//! Database-backed recovery scenarios: what starting one does and refuses, what a
//! link enrolls, what a probation passkey can and cannot do, who may undo a
//! recovery and what undoing it takes back, and what nobody may remove meanwhile.

use super::*;
use crate::{
    AdminError, AdminService,
    admin::tests::{Harness, cli, operator},
    passkey::tests::{Fixture, SoftKey},
    security::{BrowserCookie, Credential, Session},
    tests::{
        Browser, reason, recovery_links, recovery_reason, recovery_token, refresh_grant, register,
        registration, verified_address,
    },
};
use axum::{
    http::{Method, StatusCode},
    response::Response,
};
use serde_json::{Value, json};
use sourceorigin_common::{
    AuthenticationMethod, ClientId, EmailId, Provider, TokenId, clients::ClientKind,
};
use sourceorigin_repository::{
    Database, InsertExternalIdentity, InsertUnverifiedEmail, StoredSession,
};
use std::collections::HashSet;

mod enroll;
mod probation;
mod start;
mod undo;

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
    /// The key not signing now: the recovery's, or the original one
    /// while the recovery's signs ([`Self::swap`]).
    other: Option<SoftKey>,
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
        let (credential, key) = self.keys.new_key(&started);
        self.other = Some(key);
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
        let other = self.other.take().expect("another key");
        self.other = Some(self.keys.replace_key(other));
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
                // A notification's email is named by the notification's kind.
                let message = match payload.get("notification") {
                    Some(notification) => notification,
                    None => &payload,
                };
                let kind = message.get("kind").or_else(|| message.get("type"));
                let kind = kind.and_then(|kind| kind.as_str()).expect("kind");
                (kind.to_owned(), message["kept"].as_bool())
            })
            .collect()
    }

    /// The account's events, newest first.
    async fn events(&self) -> Vec<DomainEvent> {
        self.keys.events().await
    }
}
