//! Database-backed admin API scenarios: who may call it, and what each operation changes.

use super::*;
use crate::security::{RequestContext, Session};
use crate::tests::until_blocked;
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, header},
};
use chrono::{Duration, Utc};
use piquel_admin_api::{AUDIENCE, paths};
use piquel_common::{
    AccountStatus, AuthenticationMethod, Handle, HandleError, Personal,
    config::Origin,
    events::{DomainEvent, RevocationReason},
    protocol::{
        claims::{AccessTokenClaims, Acr, Audience, AuthenticationClaims, ProfileClaims},
        jwt::TokenType,
        oauth::Scopes,
    },
};
use piquel_crypto::Rs256Key;
use piquel_repository::{DatabaseConfig, InsertUser, SessionScope};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// Issuer of the scenario tokens.
const ISSUER: &str = "https://auth.piquel.fr";

/// A scenario account and its signed-in session.
#[derive(Clone, Copy)]
struct Account {
    /// The account.
    user_id: UserId,
    /// Its passkey session.
    session_id: SessionId,
}

/// The admin API on the test database, with the key its tokens are signed with.
struct Harness {
    /// Routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
    /// Signs scenario access tokens.
    keys: Arc<Rs256Key>,
}

impl Harness {
    /// Builds the admin API over a migrated test database.
    async fn new() -> Self {
        let url = piquel_common::config::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name a disposable PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("config"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        let keys = Arc::new(Rs256Key::generate("admin-tests").expect("signing key"));
        let application = AdminApplication {
            operations: AdminOperations::new(database.clone()),
            tokens: AdminTokens {
                keys: keys.clone(),
                issuer: ISSUER.into(),
                database: database.clone(),
            },
            origin: origin(),
            invitations: true,
        };
        Self {
            router: application.routes(),
            database,
            keys,
        }
    }

    /// Creates an account with the handle `handle`, without a session.
    async fn named(&self, handle: &str) -> UserId {
        let user_id = UserId::new();
        self.database
            .users()
            .insert(&InsertUser {
                id: user_id,
                handle: Handle::parse(handle).expect("handle"),
                display_name: "Admin test".into(),
            })
            .await
            .expect("user");
        user_id
    }

    /// Creates an account signed in with a passkey.
    async fn account(&self) -> Account {
        let suffix = TokenId::new().to_string();
        let user_id = self.named(&format!("admin-{}", &suffix[24..])).await;
        let mut tx = self.database.begin().await.expect("transaction");
        let secret = Session::create(
            &mut tx,
            RequestContext::TEST,
            user_id,
            AuthenticationMethod::Passkey,
        )
        .await
        .expect("session");
        let session_id = tx
            .sessions()
            .find_active_by_browser_secret(secret.digest().as_bytes())
            .await
            .expect("lookup")
            .expect("session")
            .id;
        tx.commit().await.expect("commit");
        Account {
            user_id,
            session_id,
        }
    }

    /// The operations behind the routes, to call without an extractor.
    fn operations(&self) -> AdminOperations {
        AdminOperations::new(self.database.clone())
    }

    /// Creates an administrator, granted by the CLI.
    async fn admin(&self) -> Account {
        let account = self.account().await;
        self.operations()
            .grant_administrator(&cli(), account.user_id)
            .await
            .expect("grant");
        account
    }

    /// An admin API token for `account`, signed in at `acr` `age` ago.
    fn token(&self, account: Account, acr: Acr, age: Duration) -> String {
        self.signed(account, AUDIENCE, acr, age)
    }

    /// A token for `account` and `audience`, signed in at `acr` `age` ago.
    fn signed(&self, account: Account, audience: &str, acr: Acr, age: Duration) -> String {
        let now = Utc::now();
        self.keys
            .sign(
                TokenType::Access,
                &AccessTokenClaims {
                    iss: ISSUER.into(),
                    sub: account.user_id.to_string(),
                    aud: Audience::One(audience.into()),
                    client_id: AUDIENCE.parse().expect("client ID"),
                    jti: TokenId::new(),
                    scope: Scopes::default(),
                    iat: now,
                    exp: now + Duration::minutes(5),
                    nbf: None,
                    authentication: AuthenticationClaims {
                        sid: Some(account.session_id),
                        auth_time: Some(now - age),
                        amr: vec![],
                        acr: Some(acr),
                    },
                    act: None,
                    cnf: None,
                    profile: ProfileClaims::default(),
                    extra: (),
                },
            )
            .expect("sign")
    }

    /// Sends a request with `token` as its bearer, and `body` as JSON.
    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        let request = request
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, 1 << 20).await.expect("body");
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON body")
        };
        (parts.status, parts.headers, json)
    }

    /// The kinds of the events concerning `user_id`, newest first.
    async fn events(&self, user_id: UserId) -> Vec<DomainEvent> {
        self.database
            .events()
            .history_for_user(user_id, 100)
            .await
            .expect("history")
            .into_iter()
            .map(|stored| stored.event.known().cloned().expect("a known event"))
            .collect()
    }
}

/// The operator of CLI-side changes.
fn cli() -> Operator {
    Operator::Cli {
        os_user: "tester".into(),
        host: "test".into(),
    }
}

/// Auth's origin, which invitations link to.
fn origin() -> Origin {
    ISSUER.parse().expect("origin")
}

/// The path of an account's route.
fn user_path(template: &str, user_id: UserId) -> String {
    template.replace("{user_id}", &user_id.to_string())
}

/// Every caller failure answers with its own status and challenge, before any
/// operation runs: reads need an administrator's passkey sign-in, mutations a
/// recent one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn callers_must_be_administrators_with_a_passkey() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let fresh = harness.token(admin, Acr::PhishingResistant, Duration::seconds(10));
    let old = harness.token(admin, Acr::PhishingResistant, Duration::minutes(10));
    let social = harness.token(admin, Acr::Social, Duration::seconds(10));
    let not_admin = harness.token(user, Acr::PhishingResistant, Duration::seconds(10));
    let wrong_audience =
        harness.signed(admin, "notes-api", Acr::PhishingResistant, Duration::zero());
    let ended = harness.admin().await;
    let ended_token = harness.token(ended, Acr::PhishingResistant, Duration::zero());
    harness
        .database
        .sessions()
        .revoke(ended.user_id, SessionScope::One(ended.session_id))
        .await
        .expect("revoke");
    let read = paths::USERS;
    let mutation = user_path(paths::USER_ENABLE, user.user_id);
    for (path, method, token, status, challenge) in [
        (read, Method::GET, None, 401, Some("Bearer")),
        (
            read,
            Method::GET,
            Some("not-a-jwt"),
            401,
            Some(r#"Bearer error="invalid_token""#),
        ),
        (
            read,
            Method::GET,
            Some(wrong_audience.as_str()),
            401,
            Some(r#"Bearer error="invalid_token""#),
        ),
        (
            read,
            Method::GET,
            Some(ended_token.as_str()),
            401,
            Some(r#"Bearer error="invalid_token""#),
        ),
        (read, Method::GET, Some(not_admin.as_str()), 403, None),
        (
            read,
            Method::GET,
            Some(social.as_str()),
            401,
            Some(r#"Bearer error="insufficient_user_authentication", acr_values="phr""#),
        ),
        (read, Method::GET, Some(old.as_str()), 200, None),
        (
            mutation.as_str(),
            Method::POST,
            Some(old.as_str()),
            401,
            Some(
                r#"Bearer error="insufficient_user_authentication", acr_values="phr", max_age="300""#,
            ),
        ),
        // The account is active, so a caller who passes every check gets a conflict.
        (
            mutation.as_str(),
            Method::POST,
            Some(fresh.as_str()),
            409,
            None,
        ),
    ] {
        let (actual, headers, _) = harness.call(method.clone(), path, token, None).await;
        assert_eq!(actual.as_u16(), status, "{method} {path} with {token:?}");
        assert_eq!(
            headers
                .get(header::WWW_AUTHENTICATE)
                .map(|value| value.to_str().expect("header")),
            challenge,
            "{method} {path} with {token:?}"
        );
    }
}

/// Disabling an account ends its sessions at once and records why; enabling it
/// restores it, and both show in the events.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn disabling_ends_sessions_and_is_recorded() {
    let capture = piquel_telemetry::Telemetry::capture(crate::TELEMETRY_FILTER);
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let token = harness.token(admin, Acr::PhishingResistant, Duration::zero());
    let disable = user_path(paths::USER_DISABLE, user.user_id);
    let (status, ..) = harness
        .call(
            Method::POST,
            &disable,
            Some(&token),
            Some(json!({"reason": ""})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, ..) = harness
        .call(
            Method::POST,
            &disable,
            Some(&token),
            Some(json!({"reason": "Spam"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let stored = harness
        .database
        .users()
        .find_by_id(user.user_id)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.status, AccountStatus::Disabled);
    let administrator = admin.user_id.to_string();
    assert!(
        capture.logs().iter().any(|log| {
            let has = |key: &str, value: &str| {
                log.attributes_iter().any(|(name, logged)| {
                    name.as_str() == key && format!("{logged:?}").contains(value)
                })
            };
            has("event.kind", "account_disabled") && has("event.administrator", &administrator)
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
    let (status, ..) = harness
        .call(
            Method::POST,
            &user_path(paths::USER_ENABLE, user.user_id),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
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
    let (status, _, page) = harness
        .call(
            Method::GET,
            &format!(
                "{}?user={}&kind=account_disabled",
                paths::EVENTS,
                user.user_id
            ),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page["events"][0]["actor"]["user_id"],
        admin.user_id.to_string()
    );
    assert_eq!(
        page["events"][0]["event"]["data"]["reason"],
        json!({"$personal": "Spam"})
    );
}

/// `handle check` lists look-alike handles. Renaming one away fixes it, bumps the
/// profile version and is recorded; taken, reserved and unchanged handles are
/// refused.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn handles_are_checked_and_renamed() {
    let harness = Harness::new().await;
    let operations = harness.operations();
    let suffix = &TokenId::new().to_string()[24..];
    let original = harness.named(&format!("look-{suffix}")).await;
    let lookalike = harness.named(&format!("l0ok-{suffix}")).await;
    let problems = |problems: Vec<HandleProblem>| {
        problems
            .into_iter()
            .filter(|problem| [original, lookalike].contains(&problem.user_id))
            .map(|problem| (problem.username, problem.issue))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        problems(operations.check_handles().await.expect("check")),
        [
            (
                format!("l0ok-{suffix}"),
                HandleIssue::LooksLike(vec![format!("look-{suffix}")])
            ),
            (
                format!("look-{suffix}"),
                HandleIssue::LooksLike(vec![format!("l0ok-{suffix}")])
            ),
        ]
    );
    let rename = |handle: String, allow_reserved| {
        let operations = operations.clone();
        async move {
            operations
                .rename_handle(
                    &cli(),
                    lookalike,
                    Handle::parse(&handle).expect("handle"),
                    allow_reserved,
                )
                .await
        }
    };
    assert!(matches!(
        rename(format!("look-{suffix}"), false).await,
        Err(AdminError::HandleTaken(_))
    ));
    assert!(matches!(
        rename("admin".into(), false).await,
        Err(AdminError::InvalidHandle(HandleError::Reserved(_)))
    ));
    assert!(matches!(
        rename(format!("l0ok-{suffix}"), false).await,
        Err(AdminError::SameHandle)
    ));
    rename(format!("renamed-{suffix}"), false)
        .await
        .expect("rename");
    let renamed = harness
        .database
        .users()
        .find_by_id(lookalike)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(renamed.username, format!("renamed-{suffix}"));
    assert_eq!(renamed.profile_version, 2);
    assert_eq!(
        harness.events(lookalike).await[..1],
        [DomainEvent::HandleChanged {
            old: Personal::Value(format!("l0ok-{suffix}")),
            new: Personal::Value(Handle::parse(&format!("renamed-{suffix}")).expect("handle")),
        }]
    );
    assert_eq!(
        problems(operations.check_handles().await.expect("check")),
        []
    );
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
    let token = harness.token(admin, Acr::PhishingResistant, Duration::zero());
    let (status, _, page) = harness
        .call(
            Method::GET,
            &format!("{}?user={}", paths::EVENTS, user.user_id),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page["events"][0]["event"],
        json!({"kind": "from_a_newer_release", "version": 1, "data": data})
    );
}

/// Administrator accounts are out of the API's reach until their rights are
/// revoked, and nobody grants or revokes their own rights. A revocation applies to the next
/// request of the revoked administrator's token.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_are_protected_until_revoked() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let other = harness.account().await;
    let token = harness.token(admin, Acr::PhishingResistant, Duration::zero());
    let other_token = harness.token(other, Acr::PhishingResistant, Duration::zero());
    let (status, ..) = harness
        .call(
            Method::POST,
            paths::ADMINISTRATORS,
            Some(&token),
            Some(json!({"user_id": other.user_id})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, ..) = harness
        .call(Method::GET, paths::USERS, Some(&other_token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let disable = user_path(paths::USER_DISABLE, other.user_id);
    let reason = json!({"reason": "Compromised"});
    let (status, ..) = harness
        .call(Method::POST, &disable, Some(&token), Some(reason.clone()))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, ..) = harness
        .call(
            Method::DELETE,
            &user_path(paths::ADMINISTRATOR, admin.user_id),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Refused before any lock, so a grant queued behind the caller's own
    // revocation cannot restore their rights.
    let (status, ..) = harness
        .call(
            Method::POST,
            paths::ADMINISTRATORS,
            Some(&token),
            Some(json!({"user_id": admin.user_id})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, ..) = harness
        .call(
            Method::DELETE,
            &user_path(paths::ADMINISTRATOR, other.user_id),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, ..) = harness
        .call(Method::GET, paths::USERS, Some(&other_token), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, ..) = harness
        .call(Method::POST, &disable, Some(&token), Some(reason))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        harness.events(other.user_id).await[2..4],
        [
            DomainEvent::AdministratorRevoked {},
            DomainEvent::AdministratorGranted {},
        ][..]
    );
}

/// An invitation link works until an administrator revokes it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoked_invitations_cannot_be_redeemed() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let token = harness.token(admin, Acr::PhishingResistant, Duration::zero());
    let (status, _, created) = harness
        .call(
            Method::POST,
            paths::INVITATIONS,
            Some(&token),
            Some(json!({"expires_in": "24h"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let url: url::Url = created["url"].as_str().expect("url").parse().expect("URL");
    let (_, encoded) = url
        .query_pairs()
        .find(|(name, _)| name == "invitation")
        .expect("invitation secret");
    let secret = piquel_crypto::Secret::parse(&encoded).expect("secret");
    let digest = secret.digest();
    assert!(
        harness
            .database
            .security()
            .invitation_active(digest.as_bytes())
            .await
            .expect("lookup")
    );
    let invitation = paths::INVITATION.replace(
        "{invitation_id}",
        created["id"].as_str().expect("invitation ID"),
    );
    let (status, ..) = harness
        .call(Method::DELETE, &invitation, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        !harness
            .database
            .security()
            .invitation_active(digest.as_bytes())
            .await
            .expect("lookup")
    );
    // The previous release checks only the expiry, so revocation sets it too.
    let (_, _, listed) = harness
        .call(Method::GET, paths::INVITATIONS, Some(&token), None)
        .await;
    let revoked = listed
        .as_array()
        .expect("invitations")
        .iter()
        .find(|listed| listed["id"] == created["id"])
        .expect("revoked invitation");
    assert!(revoked["expires_at"].as_str() <= revoked["revoked_at"].as_str());
    let (status, ..) = harness
        .call(Method::DELETE, &invitation, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// An administrator's operator, as a token signed in with a passkey at `auth_time`
/// makes it.
fn operator(admin: Account, auth_time: chrono::DateTime<Utc>) -> Operator {
    Operator::Admin {
        user_id: admin.user_id,
        session_id: admin.session_id,
        acr: Some(Acr::PhishingResistant),
        auth_time: Some(auth_time),
    }
}

/// A mutation checks its caller's confirmation after its last write: one admitted
/// just inside the window, that then waited for a logout holding the target's
/// session, is refused with the step-up and changes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn mutations_recheck_the_confirmation_after_waiting() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let auth_time = Utc::now() - Duration::seconds(298);
    let mut logout = harness.database.begin().await.expect("transaction");
    logout
        .sessions()
        .revoke(user.user_id, SessionScope::One(user.session_id))
        .await
        .expect("target session lock");
    let operations = harness.operations();
    let reason = Reason::parse("Spam".into()).expect("reason");
    let operator = operator(admin, auth_time);
    let (result, ()) = tokio::join!(
        operations.disable_user(&operator, user.user_id, reason),
        async {
            until_blocked(&mut logout, 1).await;
            let expired = auth_time + Duration::seconds(301) - Utc::now();
            tokio::time::sleep(expired.to_std().unwrap_or_default()).await;
            logout.commit().await.expect("logout");
        }
    );
    assert!(
        matches!(result, Err(AdminError::StepUpRequired(_))),
        "{result:?}"
    );
    let stored = harness
        .database
        .users()
        .find_by_id(user.user_id)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.status, AccountStatus::Active);
}

/// A mutation waiting for its target holds no lock of its caller's, so a sign-in
/// that locks the target's account and then revokes the caller's session, as
/// switching accounts does, finishes first.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn waiting_mutations_hold_no_caller_locks() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let mut switch = harness.database.begin().await.expect("transaction");
    switch
        .users()
        .find_active_by_id_for_update(user.user_id)
        .await
        .expect("target lock");
    let operations = harness.operations();
    let reason = Reason::parse("Spam".into()).expect("reason");
    let operator = operator(admin, Utc::now());
    let (result, ()) = tokio::join!(
        operations.disable_user(&operator, user.user_id, reason),
        async {
            until_blocked(&mut switch, 1).await;
            switch
                .sessions()
                .revoke(admin.user_id, SessionScope::One(admin.session_id))
                .await
                .expect("the switch revokes the caller's session without a deadlock");
            switch.commit().await.expect("commit");
        }
    );
    assert!(
        matches!(result, Err(AdminError::SessionEnded)),
        "{result:?}"
    );
}

/// A mutation never waits for its caller's session, which the caller's own
/// sign-in or social linking may hold while it waits for the mutation's locks.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn mutations_never_wait_for_the_callers_session() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let mut linking = harness.database.begin().await.expect("transaction");
    linking
        .sessions()
        .find_active_by_id_for_update(admin.session_id)
        .await
        .expect("caller session lock");
    let reason = Reason::parse("Spam".into()).expect("reason");
    let disabled = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        harness
            .operations()
            .disable_user(&operator(admin, Utc::now()), user.user_id, reason),
    )
    .await
    .expect("the mutation does not wait for the caller's session");
    assert!(disabled.is_ok(), "{disabled:?}");
    linking.rollback().await.expect("rollback");
}

/// Revoking an invitation that a signup is redeeming waits for the signup, which
/// may end the administrator's session as it signs the new account in on the
/// same browser.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn invitation_revocation_waits_for_signup() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let operations = harness.operations();
    let invitation = operations
        .create_invitation(&cli(), &origin(), InviteExpiry::default())
        .await
        .expect("invitation");
    let (_, encoded) = invitation
        .url
        .query_pairs()
        .find(|(name, _)| name == "invitation")
        .expect("invitation secret");
    let digest = piquel_crypto::Secret::parse(&encoded)
        .expect("secret")
        .digest();
    let mut signup = harness.database.begin().await.expect("transaction");
    assert!(
        signup
            .security()
            .redeem_invitation(digest.as_bytes())
            .await
            .expect("redeem")
    );
    let operator = operator(admin, Utc::now());
    let (result, ()) = tokio::join!(
        operations.revoke_invitation(&operator, invitation.id),
        async {
            until_blocked(&mut signup, 1).await;
            signup
                .sessions()
                .revoke(admin.user_id, SessionScope::One(admin.session_id))
                .await
                .expect("the signup revokes the browser's session without a deadlock");
            signup.commit().await.expect("signup");
        }
    );
    assert!(
        matches!(result, Err(AdminError::InvitationNotFound)),
        "{result:?}"
    );
}

/// Two administrators acting on each other at once are both refused, rather than
/// deadlocking on each other's account lock.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_acting_on_each_other_are_refused() {
    let harness = Harness::new().await;
    let (a, b) = (harness.admin().await, harness.admin().await);
    let harness = &harness;
    for _ in 0..10 {
        let disable = |by: Account, target: Account| {
            let token = harness.token(by, Acr::PhishingResistant, Duration::zero());
            let path = user_path(paths::USER_DISABLE, target.user_id);
            async move {
                harness
                    .call(
                        Method::POST,
                        &path,
                        Some(&token),
                        Some(json!({"reason": "Rogue"})),
                    )
                    .await
                    .0
            }
        };
        let (first, second) = tokio::join!(disable(a, b), disable(b, a));
        assert_eq!(
            (first, second),
            (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN)
        );
    }
}
