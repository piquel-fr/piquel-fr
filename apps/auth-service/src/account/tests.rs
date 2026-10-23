//! Database-backed scenarios of the shared settings on the admin mount: what an
//! administrator may change on another account, how it is recorded, and what the
//! mount refuses.

use super::*;
use crate::{
    AdminService, Operator, Reason,
    admin::tests::{Account, Harness, cli, operator},
    routes,
    security::CSRF_HEADER,
    tests::{AUTH_ORIGIN, Browser, Replicas},
};
use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, header},
};
use chrono::{Duration, Utc};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use piquel_admin_api::{REASON_HEADER, paths};
use piquel_common::{
    EventId, Provider, TokenId, UserId,
    events::{Actor, DomainEvent, RevocationReason},
    protocol::claims::Acr,
};
use piquel_repository::{InsertExternalIdentity, InsertPasskey};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The reason the scenarios give, outside ASCII so its percent-encoding matters.
const REASON: &str = "Le propriétaire a perdu son téléphone";

/// The admin listener, an administrator with a fresh passkey sign-in, and the
/// owner mount, over the test database.
struct Fixture {
    /// The admin API and the admin mount.
    harness: Harness,
    /// The acting administrator.
    admin: Account,
    /// Their token, signed in with a passkey just now.
    token: String,
}

impl Fixture {
    /// Builds the listener and signs an administrator in.
    async fn new() -> Self {
        let harness = Harness::new().await;
        let admin = harness.admin().await;
        let token = harness.token(admin, Acr::PhishingResistant, Duration::seconds(10));
        Self {
            harness,
            admin,
            token,
        }
    }

    /// Creates a signed-in account with `passkeys` passkeys and a GitHub identity.
    async fn target(&self, passkeys: usize) -> (Account, Vec<PasskeyId>) {
        let account = self.harness.account().await;
        let mut tx = self.harness.database.begin().await.expect("transaction");
        let mut ids = Vec::new();
        for index in 0..passkeys {
            let id = PasskeyId::new();
            tx.passkeys()
                .insert(&InsertPasskey {
                    id,
                    credential_id: TokenId::new().to_string().into_bytes(),
                    user_id: account.user_id,
                    credential: json!({}),
                    friendly_name: format!("Key {index}"),
                })
                .await
                .expect("passkey");
            ids.push(id);
        }
        tx.federation()
            .insert_identity(&InsertExternalIdentity {
                id: TokenId::new(),
                user_id: account.user_id,
                provider: Provider::GitHub,
                issuer: "https://github.com".into(),
                subject: TokenId::new().to_string(),
                linked_email: None,
            })
            .await
            .expect("identity");
        tx.commit().await.expect("commit");
        (account, ids)
    }

    /// Sends `method` to the account settings path `path` of `user` on the admin
    /// mount, with `token` and the percent-encoded `reason`, if any.
    async fn call(
        &self,
        method: Method,
        user: UserId,
        path: &str,
        token: Option<&str>,
        reason: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder().method(method).uri(format!(
            "{}{path}",
            paths::USER.replace("{user_id}", &user.to_string())
        ));
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(reason) = reason {
            request = request.header(REASON_HEADER, reason);
        }
        let body = match body {
            Some(body) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        self.harness
            .send(request.body(body).expect("request"))
            .await
    }

    /// [`Self::call`] as the administrator, giving [`REASON`].
    async fn change(
        &self,
        method: Method,
        user: UserId,
        path: &str,
        body: Option<Value>,
    ) -> StatusCode {
        let reason = utf8_percent_encode(REASON, NON_ALPHANUMERIC).to_string();
        self.call(method, user, path, Some(&self.token), Some(&reason), body)
            .await
            .0
    }
}

/// The path of a shared route for `id`.
fn item(template: &str, id: &impl ToString) -> String {
    template.replace("{id}", &id.to_string())
}

/// An administrator renames and removes another account's passkey and unlinks its
/// identity. Each change is the owner's own operation, recorded as the
/// administrator's with the decoded reason as personal data, and the owner sees
/// who acted and why in their history.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_change_another_account_on_its_behalf() {
    let fixture = Fixture::new().await;
    let (target, passkeys) = fixture.target(2).await;
    let user = target.user_id;
    let renamed = json!({"friendly_name": "Lost phone"});
    for (method, path, body) in [
        (
            Method::PATCH,
            item(passkey::ITEM, &passkeys[0]),
            Some(renamed),
        ),
        (Method::DELETE, item(passkey::ITEM, &passkeys[1]), None),
        (
            Method::DELETE,
            federation::IDENTITY.replace("{provider}", "github"),
            None,
        ),
    ] {
        assert_eq!(
            fixture.change(method.clone(), user, &path, body).await,
            StatusCode::NO_CONTENT,
            "{method} {path}"
        );
    }

    let database = &fixture.harness.database;
    let keys = database
        .passkeys()
        .list_active(user)
        .await
        .expect("passkeys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].friendly_name, "Lost phone");
    let identities = database.federation().list_active(user).await;
    assert_eq!(identities.expect("identities").len(), 0, "unlinked");
    let history = database
        .events()
        .history_for_user(user, 20)
        .await
        .expect("history");
    let admin = Actor::Admin {
        user_id: fixture.admin.user_id,
        session_id: fixture.admin.session_id,
    };
    for expected in [
        DomainEvent::PasskeyRenamed {
            passkey_id: passkeys[0],
        },
        DomainEvent::PasskeyRemoved {
            passkey_id: passkeys[1],
        },
        DomainEvent::IdentityUnlinked {
            provider: Provider::GitHub,
        },
        DomainEvent::SessionRevoked {
            session_id: target.session_id,
            reason: RevocationReason::CredentialRemoved,
        },
    ] {
        let stored = history
            .iter()
            .find(|stored| stored.event.known() == Some(&expected))
            .unwrap_or_else(|| panic!("{expected:?} recorded"));
        assert_eq!(stored.actor, admin, "{expected:?}");
        assert_eq!(stored.reason.as_deref(), Some(REASON), "{expected:?}");
    }

    let browser = Browser::sign_in(database, user).await;
    let owner = AccountApplication::owner(database.clone()).routes();
    let (status, page) = browser.call(&owner, Method::GET, history::LIST).await;
    assert_eq!(status, StatusCode::OK);
    let entry = page["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["kind"] == "passkey.renamed")
        .expect("the rename");
    assert_eq!(entry["actor"], "admin");
    assert_eq!(entry["reason"], REASON);
}

/// The admin mount serves only the shared routes and methods: an administrator
/// cannot add a passkey or an address, verify one, report an entry or manage
/// clients there.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_admin_mount_serves_only_shared_routes() {
    let fixture = Fixture::new().await;
    let (target, _) = fixture.target(1).await;
    let report = routes::history::REPORT.replace("{event_id}", &EventId::new().to_string());
    for (method, path, status) in [
        (Method::POST, emails::LIST, StatusCode::METHOD_NOT_ALLOWED),
        (Method::POST, emails::VERIFY, StatusCode::METHOD_NOT_ALLOWED),
        (
            Method::POST,
            routes::passkey::ENROLL_START,
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            routes::passkey::CONFIRM_START,
            StatusCode::NOT_FOUND,
        ),
        (Method::POST, &report, StatusCode::NOT_FOUND),
        (Method::GET, routes::clients::LIST, StatusCode::NOT_FOUND),
    ] {
        let body = Some(json!({"email": "taken@example.com"}));
        let status_now = fixture
            .change(method.clone(), target.user_id, path, body)
            .await;
        assert_eq!(status_now, status, "{method} {path}");
    }
}

/// The admin mount serves administrators only, on accounts that are not
/// administrators', with a reason and a recent passkey for every change. A read
/// needs neither.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_admin_mount_checks_who_acts_and_why() {
    let fixture = Fixture::new().await;
    let (target, passkeys) = fixture.target(1).await;
    let user = target.user_id;
    let harness = &fixture.harness;
    let admin = Some(fixture.token.as_str());
    let other_admin = harness.admin().await.user_id;
    let account = harness.account().await;
    let account = harness.token(account, Acr::PhishingResistant, Duration::seconds(10));
    let account = Some(account.as_str());
    let old = harness.token(fixture.admin, Acr::PhishingResistant, Duration::minutes(10));
    let old = Some(old.as_str());
    let max_age =
        r#"Bearer error="insufficient_user_authentication", acr_values="phr", max_age="300""#;
    let (read, change) = (Method::GET, Method::PATCH);
    for (method, user, token, reason, status, challenge) in [
        (read.clone(), user, None, None, 401, Some("Bearer")),
        (read.clone(), user, account, None, 403, None),
        (read.clone(), other_admin, admin, None, 403, None),
        (read.clone(), UserId::new(), admin, None, 404, None),
        (read, user, old, None, 200, None),
        (change.clone(), user, admin, None, 400, None),
        (change.clone(), user, admin, Some("%0A"), 400, None),
        (change.clone(), user, admin, Some("%FF"), 400, None),
        (change, user, old, Some("Spam"), 401, Some(max_age)),
    ] {
        let path = if method == Method::GET {
            passkey::LIST.to_owned()
        } else {
            item(passkey::ITEM, &passkeys[0])
        };
        let body = Some(json!({"friendly_name": "Renamed"}));
        let (actual, headers, _) = fixture
            .call(method.clone(), user, &path, token, reason, body)
            .await;
        let actual_challenge = headers
            .get(header::WWW_AUTHENTICATE)
            .map(|value| value.to_str().expect("header"));
        let row = format!("{method} {path} for {user} with reason {reason:?}");
        assert_eq!(actual.as_u16(), status, "{row}");
        assert_eq!(actual_challenge, challenge, "{row}");
    }
    let keys = harness.database.passkeys().list_active(user).await;
    assert_eq!(keys.expect("passkeys")[0].friendly_name, "Key 0");
}

/// A change checks its administrator again under the account lock and before
/// committing: rights revoked after the request was admitted, or a target made an
/// administrator meanwhile, refuse it and change nothing. The CLI may change an
/// administrator's account.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn changes_check_the_administrator_again() {
    let fixture = Fixture::new().await;
    let service = AccountService::new(fixture.harness.database.clone());
    let admins = AdminService::new(fixture.harness.database.clone());
    let reason = || Some(Reason::parse("Support ticket".into()).expect("reason"));
    let rename = async |operator: Operator, user: UserId, passkey: PasskeyId| {
        service
            .rename_passkey(
                &Subject::operator(user, operator, reason()),
                passkey,
                "Renamed".into(),
            )
            .await
    };

    let (target, passkeys) = fixture.target(1).await;
    let revoked = fixture.harness.admin().await;
    let admitted = operator(revoked, Utc::now());
    admins
        .revoke_administrator(&cli(), revoked.user_id)
        .await
        .expect("revoke");
    assert!(matches!(
        rename(admitted, target.user_id, passkeys[0]).await,
        Err(AccountError::Operator(crate::AdminError::NotAdministrator))
    ));

    let admitted = operator(fixture.admin, Utc::now());
    admins
        .grant_administrator(&cli(), target.user_id)
        .await
        .expect("grant");
    assert!(matches!(
        rename(admitted, target.user_id, passkeys[0]).await,
        Err(AccountError::Operator(
            crate::AdminError::AdministratorTarget
        ))
    ));
    let keys = fixture
        .harness
        .database
        .passkeys()
        .list_active(target.user_id)
        .await
        .expect("passkeys");
    assert_eq!(keys[0].friendly_name, "Key 0", "nothing changed");

    rename(cli(), target.user_id, passkeys[0])
        .await
        .expect("the CLI changes an administrator's account");
}

/// The last passkey stays, whoever removes it and even with a social identity
/// linked.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_last_passkey_stays_on_both_mounts() {
    let fixture = Fixture::new().await;
    let (target, passkeys) = fixture.target(1).await;
    let path = item(passkey::ITEM, &passkeys[0]);
    assert_eq!(
        fixture
            .change(Method::DELETE, target.user_id, &path, None)
            .await,
        StatusCode::BAD_REQUEST
    );
    let database = &fixture.harness.database;
    let browser = Browser::sign_in(database, target.user_id).await;
    let owner = AccountApplication::owner(database.clone()).routes();
    let (status, _) = browser.call(&owner, Method::DELETE, &path).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        database
            .passkeys()
            .list_active(target.user_id)
            .await
            .expect("passkeys")
            .len(),
        1
    );
}

/// The public listener serves no admin mount: `/users/…` is no route there, for
/// reads or for mutations that pass the browser policy.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_public_listener_has_no_admin_mount() {
    let replicas = Replicas::new().await;
    let path = format!(
        "{}{}",
        paths::USER.replace("{user_id}", &UserId::new().to_string()),
        passkey::LIST
    );
    for method in [Method::GET, Method::DELETE] {
        let response = replicas
            .a
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(&path)
                    .header(header::ORIGIN, AUTH_ORIGIN)
                    .header(CSRF_HEADER, "1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{method} {path}: {}",
            response.status()
        );
    }
}
