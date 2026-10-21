//! Database-backed history scenarios: whose entries a page holds, how pages
//! continue, and what a report changes.

use super::*;
use crate::security::{BrowserCookie, Session};
use crate::tests::Replicas;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use chrono::Duration;
use piquel_common::{
    AuthenticationMethod, PasskeyId, SessionId, TokenId, UserId,
    clients::ClientKind,
    events::{EventContext, JobName},
};
use piquel_repository::{
    InsertAuthorizationCode, InsertRefreshFamily, InsertRefreshToken, InsertUser,
    RefreshRotationError, SessionAuthentication,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// Largest response body the scenarios read.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// A scenario account with one signed-in browser.
struct Account {
    /// The account.
    user_id: UserId,
    /// The browser's session.
    session_id: SessionId,
    /// The browser's session cookie pair.
    cookie: String,
}

/// The history routes over the test database.
struct Harness {
    /// Routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
}

impl Harness {
    /// Builds the history routes over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            router: HistoryApplication::new(database.clone()).routes(),
            database,
        }
    }

    /// Creates an account and signs a browser in to it.
    async fn account(&self) -> Account {
        let user_id = UserId::new();
        self.database
            .users()
            .insert(&InsertUser {
                id: user_id,
                username: format!("history_{}", &user_id.to_string()[24..]),
                display_name: "History test".into(),
            })
            .await
            .expect("user");
        self.sign_in(user_id).await
    }

    /// Signs another browser in to `user_id`.
    async fn sign_in(&self, user_id: UserId) -> Account {
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
            cookie: format!("{}={}", BrowserCookie::Session.as_str(), secret.encoded()),
        }
    }

    /// Records `events` about `account`, caused by `actor`, in one transaction.
    async fn record(&self, account: &Account, actor: Actor, events: Vec<DomainEvent>) {
        let context = EventContext {
            actor,
            origin: RequestOrigin::default(),
        };
        let mut tx = self.database.begin().await.expect("transaction");
        for event in events {
            tx.record(&context, Some(account.user_id), event)
                .await
                .expect("record");
        }
        tx.commit().await.expect("commit");
    }

    /// The account's latest event, as the repository returns it.
    async fn latest(&self, account: &Account) -> EventId {
        self.database
            .events()
            .history_for_user(account.user_id, 1)
            .await
            .expect("history")[0]
            .id
    }

    /// Sends a request as `account`'s browser and returns its status and JSON body.
    async fn call(&self, account: &Account, method: Method, path: &str) -> (StatusCode, Value) {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .extension(RequestContext::TEST)
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, &account.cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .expect("body");
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// Reads `account`'s history page that continues `before`.
    async fn page(&self, account: &Account, before: Option<&Value>) -> Value {
        let path = match before.and_then(Value::as_str) {
            Some(before) => format!("{}?before={before}", routes::history::LIST),
            None => routes::history::LIST.to_owned(),
        };
        let (status, page) = self.call(account, Method::GET, &path).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        page
    }

    /// Reports `event_id` as `account`'s browser.
    async fn report(&self, account: &Account, event_id: EventId) -> (StatusCode, Value) {
        let path = routes::history::REPORT.replace("{event_id}", &event_id.to_string());
        self.call(account, Method::POST, &path).await
    }

    /// Issues a refresh grant to a new client from `account`'s session, and returns
    /// the client and its first refresh token's ID and digest.
    async fn grant(&self, account: &Account) -> (ClientId, TokenId, Vec<u8>) {
        let registration = crate::tests::registration(ClientKind::Public, "https://client.example");
        self.database
            .oidc()
            .create_client(&registration)
            .await
            .expect("client");
        let client = registration.id;
        let mut tx = self.database.begin().await.expect("transaction");
        let session = tx
            .sessions()
            .find_by_id(account.session_id)
            .await
            .expect("lookup")
            .expect("session");
        let authentication = SessionAuthentication::from(&session);
        let code = TokenId::new();
        tx.oidc()
            .insert_code(&InsertAuthorizationCode {
                id: code,
                secret_digest: code.as_uuid().as_bytes().repeat(2),
                client_id: client.clone(),
                user_id: account.user_id,
                session_id: account.session_id,
                redirect_uri: "https://client.example/callback".into(),
                pkce_challenge: "challenge".into(),
                nonce: None,
                scopes: vec!["openid".into()],
                audience: "test".into(),
                authentication: authentication.clone(),
                expires_at: Utc::now() + Duration::minutes(1),
            })
            .await
            .expect("code");
        let (family, token) = (TokenId::new(), TokenId::new());
        let digest = token.as_uuid().as_bytes().repeat(2);
        tx.tokens()
            .insert_family(
                &InsertRefreshFamily {
                    id: family,
                    user_id: account.user_id,
                    client_id: client.to_string(),
                    session_id: account.session_id,
                    authorization_code_id: code,
                    audience: "test".into(),
                    scopes: vec!["openid".into()],
                    authentication,
                },
                &InsertRefreshToken {
                    id: token,
                    family_id: family,
                    secret_digest: digest.clone(),
                    expires_at: Utc::now() + Duration::hours(1),
                },
            )
            .await
            .expect("family");
        tx.commit().await.expect("commit");
        (client, token, digest)
    }
}

/// `account`'s user, acting from its browser.
const fn user(account: &Account) -> Actor {
    Actor::User {
        user_id: account.user_id,
        session_id: Some(account.session_id),
    }
}

/// A page holds only the caller's visible entries, newest first. Pages continue
/// from their cursor without gaps or repeats, even as new events arrive, and a
/// cursor from another account's history matches nothing. Admin and CLI actions
/// show who acted.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pages_hold_only_the_callers_entries() {
    let harness = Harness::new().await;
    let alice = harness.account().await;
    let bob = harness.account().await;
    let renamed = || DomainEvent::PasskeyRenamed {
        passkey_id: PasskeyId::new(),
    };
    // Hidden confirmations between the renames make the first page read past 50 rows.
    let events = (0..60)
        .flat_map(|_| {
            [
                renamed(),
                DomainEvent::PasskeyConfirmed {
                    session_id: alice.session_id,
                },
            ]
        })
        .collect();
    harness.record(&alice, user(&alice), events).await;
    harness
        .record(
            &alice,
            Actor::Admin {
                user_id: bob.user_id,
                session_id: bob.session_id,
            },
            vec![DomainEvent::AccountViewed {}],
        )
        .await;
    harness
        .record(
            &alice,
            Actor::Cli {
                os_user: "operator".into(),
                host: "host".into(),
            },
            vec![DomainEvent::AdministratorGranted {}],
        )
        .await;
    harness
        .record(&bob, user(&bob), vec![renamed(), renamed()])
        .await;

    let first = harness.page(&alice, None).await;
    let entries = first["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 50);
    assert_eq!(
        (&entries[0]["kind"], &entries[0]["actor"]),
        (&json!("administrator.granted"), &json!("operator"))
    );
    assert_eq!(
        (&entries[1]["kind"], &entries[1]["actor"]),
        (&json!("account.viewed"), &json!("admin"))
    );
    assert_eq!(entries[2]["kind"], "passkey.renamed");
    assert_eq!(entries[2]["actor"], "account");
    assert_eq!(entries[2]["erased"], false);

    let second = harness.page(&alice, Some(&first["next"])).await;
    harness.record(&alice, user(&alice), vec![renamed()]).await;
    assert_eq!(
        harness.page(&alice, Some(&first["next"])).await,
        second,
        "new events never shift a later page"
    );
    assert_eq!(second["next"], Value::Null);
    let second = second["entries"].as_array().expect("entries");
    // The 60 renames, the admin and CLI actions, and the sign-in.
    assert_eq!(second.len(), 63 - 50);
    assert_eq!(second.last().expect("sign-in")["kind"], "session.signed_in");

    let mut ids: Vec<_> = entries
        .iter()
        .chain(second)
        .map(|entry| &entry["id"])
        .collect();
    let total = ids.len();
    ids.sort_by_key(|id| id.as_str());
    ids.dedup();
    assert_eq!(ids.len(), total, "no entry repeats across pages");
    let bobs: Vec<Value> = harness
        .database
        .events()
        .history_for_user(bob.user_id, 100)
        .await
        .expect("history")
        .iter()
        .map(|stored| json!(stored.id))
        .collect();
    assert!(
        ids.iter().all(|id| !bobs.contains(id)),
        "only Alice's events"
    );
    assert_eq!(
        harness.page(&bob, Some(&first["next"])).await["entries"],
        json!([]),
        "another account's cursor matches nothing"
    );
}

/// A page stops after [`MAX_BATCHES`] batches of hidden events, short but with a
/// cursor, and the next page continues where it stopped.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pages_stop_reading_after_a_bound() {
    let harness = Harness::new().await;
    let alice = harness.account().await;
    let renamed = DomainEvent::PasskeyRenamed {
        passkey_id: PasskeyId::new(),
    };
    let confirmed = DomainEvent::PasskeyConfirmed {
        session_id: alice.session_id,
    };
    let hidden = MAX_BATCHES * usize::from(PAGE_SIZE) + 1;
    harness
        .record(&alice, user(&alice), vec![renamed.clone()])
        .await;
    harness
        .record(&alice, user(&alice), vec![confirmed; hidden])
        .await;

    let first = harness.page(&alice, None).await;
    assert_eq!(first["entries"], json!([]));
    let second = harness.page(&alice, Some(&first["next"])).await;
    assert_eq!(second["entries"][0]["kind"], "passkey.renamed");
    assert_eq!(second["next"], Value::Null);
}

/// Reporting an entry records the report, ends the account's other sessions and
/// revokes every refresh family, this session's included, and says how to undo
/// the entry. Only the account's own entries, caused by its user, can be reported.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn reporting_ends_other_sessions_and_every_grant() {
    let harness = Harness::new().await;
    let alice = harness.account().await;
    let intruder = harness.sign_in(alice.user_id).await;
    let bob = harness.account().await;
    let grants = [harness.grant(&alice).await, harness.grant(&intruder).await];
    let passkey_id = PasskeyId::new();
    harness
        .record(
            &alice,
            Actor::System {
                job: JobName::Cleanup,
            },
            vec![DomainEvent::AccountEnabled {}],
        )
        .await;
    let system = harness.latest(&alice).await;
    harness
        .record(
            &alice,
            user(&intruder),
            vec![DomainEvent::PasskeyAdded { passkey_id }],
        )
        .await;
    let added = harness.latest(&alice).await;

    assert_eq!(
        harness.report(&bob, added).await.0,
        StatusCode::NOT_FOUND,
        "another account's entry"
    );
    assert_eq!(
        harness.report(&alice, system).await.0,
        StatusCode::BAD_REQUEST,
        "an entry the user did not cause"
    );
    let (status, report) = harness.report(&alice, added).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(
        report,
        json!({"follow_up": {"action": "remove_passkey", "passkey_id": passkey_id}})
    );

    let mut sessions = harness.database.sessions();
    assert!(
        sessions
            .find_active_by_id(alice.session_id)
            .await
            .expect("lookup")
            .is_some(),
        "the reporting session stays signed in"
    );
    assert!(
        sessions
            .find_active_by_id(intruder.session_id)
            .await
            .expect("lookup")
            .is_none()
    );
    for (client, token, digest) in grants {
        let mut tx = harness.database.begin().await.expect("transaction");
        assert!(matches!(
            tx.tokens()
                .consume_for_rotation(token, &digest, client.as_str())
                .await,
            Err(RefreshRotationError::Invalid)
        ));
    }
    let recorded: Vec<_> = harness
        .database
        .events()
        .history_for_user(alice.user_id, 2)
        .await
        .expect("history")
        .into_iter()
        .map(|stored| (stored.actor, stored.event))
        .collect();
    assert_eq!(
        recorded,
        [
            (
                user(&alice),
                DomainEvent::SessionRevoked {
                    session_id: intruder.session_id,
                    reason: RevocationReason::CompromiseReported,
                }
            ),
            (
                user(&alice),
                DomainEvent::CompromiseReported { event_id: added }
            ),
        ]
    );
}
