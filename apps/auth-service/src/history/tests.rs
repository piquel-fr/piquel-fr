//! Database-backed history scenarios: whose entries a page holds, how pages
//! continue, and what a report changes.

use super::*;
use crate::{
    account::AccountApplication,
    tests::{Browser, Replicas},
};
use axum::http::{Method, StatusCode};
use piquel_common::{
    PasskeyId, TokenId,
    clients::{ClientKind, ClientOwner},
    events::{EventContext, JobName},
};
use piquel_repository::RefreshRotationError;
use serde_json::{Value, json};

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
            router: HistoryApplication::new(database.clone())
                .routes()
                .merge(AccountApplication::new(database.clone()).routes()),
            database,
        }
    }

    /// Records `events` about `account`, caused by `actor`, in one transaction.
    async fn record(&self, account: &Browser, actor: Actor, events: Vec<DomainEvent>) {
        let context = EventContext {
            actor,
            origin: RequestOrigin::default(),
            reason: None,
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
    async fn latest(&self, account: &Browser) -> EventId {
        self.database
            .events()
            .history_for_user(account.user_id, 1)
            .await
            .expect("history")[0]
            .id
    }

    /// Reads `account`'s history page that continues `before`.
    async fn page(&self, account: &Browser, before: Option<&Value>) -> Value {
        let path = match before.and_then(Value::as_str) {
            Some(before) => format!("{}?before={before}", routes::history::LIST),
            None => routes::history::LIST.to_owned(),
        };
        let (status, page) = account.call(&self.router, Method::GET, &path).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        page
    }

    /// Reports `event_id` as `account`'s browser.
    async fn report(&self, account: &Browser, event_id: EventId) -> (StatusCode, Value) {
        let path = routes::history::REPORT.replace("{event_id}", &event_id.to_string());
        account.call(&self.router, Method::POST, &path).await
    }

    /// Issues a refresh grant to a new client from `account`'s session, and returns
    /// the client and its first refresh token's ID and digest.
    async fn grant(&self, account: &Browser) -> (ClientId, TokenId, Vec<u8>) {
        let registration = crate::tests::registration(ClientKind::Public, "https://client.example");
        self.database
            .oidc()
            .create_client(&registration, ClientOwner::Operator)
            .await
            .expect("client");
        let client = registration.id;
        let (token, digest) = crate::tests::refresh_grant(
            &self.database,
            account.user_id,
            account.session_id,
            &client,
            TokenId::new(),
        )
        .await;
        (client, token, digest)
    }
}

/// `account`'s user, acting from its browser.
const fn user(account: &Browser) -> Actor {
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
    let alice = Browser::new_account(&harness.database).await;
    let bob = Browser::new_account(&harness.database).await;
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

/// An event a newer release wrote, of a kind this one does not know, is hidden
/// rather than failing the page, and cannot be reported.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn events_a_newer_release_wrote_are_hidden() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    let unknown = harness
        .database
        .events()
        .insert_written_elsewhere(alice.user_id, "from_a_newer_release", 1, &json!({}))
        .await
        .expect("event");
    let page = harness.page(&alice, None).await;
    assert_eq!(page["entries"].as_array().expect("entries").len(), 1);
    assert_eq!(page["entries"][0]["kind"], "session.signed_in");
    assert_eq!(
        harness.report(&alice, unknown).await.0,
        StatusCode::NOT_FOUND
    );
}

/// A page stops after [`MAX_BATCHES`] batches of hidden events, short but with a
/// cursor, and the next page continues where it stopped.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pages_stop_reading_after_a_bound() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
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
    let alice = Browser::new_account(&harness.database).await;
    let intruder = Browser::sign_in(&harness.database, alice.user_id).await;
    let bob = Browser::new_account(&harness.database).await;
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
                .consume_for_rotation(token, std::slice::from_ref(&digest), client.as_str())
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
        .map(|stored| {
            (
                stored.actor,
                stored.event.known().cloned().expect("a known event"),
            )
        })
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
