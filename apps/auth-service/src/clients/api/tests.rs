//! Database-backed scenarios: whose clients an account sees and changes, which
//! changes need a passkey confirmation, what owners may never set, and what a
//! deletion leaves behind.

use super::*;
use crate::{
    ClientRegistryError, GracePeriod,
    security::Session,
    tests::{
        Browser, Replicas, change, refresh_grant, register, registration, sign_out, until_blocked,
    },
};
use axum::http::Method;
use piquel_common::{
    AuthenticationMethod, ClientId, TokenId,
    clients::{ClientKind, ClientRegistration},
    events::{Actor, DomainEvent},
};
use piquel_repository::RefreshRotationError;
use serde_json::json;

/// The client routes over the test database.
struct Harness {
    /// Routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
}

impl Harness {
    /// Builds the client routes over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            router: ClientApplication::new(database.clone()).routes(),
            database,
        }
    }

    /// Registers a client of `kind` as `browser`, and returns its ID.
    async fn create(&self, browser: &Browser, kind: &str) -> String {
        let (status, body) = browser
            .send(
                &self.router,
                Method::POST,
                "/account/clients",
                Some(json!({
                    "kind": kind,
                    "display_name": "Notes",
                    "redirect_uris": ["https://notes.example/callback"],
                    "allowed_scopes": ["openid", "offline_access"],
                    "allow_refresh": true,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().expect("client ID").to_owned()
    }
}

/// An account lists, shows and changes only its own clients. Another account's
/// client, and a client operators manage, answer 404 to every route, as an
/// unknown or malformed ID does, before the body is read.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn accounts_manage_only_their_own_clients() {
    let harness = Harness::new().await;
    let (alice, bob) = (
        Browser::new_account(&harness.database).await,
        Browser::new_account(&harness.database).await,
    );
    let operated = registration(ClientKind::Public, "https://operated.example");
    register(&harness.database, &operated)
        .await
        .expect("operator client");

    let id = harness.create(&alice, "confidential").await;
    assert!(id.starts_with("c_"), "{id}");
    let (status, list) = alice
        .send(&harness.router, Method::GET, "/account/clients", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        list.as_array()
            .expect("list")
            .iter()
            .map(|client| client["id"].as_str())
            .collect::<Vec<_>>(),
        [Some(id.as_str())]
    );
    let (status, details) = alice
        .send(
            &harness.router,
            Method::GET,
            &format!("/account/clients/{id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(details["secrets"].as_array().map(Vec::len), Some(1));

    let (_, list) = bob
        .send(&harness.router, Method::GET, "/account/clients", None)
        .await;
    assert_eq!(list, json!([]));
    for (browser, id) in [
        (&bob, id.as_str()),
        (&alice, operated.id.as_str()),
        (&alice, "c_unknown"),
        (&alice, "%FF"),
    ] {
        let item = format!("/account/clients/{id}");
        for (method, path, body) in [
            (Method::GET, item.clone(), None),
            (
                Method::PATCH,
                item.clone(),
                Some(json!({"display_name": "Mine"})),
            ),
            (
                Method::PATCH,
                item.clone(),
                Some(json!({"display_name": 17})),
            ),
            (Method::DELETE, item.clone(), None),
            (Method::POST, format!("{item}/disable"), None),
            (Method::POST, format!("{item}/secrets"), Some(json!({}))),
            (
                Method::POST,
                format!("{item}/secrets"),
                Some(json!({"grace": "x"})),
            ),
        ] {
            let (status, body) = browser
                .send(&harness.router, method.clone(), &path, body)
                .await;
            assert_eq!(
                (status, body["error"].is_string()),
                (StatusCode::NOT_FOUND, true),
                "{method} {path}"
            );
        }
    }
    let client = harness
        .database
        .oidc()
        .find_client(&id)
        .await
        .expect("lookup")
        .expect("client");
    assert_eq!(client.display_name, "Notes", "bob's change did nothing");
    assert!(client.enabled && client.deleted_at.is_none());
}

/// Registering, deleting, rotating a secret and changing redirect or post-logout
/// URIs need a recent passkey confirmation; a refused change leaves the client as
/// it was. Renaming and pausing need only the session.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sensitive_changes_need_a_recent_confirmation() {
    let harness = Harness::new().await;
    let confirmed = Browser::new_account(&harness.database).await;
    let social = Browser::sign_in_with(
        &harness.database,
        confirmed.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    let id = harness.create(&confirmed, "confidential").await;
    let item = format!("/account/clients/{id}");
    let step_up = json!({
        "error": "Confirm with your passkey to continue.",
        "code": "step_up_required",
        "max_age": crate::security::CONFIRMATION_MAX_AGE,
    });
    let new = json!({
        "kind": "public",
        "display_name": "Other",
        "redirect_uris": ["https://other.example/callback"],
    });
    // Asked before the settings are read, even invalid ones.
    let invalid = json!({"kind": "public", "display_name": "", "redirect_uris": ["not a URI"]});
    let list = "/account/clients".to_owned();
    for (method, path, body) in [
        (Method::POST, list.clone(), Some(new)),
        (Method::POST, list, Some(invalid)),
        (
            Method::PATCH,
            item.clone(),
            Some(json!({"redirect_uris": ["https://attacker.example/callback"]})),
        ),
        (
            Method::PATCH,
            item.clone(),
            Some(json!({"post_logout_uris": ["https://attacker.example/"]})),
        ),
        (Method::POST, format!("{item}/secrets"), Some(json!({}))),
        (Method::DELETE, item.clone(), None),
    ] {
        let (status, body) = social
            .send(&harness.router, method.clone(), &path, body)
            .await;
        assert_eq!(
            (status, body),
            (StatusCode::FORBIDDEN, step_up.clone()),
            "{method} {path}"
        );
    }
    let (status, client) = social
        .send(
            &harness.router,
            Method::PATCH,
            &item,
            Some(json!({"display_name": "Renamed"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(client["display_name"], "Renamed");
    assert_eq!(
        client["redirect_uris"],
        json!(["https://notes.example/callback"]),
        "the refused change was rolled back"
    );
    assert_eq!(client["post_logout_uris"], json!([]));
    let (status, _) = social
        .send(
            &harness.router,
            Method::POST,
            &format!("{item}/disable"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, rotated) = confirmed
        .send(
            &harness.router,
            Method::POST,
            &format!("{item}/secrets"),
            Some(json!({"grace": "0"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        rotated["client_secret"]
            .as_str()
            .is_some_and(|secret| secret.starts_with("pqcs_"))
    );
    let (status, client) = confirmed
        .send(
            &harness.router,
            Method::PATCH,
            &item,
            Some(json!({"redirect_uris": ["https://notes.example/auth"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        client["redirect_uris"],
        json!(["https://notes.example/auth"])
    );
}

/// A request sent with a cookie its session had before a passkey confirmation
/// never gains that confirmation, even when it commits while the request waits
/// for the account lock: the confirmation replaced the cookie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn confirmations_never_reach_requests_sent_before_them() {
    let harness = Harness::new().await;
    let owner = Browser::new_account(&harness.database).await;
    let id = harness.create(&owner, "confidential").await;
    let item = format!("/account/clients/{id}");
    for (method, path, body) in [
        (
            Method::PATCH,
            item.clone(),
            Some(json!({"redirect_uris": ["https://attacker.example/callback"]})),
        ),
        (Method::POST, format!("{item}/secrets"), Some(json!({}))),
        (Method::DELETE, item.clone(), None),
    ] {
        let stale = Browser::sign_in_with(
            &harness.database,
            owner.user_id,
            AuthenticationMethod::Federation,
        )
        .await;
        let mut holder = harness.database.begin().await.expect("transaction");
        holder
            .users()
            .find_active_by_id_for_update(owner.user_id)
            .await
            .expect("lock")
            .expect("account");
        let ((status, _), ()) = tokio::join!(
            stale.send(&harness.router, method.clone(), &path, body),
            async {
                until_blocked(&mut holder, 1).await;
                let session = holder
                    .sessions()
                    .find_by_id(stale.session_id)
                    .await
                    .expect("lookup")
                    .expect("session");
                Session::reauthenticate(
                    &mut holder,
                    &session,
                    AuthenticationMethod::Passkey.into(),
                )
                .await
                .expect("confirm");
                holder.commit().await.expect("commit");
            },
        );
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }
    let client = harness
        .database
        .oidc()
        .find_client(&id)
        .await
        .expect("lookup")
        .expect("client");
    assert_eq!(client.redirect_uris, ["https://notes.example/callback"]);
    assert!(client.deleted_at.is_none());
    let secrets = harness
        .database
        .oidc()
        .client_secrets(&client.id)
        .await
        .expect("secrets");
    assert_eq!(secrets.len(), 1, "no secret was added");
}

/// No body makes an owner's client trusted, and owners may grant only the
/// standard scopes. Invalid settings name their field with RFC 7591's codes.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owned_clients_are_never_trusted_and_get_only_standard_scopes() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    let (status, client) = alice
        .send(
            &harness.router,
            Method::POST,
            "/account/clients",
            Some(json!({
                "kind": "public",
                "display_name": "Notes",
                "redirect_uris": ["https://notes.example/callback"],
                "trusted": true,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(client["trusted"], false);
    assert_eq!(
        client["allowed_scopes"],
        json!(["openid", "profile", "email"])
    );
    let item = format!("/account/clients/{}", client["id"].as_str().expect("ID"));
    let (status, client) = alice
        .send(
            &harness.router,
            Method::PATCH,
            &item,
            Some(json!({"trusted": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(client["trusted"], false);

    for (body, code, field) in [
        (
            json!({"allowed_scopes": ["openid", "notes:read"]}),
            "invalid_client_metadata",
            "allowed_scopes",
        ),
        (
            json!({"redirect_uris": ["http://notes.example/callback"]}),
            "invalid_redirect_uri",
            "redirect_uris",
        ),
        (
            json!({"redirect_uris": []}),
            "invalid_redirect_uri",
            "redirect_uris",
        ),
        (
            json!({"display_name": " "}),
            "invalid_client_metadata",
            "display_name",
        ),
    ] {
        let (status, error) = alice
            .send(&harness.router, Method::PATCH, &item, Some(body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(
            (error["code"].as_str(), error["field"].as_str()),
            (Some(code), Some(field))
        );
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|message| message.starts_with(field))
        );
    }
}

/// Deleting a client revokes its refresh tokens, removes its secrets and leaves a
/// disabled tombstone. Its ID can never be registered, applied, enabled, changed
/// or deleted again, by the account or an operator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deleted_clients_stay_deleted() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    let id = harness.create(&alice, "confidential").await;
    let client_id: ClientId = id.parse().expect("client ID");
    let (token, digest) = refresh_grant(
        &harness.database,
        alice.user_id,
        alice.session_id,
        &client_id,
        TokenId::new(),
    )
    .await;

    let item = format!("/account/clients/{id}");
    let (status, _) = alice
        .send(&harness.router, Method::DELETE, &item, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = alice.send(&harness.router, Method::GET, &item, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, list) = alice
        .send(&harness.router, Method::GET, "/account/clients", None)
        .await;
    assert_eq!(list, json!([]));

    let mut tx = harness.database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(token, std::slice::from_ref(&digest), client_id.as_str())
            .await,
        Err(RefreshRotationError::Invalid)
    ));
    drop(tx);
    let oidc = &mut harness.database.oidc();
    let tombstone = oidc.find_client(&id).await.expect("lookup").expect("row");
    assert!(tombstone.deleted_at.is_some() && !tombstone.enabled);
    assert_eq!(oidc.client_secrets(&client_id).await.expect("secrets"), []);
    let history = harness
        .database
        .events()
        .history_for_client(&client_id, 1)
        .await
        .expect("history");
    assert_eq!(
        (history[0].event.known(), &history[0].actor),
        (
            Some(&DomainEvent::ClientDeleted {
                client_id: client_id.clone()
            }),
            &Actor::User {
                user_id: alice.user_id,
                session_id: Some(alice.session_id),
            }
        )
    );

    let reused = ClientRegistration {
        id: client_id.clone(),
        ..registration(ClientKind::Confidential, "https://notes.example")
    };
    assert!(matches!(
        register(&harness.database, &reused).await,
        Err(ClientRegistryError::Exists { .. })
    ));
    let secret = Some(piquel_crypto::ClientSecret::generate().expect("secret"));
    assert!(matches!(
        change(&harness.database, async |registry| {
            registry
                .apply(&reused, secret, GracePeriod::default())
                .await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
    assert!(matches!(
        change(&harness.database, async |registry| {
            registry.set_enabled(&client_id, true).await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
    assert!(matches!(
        change(&harness.database, async |registry| {
            registry.delete(&client_id).await
        })
        .await,
        Err(ClientRegistryError::Deleted(_))
    ));
}

/// A deletion and a refresh rotation lock a family and the client in the same
/// order, so they never deadlock. Here a transaction holds one family of the
/// client while the deletion waits for it, then rotates another family, which
/// locks the client: the deletion must not be holding it yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_and_refresh_rotation_never_deadlock() {
    let harness = Harness::new().await;
    let (owner, user) = (
        Browser::new_account(&harness.database).await,
        Browser::new_account(&harness.database).await,
    );
    let client_id: ClientId = harness
        .create(&owner, "public")
        .await
        .parse()
        .expect("client ID");
    let grant = async || {
        refresh_grant(
            &harness.database,
            user.user_id,
            user.session_id,
            &client_id,
            TokenId::new(),
        )
        .await
    };
    let (held, held_digest) = grant().await;
    let (rotated, rotated_digest) = grant().await;

    let mut holder = harness.database.begin().await.expect("transaction");
    holder
        .tokens()
        .revoke_family_for_token(held, std::slice::from_ref(&held_digest))
        .await
        .expect("hold the first family");
    let deletion = tokio::spawn({
        let (database, id) = (harness.database.clone(), client_id.clone());
        async move { change(&database, async |registry| registry.delete(&id).await).await }
    });
    until_blocked(&mut holder, 1).await;
    holder
        .tokens()
        .consume_for_rotation(
            rotated,
            std::slice::from_ref(&rotated_digest),
            client_id.as_str(),
        )
        .await
        .expect("the rotation locks the client while the deletion waits");
    holder.commit().await.expect("commit");
    deletion
        .await
        .expect("task")
        .expect("the deletion follows the rotation");

    let mut tx = harness.database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(
                rotated,
                std::slice::from_ref(&rotated_digest),
                client_id.as_str()
            )
            .await,
        Err(RefreshRotationError::Invalid | RefreshRotationError::Replay { .. })
    ));
}

/// A family granted after a deletion locked the client's families is locked by
/// no one else but a rotation that will find the client deleted, so the deletion
/// skips it instead of waiting, which could deadlock with that rotation. Here the
/// deletion queues behind a held family while the grant commits, then a second
/// transaction holds the new family.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_skips_families_granted_while_it_waits() {
    let harness = Harness::new().await;
    let (owner, user) = (
        Browser::new_account(&harness.database).await,
        Browser::new_account(&harness.database).await,
    );
    let client_id: ClientId = harness
        .create(&owner, "public")
        .await
        .parse()
        .expect("client ID");
    let grant = async |family: TokenId| {
        refresh_grant(
            &harness.database,
            user.user_id,
            user.session_id,
            &client_id,
            family,
        )
        .await
    };
    let (held, fresh) = (TokenId::new(), TokenId::new());
    grant(held).await;
    let mut holder = harness.database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_family(held)
        .await
        .expect("hold the family");
    let deletion = tokio::spawn({
        let (database, id) = (harness.database.clone(), client_id.clone());
        async move { change(&database, async |registry| registry.delete(&id).await).await }
    });
    until_blocked(&mut holder, 1).await;
    let (token, digest) = grant(fresh).await;
    let mut rotation = harness.database.begin().await.expect("transaction");
    rotation
        .tokens()
        .lock_family(fresh)
        .await
        .expect("hold the fresh family");
    holder.commit().await.expect("commit");
    tokio::time::timeout(std::time::Duration::from_secs(10), deletion)
        .await
        .expect("the deletion does not wait for the fresh family")
        .expect("task")
        .expect("deletion");
    assert!(matches!(
        rotation
            .tokens()
            .consume_for_rotation(token, std::slice::from_ref(&digest), client_id.as_str())
            .await,
        Err(RefreshRotationError::Invalid)
    ));
}

/// A deletion and a logout that share families lock them in the same order, so
/// they never deadlock. The families are inserted highest ID first, so a scan
/// meets them out of ID order; a transaction holds the lowest while the deletion,
/// then the logout, queue for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deletion_and_logout_never_deadlock() {
    let harness = Harness::new().await;
    let (owner, user) = (
        Browser::new_account(&harness.database).await,
        Browser::new_account(&harness.database).await,
    );
    let client_id: ClientId = harness
        .create(&owner, "public")
        .await
        .parse()
        .expect("client ID");
    let (low, high) = (TokenId::new(), TokenId::new());
    for family in [high, low] {
        refresh_grant(
            &harness.database,
            user.user_id,
            user.session_id,
            &client_id,
            family,
        )
        .await;
    }

    let mut holder = harness.database.begin().await.expect("transaction");
    holder
        .tokens()
        .lock_family(low)
        .await
        .expect("hold the lowest family");
    let deletion = tokio::spawn({
        let (database, id) = (harness.database.clone(), client_id.clone());
        async move { change(&database, async |registry| registry.delete(&id).await).await }
    });
    until_blocked(&mut holder, 1).await;
    let logout = tokio::spawn({
        let (database, user, session) = (harness.database.clone(), user.user_id, user.session_id);
        async move {
            let mut tx = database.begin().await?;
            sign_out(&mut tx, user, session).await?;
            tx.commit().await
        }
    });
    until_blocked(&mut holder, 2).await;
    holder.commit().await.expect("commit");
    deletion.await.expect("task").expect("deletion");
    logout.await.expect("task").expect("logout");
}

/// An operator's suspension disables a client, and its owner cannot enable it,
/// though they can still see and disable it. Lifting the suspension leaves it
/// disabled, for the owner to enable.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_cannot_enable_a_suspended_client() {
    let harness = Harness::new().await;
    let alice = Browser::new_account(&harness.database).await;
    let id = harness.create(&alice, "public").await;
    let client_id: ClientId = id.parse().expect("client ID");
    let item = format!("/account/clients/{id}");
    let suspend = async |suspended: bool| {
        change(&harness.database, async |registry| {
            registry.set_suspended(&client_id, suspended).await
        })
        .await
        .expect("suspension");
    };
    suspend(true).await;
    let (status, client) = alice.send(&harness.router, Method::GET, &item, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(client["suspended_at"].is_string() && client["enabled"] == false);
    let (status, error) = alice
        .send(
            &harness.router,
            Method::POST,
            &format!("{item}/enable"),
            None,
        )
        .await;
    assert_eq!(
        (status, error["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("client_suspended"))
    );
    assert!(matches!(
        change(&harness.database, async |registry| {
            registry.set_enabled(&client_id, true).await
        })
        .await,
        Err(ClientRegistryError::Suspended(_)),
    ));
    let (status, _) = alice
        .send(
            &harness.router,
            Method::POST,
            &format!("{item}/disable"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    suspend(false).await;
    let (_, client) = alice.send(&harness.router, Method::GET, &item, None).await;
    assert!(client["suspended_at"].is_null() && client["enabled"] == false);
    let (status, _) = alice
        .send(
            &harness.router,
            Method::POST,
            &format!("{item}/enable"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}
