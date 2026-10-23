//! Database-backed scenarios: what an export holds, what scheduling a deletion
//! ends, and who restores and purges accounts.

use super::*;
use crate::{
    AdminError, AdminService,
    jobs::AccountPurge,
    tests::{Browser, Replicas, change, operator, refresh_grant, register, registration},
};
use axum::http::Method;
use piquel_common::{
    ClientId, EmailId, PasskeyId, Provider, TokenId,
    clients::{ClientKind, ClientOwner},
    events::{JobName, RequestOrigin},
};
use piquel_repository::{
    InsertExternalIdentity, InsertPasskey, InsertVerifiedEmail, RefreshRotationError,
};
use serde_json::json;

/// The account routes over a migrated test database.
struct Accounts {
    /// The routes under test.
    router: Router,
    /// The scenario database.
    database: Database,
}

impl Accounts {
    /// Serves the account routes over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            router: AccountApplication::new(database.clone()).routes(),
            database,
        }
    }

    /// The events recorded about `user_id`, newest first, with their actors.
    async fn events(&self, user_id: UserId) -> Vec<(DomainEvent, Actor)> {
        self.database
            .events()
            .history_for_user(user_id, 20)
            .await
            .expect("history")
            .into_iter()
            .map(|stored| (stored.event.known().cloned().expect("known"), stored.actor))
            .collect()
    }

    /// The account `user_id`, if it still exists.
    async fn user(&self, user_id: UserId) -> Option<StoredUser> {
        self.database
            .users()
            .find_by_id(user_id)
            .await
            .expect("lookup")
    }

    /// The status of `user_id`, if the account still exists.
    async fn status(&self, user_id: UserId) -> Option<AccountStatus> {
        self.user(user_id).await.map(|user| user.status)
    }

    /// The handle of `browser`'s account.
    async fn handle(&self, browser: &Browser) -> String {
        self.user(browser.user_id).await.expect("account").username
    }

    /// Issues a refresh grant to a new client from `browser`'s session, and returns
    /// the client and its first refresh token's ID and digest.
    async fn grant(&self, browser: &Browser) -> (ClientId, TokenId, Vec<u8>) {
        let client = registration(ClientKind::Public, "https://client.example");
        register(&self.database, &client).await.expect("client");
        let (token, digest) = refresh_grant(
            &self.database,
            browser.user_id,
            browser.session_id,
            &client.id,
            TokenId::new(),
        )
        .await;
        (client.id, token, digest)
    }

    /// Registers a client `browser`'s account manages, and returns its ID.
    async fn own_client(&self, browser: &Browser) -> ClientId {
        let client = registration(ClientKind::Public, "https://owned.example");
        change(&self.database, async |registry| {
            registry
                .create(ClientOwner::Account(browser.user_id), &client, None)
                .await
        })
        .await
        .expect("owned client");
        client.id
    }

    /// Gives `browser`'s account one record of every category an export holds
    /// besides its sessions and history, and returns its grant's refresh token digest.
    async fn seed(&self, browser: &Browser) -> Vec<u8> {
        let handle = self.handle(browser).await;
        let mut tx = self.database.begin().await.expect("transaction");
        tx.emails()
            .insert_verified(&InsertVerifiedEmail {
                id: EmailId::new(),
                user_id: browser.user_id,
                normalized_email: format!("{handle}@example.com"),
                is_primary: true,
                verified_at: Utc::now(),
            })
            .await
            .expect("email");
        tx.passkeys()
            .insert(&InsertPasskey {
                id: PasskeyId::new(),
                credential_id: browser.user_id.as_uuid().as_bytes().to_vec(),
                user_id: browser.user_id,
                credential: json!({"cred": {
                    "backup_eligible": true,
                    "backup_state": false,
                    "key": "KEY-MATERIAL",
                }}),
                friendly_name: "Laptop".into(),
            })
            .await
            .expect("passkey");
        tx.federation()
            .insert_identity(&InsertExternalIdentity {
                id: TokenId::new(),
                user_id: browser.user_id,
                provider: Provider::GitHub,
                issuer: "https://github.com".into(),
                subject: browser.user_id.to_string(),
                linked_email: None,
            })
            .await
            .expect("identity");
        tx.commit().await.expect("commit");
        let (client, _, digest) = self.grant(browser).await;
        self.database
            .oidc()
            .save_consent(browser.user_id, &client, "test", &["openid".into()])
            .await
            .expect("consent");
        self.own_client(browser).await;
        digest
    }

    /// Asks to delete `browser`'s account, confirming with `handle`.
    async fn delete(&self, browser: &Browser, handle: &str) -> Response {
        let body = json!({"confirm_username": handle});
        browser
            .request(
                &self.router,
                Method::POST,
                routes::account::DELETION,
                Some(body),
            )
            .await
    }
}

/// `browser`'s user, acting from it.
const fn user(browser: &Browser) -> Actor {
    Actor::User {
        user_id: browser.user_id,
        session_id: Some(browser.session_id),
    }
}

/// An export needs a recent passkey confirmation, and is recorded. It holds every
/// category of the account's data and no credential, token or digest.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn exports_hold_every_category_and_no_secret() {
    let accounts = Accounts::new().await;
    let browser = Browser::new_account(&accounts.database).await;
    let handle = accounts.handle(&browser).await;
    let social = Browser::sign_in_with(
        &accounts.database,
        browser.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    let (status, refused) = social
        .call(&accounts.router, Method::GET, routes::account::EXPORT)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(refused["code"], "step_up_required");

    let digest = accounts.seed(&browser).await;

    let response = browser
        .request(&accounts.router, Method::GET, routes::account::EXPORT, None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let disposition = response.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .expect("disposition")
        .to_owned();
    let export = Browser::json(response).await;
    assert_eq!(
        disposition,
        format!(
            "attachment; filename=\"piquel-account-{handle}-{}.json\"",
            Utc::now().format("%Y-%m-%d")
        )
    );
    assert_eq!(
        (&export["format"], &export["version"]),
        (&json!("piquel.account-export"), &json!(1))
    );
    assert_eq!(export["profile"]["username"], handle.as_str());
    let count = |category: &str| export[category].as_array().map_or(0, Vec::len);
    for (category, expected) in [
        ("emails", 1),
        ("passkeys", 1),
        ("identities", 1),
        ("sessions", 2),
        ("consents", 1),
        ("grants", 1),
        ("clients", 1),
    ] {
        assert_eq!(count(category), expected, "{category}");
    }
    assert!(
        count("history") >= 2,
        "both sign-ins: {}",
        export["history"]
    );
    let passkey = export["passkeys"][0].as_object().expect("passkey");
    assert_eq!(
        passkey.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "backed_up",
            "backup_eligible",
            "created_at",
            "friendly_name",
            "id",
            "last_used_at"
        ]
    );
    assert_eq!(
        (&passkey["backup_eligible"], &passkey["backed_up"]),
        (&json!(true), &json!(false))
    );
    let text = export.to_string();
    for secret in ["KEY-MATERIAL", "digest", "secret", "credential"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    assert!(!text.contains(&serde_json::to_string(&digest).expect("digest")));
    assert_eq!(
        accounts.events(browser.user_id).await[0],
        (DomainEvent::AccountExported {}, user(&browser))
    );
}

/// Scheduling a deletion needs the account's handle and a recent passkey
/// confirmation. It signs every browser out, revokes every grant and leaves an
/// account that can no longer sign in.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn scheduling_ends_every_session_and_grant() {
    let accounts = Accounts::new().await;
    let browser = Browser::new_account(&accounts.database).await;
    let handle = accounts.handle(&browser).await;
    let other = Browser::sign_in(&accounts.database, browser.user_id).await;
    let social = Browser::sign_in_with(
        &accounts.database,
        browser.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    let (client, token, digest) = accounts.grant(&other).await;

    let refused = accounts.delete(&social, &handle).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let mismatch = accounts.delete(&browser, "someone-else").await;
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        accounts.status(browser.user_id).await,
        Some(AccountStatus::Active)
    );

    let response = accounts.delete(&browser, &handle).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cleared = response.headers()[header::SET_COOKIE]
        .to_str()
        .expect("cookie")
        .to_owned();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    let notice = Browser::json(response).await;
    let purge_after: DateTime<Utc> =
        serde_json::from_value(notice["purge_after"].clone()).expect("purge_after");
    let grace = purge_after - Utc::now();
    assert!(
        grace > Duration::days(29) && grace <= Duration::days(30),
        "{grace}"
    );

    assert_eq!(
        accounts.status(browser.user_id).await,
        Some(AccountStatus::Deleting)
    );
    for signed_in in [&browser, &other, &social] {
        assert!(
            accounts
                .database
                .sessions()
                .find_active_by_id(signed_in.session_id)
                .await
                .expect("lookup")
                .is_none()
        );
    }
    let mut tx = accounts.database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(token, &digest, client.as_str())
            .await,
        Err(RefreshRotationError::Invalid)
    ));
    assert!(
        security::Session::create(
            &mut tx,
            RequestContext::TEST,
            browser.user_id,
            AuthenticationMethod::Passkey
        )
        .await
        .is_err(),
        "an account scheduled for deletion cannot sign in"
    );
    drop(tx);

    let events = accounts.events(browser.user_id).await;
    let revoked = |signed_in: &Browser| {
        (
            DomainEvent::SessionRevoked {
                session_id: signed_in.session_id,
                reason: RevocationReason::AccountDeletion,
            },
            user(&browser),
        )
    };
    for expected in [revoked(&browser), revoked(&other), revoked(&social)] {
        assert!(
            events[..3].contains(&expected),
            "{expected:?} in {events:?}"
        );
    }
    assert_eq!(
        events[3],
        (
            DomainEvent::AccountDeletionScheduled { purge_after },
            user(&browser)
        )
    );
}

/// Operators schedule, restore and purge accounts as themselves. The purge job
/// leaves an account until its grace period ends, then deletes it as the system,
/// with the clients it manages, which stay as tombstones without an owner.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn operators_and_the_purge_job_delete_accounts() {
    let accounts = Accounts::new().await;
    let browser = Browser::new_account(&accounts.database).await;
    let owned = accounts.own_client(&browser).await;
    let admin = AdminService::new(accounts.database.clone());
    let cli = operator();
    let as_cli = operator().context().actor;

    admin
        .schedule_deletion(&cli, browser.user_id)
        .await
        .expect("schedule");
    assert!(matches!(
        admin.schedule_deletion(&cli, browser.user_id).await,
        Err(AdminError::Account(AccountError::NotActive))
    ));
    let early = accounts.database.begin().await.expect("transaction");
    AccountPurge::purge(early, browser.user_id)
        .await
        .expect("too early to purge");
    assert_eq!(
        accounts.status(browser.user_id).await,
        Some(AccountStatus::Deleting)
    );
    admin
        .restore_user(&cli, browser.user_id)
        .await
        .expect("restore");
    assert!(matches!(
        admin.restore_user(&cli, browser.user_id).await,
        Err(AdminError::Account(AccountError::NotScheduled))
    ));
    assert_eq!(
        accounts.status(browser.user_id).await,
        Some(AccountStatus::Active)
    );

    let mut tx = accounts.database.begin().await.expect("transaction");
    tx.users()
        .set_status(browser.user_id, AccountStatus::Deleting)
        .await
        .expect("status");
    tx.deletions()
        .schedule(browser.user_id, Utc::now() - Duration::seconds(1))
        .await
        .expect("due deletion");
    tx.commit().await.expect("commit");
    let due = accounts.database.begin().await.expect("transaction");
    AccountPurge::purge(due, browser.user_id)
        .await
        .expect("purge");
    assert_eq!(accounts.status(browser.user_id).await, None);
    let tombstone = accounts
        .database
        .oidc()
        .find_client(owned.as_str())
        .await
        .expect("lookup")
        .expect("tombstone");
    assert!(tombstone.deleted_at.is_some() && tombstone.owner_id.is_none());

    let kinds: Vec<_> = accounts
        .events(browser.user_id)
        .await
        .into_iter()
        .take(4)
        .map(|(event, actor)| (event.kind(), actor))
        .collect();
    let system = Actor::System {
        job: JobName::AccountPurge,
    };
    assert_eq!(
        kinds,
        [
            ("account_purged", system),
            ("account_restored", as_cli.clone()),
            ("session_revoked", as_cli.clone()),
            ("account_deletion_scheduled", as_cli),
        ]
    );
}

/// The CLI purges an account at once, in any status, as the operator, and the
/// purge erases the personal data of the events it leaves.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_cli_purges_disabled_accounts_at_once() {
    let accounts = Accounts::new().await;
    let admin = AdminService::new(accounts.database.clone());
    let cli = operator();
    let disabled = Browser::new_account(&accounts.database).await;
    admin
        .disable_user(
            &cli,
            disabled.user_id,
            crate::admin::Reason::parse("Abuse".into()).expect("reason"),
        )
        .await
        .expect("disable");
    assert!(matches!(
        admin.schedule_deletion(&cli, disabled.user_id).await,
        Err(AdminError::Account(AccountError::NotActive))
    ));
    admin
        .purge_user(&cli, disabled.user_id)
        .await
        .expect("immediate purge");
    assert_eq!(accounts.status(disabled.user_id).await, None);
    assert_eq!(
        accounts.events(disabled.user_id).await[0],
        (DomainEvent::AccountPurged {}, operator().context().actor)
    );
    // The purge erased the personal data of the events it left, and kept none of its own.
    let stored = accounts
        .database
        .events()
        .history_for_user(disabled.user_id, 20)
        .await
        .expect("history");
    assert!(
        stored
            .iter()
            .all(|event| event.origin == piquel_common::Personal::<RequestOrigin>::Erased)
    );
}
