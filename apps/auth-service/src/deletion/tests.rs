//! Database-backed scenarios: what an export holds, what a deletion ends, who
//! restores and purges accounts, and how a restore offer restores one once.

use super::*;
use crate::{
    AdminError, AdminService, Reason,
    jobs::AccountPurge,
    security::SessionError,
    tests::{Browser, Replicas, change, operator, refresh_grant, register, registration},
};
use axum::http::header;
use piquel_common::{
    AuthenticationMethod, EmailId, Provider, TokenId,
    clients::{ClientKind, ClientOwner},
    events::{JobName, RequestOrigin},
};
use piquel_repository::{
    Database, InsertExternalIdentity, InsertPasskey, InsertVerifiedEmail, RefreshRotationError,
};
use serde_json::json;

/// The scenario database, and the operations under test.
struct Fixture {
    /// The scenario database.
    database: Database,
    /// The owner's operations.
    account: AccountService,
    /// The operators' operations.
    admin: AdminService,
}

impl Fixture {
    /// The operations over a migrated test database.
    async fn new() -> Self {
        let database = Replicas::database().await;
        Self {
            account: AccountService::new(database.clone()),
            admin: AdminService::new(database.clone(), true),
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
        self.user(browser.user_id)
            .await
            .expect("account")
            .handle
            .to_string()
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
    /// besides its sessions and history, and returns its grant's refresh token
    /// digest.
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

    /// Makes the account due for its purge, as though its grace period ended.
    async fn due(&self, user_id: UserId) {
        let mut tx = self.database.begin().await.expect("transaction");
        tx.users()
            .set_status(user_id, AccountStatus::Deleting)
            .await
            .expect("status");
        tx.deletions()
            .schedule(user_id, Utc::now() - Duration::seconds(1))
            .await
            .expect("due deletion");
        tx.commit().await.expect("commit");
    }
}

/// `browser`'s user, acting from it.
const fn user(browser: &Browser) -> Actor {
    Actor::User {
        user_id: browser.user_id,
        session_id: Some(browser.session_id),
    }
}

/// Why the scenarios' operators act.
fn reason() -> Reason {
    Reason::parse("Asked by email".into()).expect("reason")
}

/// An export needs a recent passkey confirmation, and is recorded. It holds every
/// category of the account's data and no credential, token or digest.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn exports_hold_every_category_and_no_secret() {
    let fixture = Fixture::new().await;
    let browser = Browser::new_account(&fixture.database).await;
    let social = Browser::sign_in_with(
        &fixture.database,
        browser.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    assert!(matches!(
        fixture
            .account
            .export(&social.owner(&fixture.database).await)
            .await,
        Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
    ));

    let digest = fixture.seed(&browser).await;
    let export = fixture
        .account
        .export(&browser.owner(&fixture.database).await)
        .await
        .expect("export");
    let handle = fixture.handle(&browser).await;
    assert_eq!(
        export.file_name(),
        format!(
            "piquel-account-{handle}-{}.json",
            Utc::now().format("%Y-%m-%d")
        )
    );
    let export = serde_json::to_value(export).expect("JSON");
    assert_eq!(
        (&export["format"], &export["version"]),
        (&json!("piquel.account-export"), &json!(1))
    );
    assert_eq!(export["profile"]["handle"], handle.as_str());
    let count = |category: &str| export[category].as_array().map_or(0, Vec::len);
    for (category, expected) in [
        ("handles", 1),
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
    let text = export.to_string();
    for secret in ["KEY-MATERIAL", "digest", "secret", "credential"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    assert!(!text.contains(&serde_json::to_string(&digest).expect("digest")));
    assert_eq!(
        fixture.events(browser.user_id).await[0],
        (DomainEvent::AccountExported {}, user(&browser))
    );
}

/// Deleting needs the account's handle and a recent passkey confirmation. It signs
/// every browser out, revokes every grant and leaves an account that can no longer
/// sign in.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn deleting_ends_every_session_and_grant() {
    let fixture = Fixture::new().await;
    let browser = Browser::new_account(&fixture.database).await;
    let handle = fixture.handle(&browser).await;
    let other = Browser::sign_in(&fixture.database, browser.user_id).await;
    let social = Browser::sign_in_with(
        &fixture.database,
        browser.user_id,
        AuthenticationMethod::Federation,
    )
    .await;
    let (client, token, digest) = fixture.grant(&other).await;
    let owner = browser.owner(&fixture.database).await;

    assert!(matches!(
        fixture
            .account
            .delete_account(&social.owner(&fixture.database).await, &handle)
            .await,
        Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
    ));
    assert!(matches!(
        fixture.account.delete_account(&owner, "someone-else").await,
        Err(AccountError::Deletion(DeletionError::HandleMismatch))
    ));
    assert_eq!(
        fixture.status(browser.user_id).await,
        Some(AccountStatus::Active)
    );

    let deleted = fixture
        .account
        .delete_account(&owner, &handle)
        .await
        .expect("delete");
    let grace = deleted.purge_after - Utc::now();
    assert!(
        grace > Duration::days(29) && grace <= Duration::days(GRACE_PERIOD_DAYS),
        "{grace}"
    );

    assert_eq!(
        fixture.status(browser.user_id).await,
        Some(AccountStatus::Deleting)
    );
    for signed_in in [&browser, &other, &social] {
        assert!(
            fixture
                .database
                .sessions()
                .find_active_by_id(signed_in.session_id)
                .await
                .expect("lookup")
                .is_none()
        );
    }
    let mut tx = fixture.database.begin().await.expect("transaction");
    assert!(matches!(
        tx.tokens()
            .consume_for_rotation(token, &[digest], client.as_str())
            .await,
        Err(RefreshRotationError::Invalid)
    ));
    assert!(
        Session::create(
            &mut tx,
            RequestContext::TEST,
            browser.user_id,
            AuthenticationMethod::Passkey.into()
        )
        .await
        .is_err(),
        "an account scheduled for deletion cannot sign in"
    );
    drop(tx);

    let events = fixture.events(browser.user_id).await;
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
            DomainEvent::AccountDeletionScheduled {
                purge_after: deleted.purge_after
            },
            user(&browser)
        )
    );
}

/// A passkey sign-in's offer restores the account once, and signs the browser in
/// with that passkey. Declining it forgets the offer and leaves the deletion.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_restore_offer_restores_the_account_once() {
    let fixture = Fixture::new().await;
    let browser = Browser::new_account(&fixture.database).await;
    let stored = crate::tests::unusable_passkey(browser.user_id);
    let passkey = stored.id;
    fixture
        .database
        .passkeys()
        .insert(&stored)
        .await
        .expect("passkey");
    let handle = fixture.handle(&browser).await;
    let _signed_out = fixture
        .account
        .delete_account(&browser.owner(&fixture.database).await, &handle)
        .await
        .expect("delete");

    let mut tx = fixture.database.begin().await.expect("transaction");
    tx.users()
        .find_by_id_for_update(browser.user_id)
        .await
        .expect("lock");
    let offered = Deletions::offer_restore(tx, browser.user_id, passkey)
        .await
        .expect("offer");
    let mut response = axum::http::Response::new(());
    offered.set_on(&mut response).expect("cookie");
    let (name, value) = response.headers()[header::SET_COOKIE]
        .to_str()
        .expect("cookie")
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .expect("cookie pair");
    assert_eq!(name, BrowserCookie::Restore.as_str());
    let holding = Browser::signed_out().with_cookie(BrowserCookie::Restore, value);

    assert!(
        fixture
            .account
            .restore_offer(&Browser::signed_out().headers())
            .await
            .expect("no offer")
            .is_none()
    );
    let offer = fixture
        .account
        .restore_offer(&holding.headers())
        .await
        .expect("offer")
        .expect("valid");
    assert_eq!(offer.handle, handle);

    let restored = fixture
        .account
        .restore(RequestContext::TEST, &holding.headers())
        .await
        .expect("restore");
    let mut response = axum::http::Response::new(());
    restored.set_on(&mut response).expect("cookies");
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|cookie| cookie.to_str().expect("cookie").to_owned())
        .collect();
    assert!(
        cookies[0].starts_with(BrowserCookie::Restore.as_str()) && cookies[0].contains("Max-Age=0")
    );
    assert!(cookies[1].starts_with(BrowserCookie::Session.as_str()));
    assert_eq!(
        fixture.status(browser.user_id).await,
        Some(AccountStatus::Active)
    );
    let [session] = <[_; 1]>::try_from(
        fixture
            .database
            .sessions()
            .list_active_for_user(browser.user_id)
            .await
            .expect("sessions"),
    )
    .expect("one session");
    assert_eq!(
        fixture
            .database
            .sessions()
            .passkey(session.id)
            .await
            .expect("passkey"),
        Some(passkey),
        "signed in with the offer's passkey"
    );
    assert!(matches!(
        fixture
            .account
            .restore(RequestContext::TEST, &holding.headers())
            .await,
        Err(AccountError::Deletion(DeletionError::RestoreExpired))
    ));
}

/// Operators schedule, restore and purge accounts as themselves, with their reason.
/// The purge job leaves an account until its grace period ends, then deletes it as
/// the system, with the clients it manages, which stay as tombstones without an
/// owner.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn operators_and_the_purge_job_delete_accounts() {
    let fixture = Fixture::new().await;
    let browser = Browser::new_account(&fixture.database).await;
    let owned = fixture.own_client(&browser).await;
    let cli = operator();
    let as_cli = operator().context().actor;

    fixture
        .admin
        .schedule_deletion(&cli, browser.user_id, reason())
        .await
        .expect("schedule");
    assert!(matches!(
        fixture
            .admin
            .schedule_deletion(&cli, browser.user_id, reason())
            .await,
        Err(AdminError::Deletion(DeletionError::NotActive))
    ));
    assert!(matches!(
        fixture
            .admin
            .disable_user(&cli, browser.user_id, reason())
            .await,
        Err(AdminError::DeletionScheduled)
    ));
    let early = fixture.database.begin().await.expect("transaction");
    AccountPurge::purge(early, browser.user_id)
        .await
        .expect("too early to purge");
    assert_eq!(
        fixture.status(browser.user_id).await,
        Some(AccountStatus::Deleting)
    );
    fixture
        .admin
        .restore_user(&cli, browser.user_id, reason())
        .await
        .expect("restore");
    assert!(matches!(
        fixture
            .admin
            .restore_user(&cli, browser.user_id, reason())
            .await,
        Err(AdminError::Deletion(DeletionError::NotScheduled))
    ));

    fixture.due(browser.user_id).await;
    let due = fixture.database.begin().await.expect("transaction");
    AccountPurge::purge(due, browser.user_id)
        .await
        .expect("purge");
    assert_eq!(fixture.status(browser.user_id).await, None);
    let tombstone = fixture
        .database
        .oidc()
        .find_client(owned.as_str())
        .await
        .expect("lookup")
        .expect("tombstone");
    assert!(tombstone.deleted_at.is_some() && tombstone.owner_id.is_none());

    let kinds: Vec<_> = fixture
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

/// The CLI purges an account at once, in any status, as the operator, and the purge
/// erases the personal data of the events it leaves. Nobody deletes the last
/// active administrator's account.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_cli_purges_disabled_accounts_at_once() {
    let fixture = Fixture::new().await;
    let cli = operator();
    let disabled = Browser::new_account(&fixture.database).await;
    fixture
        .admin
        .disable_user(&cli, disabled.user_id, reason())
        .await
        .expect("disable");
    assert!(matches!(
        fixture
            .admin
            .schedule_deletion(&cli, disabled.user_id, reason())
            .await,
        Err(AdminError::Deletion(DeletionError::NotActive))
    ));
    fixture
        .admin
        .purge_user(&cli, disabled.user_id, reason())
        .await
        .expect("immediate purge");
    assert_eq!(fixture.status(disabled.user_id).await, None);
    assert_eq!(
        fixture.events(disabled.user_id).await[0],
        (DomainEvent::AccountPurged {}, operator().context().actor)
    );
    let stored = fixture
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
