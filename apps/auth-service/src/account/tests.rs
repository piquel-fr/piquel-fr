//! Database-backed scenarios of [`AccountService`]: what administrators may change
//! on another account, how it is recorded and what refuses them, and what owners
//! must confirm.

use super::*;
use crate::{
    AdminError, GracePeriod, Operator, Reason,
    admin::tests::{Account, Harness, assert_refused, cli, operator},
    config::EmailConfig,
    passkey::PasskeyError,
    security::ApiError,
    security::CONFIRMATION_MAX_AGE,
    tests::{Browser, Replicas, change, registration, sign_out, until_blocked},
};
use axum::{
    Router,
    extract::{FromRef, Path, State},
    http::Method,
    routing::{delete, post},
};
use chrono::{Duration, Utc};
use piquel_common::clients::{ClientId, ClientKind, ClientOwner};
use piquel_common::{
    AuthenticationMethod, EmailId, Provider, TokenId, UserId,
    events::{Actor, DomainEvent, RevocationReason},
    protocol::step_up::StepUpRequirement,
};
use piquel_crypto::Secret;
use piquel_repository::InsertVerifiedEmail;
use piquel_repository::{InsertExternalIdentity, InsertPasskey};
use serde_json::json;
use std::{fmt::Debug, mem::discriminant};

/// The reason the scenarios give.
const REASON: &str = "Le propriétaire a perdu son téléphone";

/// The test database, its accounts, and an administrator signed in with a passkey.
struct Fixture {
    /// Creates accounts and administrators.
    harness: Harness,
    /// The acting administrator.
    admin: Account,
    /// The operations under test.
    service: AccountService,
}

impl Fixture {
    /// Signs an administrator in over the test database.
    async fn new() -> Self {
        let harness = Harness::new().await;
        let admin = harness.admin().await;
        let service = AccountService::new(harness.database.clone());
        Self {
            harness,
            admin,
            service,
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

    /// The administrator, signed in with a passkey `age` ago.
    fn operator(&self, age: Duration) -> Operator {
        operator(self.admin, Utc::now() - age)
    }

    /// Renames `user`'s `passkey` as `operator`, for [`REASON`].
    async fn rename(
        &self,
        operator: Operator,
        user: UserId,
        passkey: PasskeyId,
    ) -> Result<(), AccountError> {
        let subject = Subject::operator(user, operator, reason());
        self.service
            .rename_passkey(&subject, passkey, "Renamed".into())
            .await
    }

    /// The names of `user`'s active passkeys.
    async fn names(&self, user: UserId) -> Vec<String> {
        let passkeys = self.harness.database.passkeys().list_active(user).await;
        passkeys
            .expect("passkeys")
            .into_iter()
            .map(|passkey| passkey.friendly_name)
            .collect()
    }
}

/// [`REASON`], validated.
fn reason() -> Reason {
    Reason::parse(REASON.into()).expect("reason")
}

/// An administrator renames and removes another account's passkey and unlinks its
/// identity, with the owner's own operations. Each change is recorded as the
/// administrator's, with the reason as personal data, and the owner sees who
/// acted and why in their history.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_change_another_account_on_its_behalf() {
    let fixture = Fixture::new().await;
    let (target, passkeys) = fixture.target(2).await;
    let user = target.user_id;
    let admin = || fixture.operator(Duration::seconds(10));
    let service = &fixture.service;
    let subject = Subject::operator(user, admin(), reason());
    service
        .rename_passkey(&subject, passkeys[0], "Lost phone".into())
        .await
        .expect("rename");
    let confirmed = || Subject::operator(user, admin(), reason());
    service
        .revoke_passkey(&confirmed(), passkeys[1])
        .await
        .expect("remove");
    service
        .unlink_identity(&confirmed(), Provider::GitHub)
        .await
        .expect("unlink");

    assert_eq!(fixture.names(user).await, ["Lost phone"]);
    let database = &fixture.harness.database;
    let identities = database.federation().list_active(user).await;
    assert_eq!(identities.expect("identities").len(), 0, "unlinked");
    let history = database
        .events()
        .history_for_user(user, 20)
        .await
        .expect("history");
    let actor = Actor::Admin {
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
        // An administrator has none of the owner's sessions to keep.
        DomainEvent::SessionRevoked {
            session_id: target.session_id,
            reason: RevocationReason::CredentialRemoved,
        },
    ] {
        let stored = history
            .iter()
            .find(|stored| stored.event.known() == Some(&expected))
            .unwrap_or_else(|| panic!("{expected:?} recorded"));
        assert_eq!(stored.actor, actor, "{expected:?}");
        assert_eq!(stored.reason.as_deref(), Some(REASON), "{expected:?}");
    }

    let browser = Browser::sign_in(database, user).await;
    let owner = AccountApplication::new(database.clone()).routes();
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

impl AccountOperation {
    /// Runs this operation as `viewer`, if it reads. `None` for a change, which
    /// checks its operator before it commits. The match is exhaustive, so a new
    /// operation must say which it is.
    async fn read(
        self,
        service: &AccountService,
        viewer: &Viewer,
    ) -> Option<Result<(), AccountError>> {
        Some(match self {
            Self::ListPasskeys => service.passkeys(viewer).await.map(drop),
            Self::ListIdentities => service.identities(viewer).await.map(drop),
            Self::ListEmails => service.emails(viewer).await.map(drop),
            Self::ListSessions => service.sessions(viewer).await.map(drop),
            Self::ViewHistory => service.history(viewer, None).await.map(drop),
            Self::RenamePasskey
            | Self::RevokePasskey
            | Self::UnlinkIdentity
            | Self::MakeEmailPrimary
            | Self::RemoveEmail
            | Self::RevokeSession
            | Self::RevokeOtherSessions => return None,
        })
    }
}

/// Every settings read checks an administrator as admin reads do, before it
/// reads or records anything: one whose rights were revoked, whose session ended,
/// or who signed in without a passkey reads nothing, and no view of the account
/// is recorded.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_settings_read_checks_its_administrator() {
    let fixture = Fixture::new().await;
    let (target, _) = fixture.target(1).await;
    for (operator, refusal) in fixture.harness.refused_readers().await {
        let viewer = Viewer::operator(target.user_id, operator);
        for read in AccountOperation::ALL {
            match read.read(&fixture.service, &viewer).await {
                None => {}
                Some(Err(AccountError::Operator(refused))) => {
                    assert_refused(&refused, &refusal, &format!("{read:?}"));
                }
                Some(result) => panic!("{read:?}: {result:?}"),
            }
        }
    }
    let history = fixture
        .harness
        .database
        .events()
        .history_for_user(target.user_id, 10)
        .await
        .expect("history");
    assert!(
        history
            .iter()
            .all(|stored| stored.event.known() != Some(&DomainEvent::AccountViewed {})),
        "no view recorded"
    );
}

/// An administrator's read shows every session, none of them theirs, and is
/// recorded as a view of the account, by them.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_reads_are_recorded_as_views() {
    let fixture = Fixture::new().await;
    let (target, _) = fixture.target(0).await;
    let viewer = Viewer::operator(target.user_id, fixture.operator(Duration::zero()));
    let sessions = fixture.service.sessions(&viewer).await.expect("sessions");
    assert_eq!(
        sessions
            .iter()
            .map(|session| (session.id, session.current))
            .collect::<Vec<_>>(),
        [(target.session_id, false)]
    );
    let history = fixture
        .harness
        .database
        .events()
        .history_for_user(target.user_id, 10)
        .await
        .expect("history");
    let view = history
        .iter()
        .find(|stored| stored.event.known() == Some(&DomainEvent::AccountViewed {}))
        .expect("the view is recorded");
    assert_eq!(
        view.actor,
        Actor::Admin {
            user_id: fixture.admin.user_id,
            session_id: fixture.admin.session_id,
        }
    );
    assert_eq!(view.subject, Some(target.user_id));
}

/// An administrator changes only existing accounts that are not administrators',
/// while they still hold their rights and session, and confirmed a passkey
/// recently. Each refusal changes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_are_refused_unless_they_may_change_the_account() {
    let fixture = Fixture::new().await;
    let (target, passkeys) = fixture.target(1).await;
    let user = target.user_id;
    let other_admin = fixture.harness.admin().await.user_id;
    let not_admin = operator(fixture.harness.account().await, Utc::now());
    let ended = fixture.harness.admin().await;
    let mut tx = fixture.harness.database.begin().await.expect("transaction");
    sign_out(&mut tx, ended.user_id, ended.session_id)
        .await
        .expect("sign out");
    tx.commit().await.expect("commit");
    let fresh = fixture.operator(Duration::seconds(10));
    let stale = fixture.operator(Duration::minutes(10));
    let step_up = StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE);
    for (operator, target, refusal) in [
        (fresh.clone(), other_admin, AdminError::AdministratorTarget),
        (fresh, UserId::new(), AdminError::UserNotFound),
        (not_admin, user, AdminError::NotAdministrator),
        (operator(ended, Utc::now()), user, AdminError::SessionEnded),
        (stale, user, AdminError::StepUpRequired(step_up)),
    ] {
        let expected = format!("{refusal:?}");
        match fixture.rename(operator, target, passkeys[0]).await {
            Err(AccountError::Operator(error)) => {
                assert_eq!(discriminant(&error), discriminant(&refusal), "{expected}");
            }
            result => panic!("{expected}: {result:?}"),
        }
    }
    assert_eq!(fixture.names(user).await, ["Key 0"]);
}

/// A change checks its administrator again under the account lock and before
/// committing: rights revoked, or a target made an administrator, while the
/// change waits for the account refuse it, and nothing it wrote commits. The CLI
/// may change an administrator's account.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn changes_check_the_administrator_again_after_waiting() {
    let fixture = Fixture::new().await;
    let database = &fixture.harness.database;
    let (target, passkeys) = fixture.target(1).await;
    let user = target.user_id;

    // The acting administrator's rights are revoked while the change waits.
    let revoked = fixture.harness.admin().await;
    let mut revocation = database.begin().await.expect("transaction");
    revocation
        .users()
        .find_by_id_for_update(user)
        .await
        .expect("target lock");
    revocation
        .administrators()
        .revoke(revoked.user_id)
        .await
        .expect("revoke");
    let (result, ()) = tokio::join!(
        fixture.rename(operator(revoked, Utc::now()), user, passkeys[0]),
        async {
            until_blocked(&mut revocation, 1).await;
            revocation.commit().await.expect("commit");
        }
    );
    assert!(
        matches!(
            result,
            Err(AccountError::Operator(AdminError::NotAdministrator))
        ),
        "{result:?}"
    );

    // The target becomes an administrator while the change waits.
    let mut grant = database.begin().await.expect("transaction");
    grant
        .users()
        .find_by_id_for_update(user)
        .await
        .expect("target lock");
    grant.administrators().grant(user).await.expect("grant");
    let (result, ()) = tokio::join!(
        fixture.rename(fixture.operator(Duration::zero()), user, passkeys[0]),
        async {
            until_blocked(&mut grant, 1).await;
            grant.commit().await.expect("commit");
        }
    );
    assert!(
        matches!(
            result,
            Err(AccountError::Operator(AdminError::AdministratorTarget))
        ),
        "{result:?}"
    );

    assert_eq!(fixture.names(user).await, ["Key 0"], "nothing changed");
    let renamed = DomainEvent::PasskeyRenamed {
        passkey_id: passkeys[0],
    };
    let history = database
        .events()
        .history_for_user(user, 20)
        .await
        .expect("history");
    assert!(
        history
            .iter()
            .all(|stored| stored.event.known() != Some(&renamed)),
        "no rename recorded"
    );
    fixture
        .rename(cli(), user, passkeys[0])
        .await
        .expect("the CLI changes an administrator's account");
}

/// The last passkey stays, whoever removes it and even with a social identity
/// linked.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_last_passkey_stays_whoever_removes_it() {
    let fixture = Fixture::new().await;
    let (target, passkeys) = fixture.target(1).await;
    let subject = Subject::operator(target.user_id, fixture.operator(Duration::zero()), reason());
    let removed = fixture.service.revoke_passkey(&subject, passkeys[0]).await;
    assert!(
        matches!(
            removed,
            Err(AccountError::Passkey(PasskeyError::LastPasskey))
        ),
        "{removed:?}"
    );
    let database = &fixture.harness.database;
    let browser = Browser::sign_in(database, target.user_id).await;
    let owner = AccountApplication::new(database.clone()).routes();
    let path = passkey::ITEM.replace("{id}", &passkeys[0].to_string());
    let (status, _) = browser.call(&owner, Method::DELETE, &path).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(fixture.names(target.user_id).await, ["Key 0"]);
}

/// The shared changes that could cut the owner off need their recent passkey
/// confirmation, checked before anything else, and again under the account lock:
/// a session that never confirmed one is refused, whichever passkey, identity or
/// address it names, even a malformed one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_confirm_the_changes_that_need_it() {
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let social =
        Browser::sign_in_with(&database, owner.user_id, AuthenticationMethod::Federation).await;
    let routes = AccountApplication::new(database).routes();
    let item = |template: &str, id: &str| template.replace("{id}", id);
    let id = EmailId::new().to_string();
    let identity = |provider| federation::IDENTITY.replace("{provider}", provider);
    // Before anything else: malformed IDs and unknown providers too, so the
    // browser confirms first.
    for (method, path) in [
        (Method::DELETE, item(passkey::ITEM, &id)),
        (Method::DELETE, item(passkey::ITEM, "not-an-id")),
        (Method::DELETE, identity("github")),
        (Method::DELETE, identity("myspace")),
        (Method::POST, item(emails::PRIMARY, &id)),
        (Method::POST, item(emails::PRIMARY, "not-an-id")),
        (Method::DELETE, item(emails::ITEM, &id)),
        (Method::DELETE, item(emails::ITEM, "not-an-id")),
    ] {
        let (status, body) = social.call(&routes, method.clone(), &path).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("step_up_required")),
            "{method} {path}"
        );
    }
}

/// A change that needs the owner's confirmation checks it under the account lock
/// on the session as the request's cookie found it, too: an owner whose session
/// was confirmed only while the change waited for the lock is refused, so a
/// cookie from before a confirmation never gains it. The account routes refuse
/// such a request before it waits; this one calls the operation from a plain
/// [`Owner`], as an in-process caller does.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_confirmation_while_waiting_does_not_count() {
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let social =
        Browser::sign_in_with(&database, owner.user_id, AuthenticationMethod::Federation).await;
    let routes = Router::new()
        .route(
            passkey::ITEM,
            delete(
                |State(database): State<Database>, owner: Owner, Path(id): Path<PasskeyId>| async move {
                    AccountService::new(database)
                        .revoke_passkey(&Subject::from(owner), id)
                        .await
                        .map_err(ApiError::from)
                },
            ),
        )
        .with_state(database.clone());
    let mut confirmation = database.begin().await.expect("transaction");
    confirmation
        .users()
        .find_active_by_id_for_update(owner.user_id)
        .await
        .expect("account lock");
    let path = passkey::ITEM.replace("{id}", &PasskeyId::new().to_string());
    let ((status, body), ()) = tokio::join!(social.call(&routes, Method::DELETE, &path), async {
        until_blocked(&mut confirmation, 1).await;
        confirmation
            .sessions()
            .confirm_passkey(social.session_id, Utc::now())
            .await
            .expect("confirm");
        confirmation.commit().await.expect("commit");
    });
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
}

operations! {
    /// The account operations that need the owner's recent confirmation, which the
    /// table below calls directly, as an in-process caller would.
    enum Confirming {
        /// Add an address.
        AddEmail,
        /// Make another verified address the primary one.
        MakeEmailPrimary,
        /// Remove an address.
        RemoveEmail,
        /// Link an identity.
        LinkIdentity,
        /// Unlink an identity.
        UnlinkIdentity,
        /// Remove a passkey.
        RevokePasskey,
        /// Register a client.
        CreateClient,
        /// Change a client's redirect URIs.
        UpdateClientRedirects,
        /// Rotate a client's secret.
        RotateClientSecret,
        /// Delete a client.
        DeleteClient,
    }
}

/// An account with something for each confirming operation to act on.
#[derive(Clone)]
struct Confirmation {
    /// The operations.
    service: AccountService,
    /// Email settings that send, so an address could be added.
    email: EmailConfig,
    /// The account.
    user: UserId,
    /// A verified address that is not the primary one.
    address: EmailId,
    /// One of two passkeys.
    passkey: PasskeyId,
    /// The account's confidential client.
    client: ClientId,
}

impl FromRef<Confirmation> for Database {
    /// The owner extractor's database.
    fn from_ref(state: &Confirmation) -> Self {
        state.service.database.clone()
    }
}

impl Confirmation {
    /// Creates an account with two passkeys, a GitHub identity, two verified
    /// addresses and a confidential client.
    async fn new(fixture: &Fixture) -> Self {
        let database = &fixture.harness.database;
        let (account, passkeys) = fixture.target(2).await;
        let user = account.user_id;
        let mut tx = database.begin().await.expect("transaction");
        let mut addresses = Vec::new();
        for (index, is_primary) in [(1, true), (2, false)] {
            let email = tx
                .emails()
                .insert_verified(&InsertVerifiedEmail {
                    id: EmailId::new(),
                    user_id: user,
                    normalized_email: format!("{user}-{index}@example.com"),
                    is_primary,
                    verified_at: Utc::now(),
                })
                .await
                .expect("address");
            addresses.push(email.id);
        }
        tx.commit().await.expect("commit");
        let client = registration(ClientKind::Confidential, "https://notes.example");
        change(database, async |registry| {
            registry
                .create(ClientOwner::Account(user), &client, None)
                .await
        })
        .await
        .expect("client");
        let settings = "https://piquel.fr/settings".parse().expect("settings URL");
        Self {
            service: fixture.service.clone(),
            email: EmailConfig::test(&settings, true),
            user,
            address: addresses[1],
            passkey: passkeys[0],
            client: client.id,
        }
    }

    /// What the operations could change: the addresses and which is primary,
    /// how many passkeys, identities and clients there are, the client's redirect
    /// URIs and secrets, and how many events the account has.
    async fn snapshot(&self) -> impl Debug + PartialEq {
        let database = &self.service.database;
        let emails = database.emails().list(self.user).await.expect("emails");
        let emails: Vec<_> = emails
            .iter()
            .map(|email| (email.id, email.is_primary))
            .collect();
        let passkeys = database.passkeys().list_active(self.user).await;
        let identities = database.federation().list_active(self.user).await;
        let clients = database.oidc().list_owned_clients(self.user).await;
        let clients: Vec<_> = clients
            .expect("clients")
            .into_iter()
            .map(|client| client.redirect_uris)
            .collect();
        let secrets = database.oidc().client_secrets(&self.client).await;
        let events = database.events().history_for_user(self.user, 1000).await;
        (
            emails,
            passkeys.expect("passkeys").len(),
            identities.expect("identities").len(),
            clients,
            secrets.expect("secrets").len(),
            events.expect("history").len(),
        )
    }
}

impl Confirming {
    /// Runs this operation as `owner` on `state`'s account.
    async fn run(self, state: &Confirmation, owner: Owner) -> Result<(), AccountError> {
        let service = &state.service;
        match self {
            Self::AddEmail => service
                .add_email(&owner, &state.email, "added@example.com")
                .await
                .map(drop),
            Self::MakeEmailPrimary => {
                let subject = Subject::from(owner);
                service.make_primary_email(&subject, state.address).await
            }
            Self::RemoveEmail => {
                let subject = Subject::from(owner);
                service.remove_email(&subject, state.address).await
            }
            Self::LinkIdentity => {
                let pending = Secret::generate().expect("pending evidence");
                service.link_identity(&owner, &pending).await.map(drop)
            }
            Self::UnlinkIdentity => {
                let subject = Subject::from(owner);
                service.unlink_identity(&subject, Provider::GitHub).await
            }
            Self::RevokePasskey => {
                let subject = Subject::from(owner);
                service.revoke_passkey(&subject, state.passkey).await
            }
            Self::CreateClient => {
                let new = json!({
                    "kind": "public",
                    "display_name": "Other",
                    "redirect_uris": ["https://other.example/callback"],
                });
                let new = serde_json::from_value(new).expect("new client");
                service.create_client(&owner, new).await.map(drop)
            }
            Self::UpdateClientRedirects => {
                let client = service.owned_client(owner, state.client.as_str()).await?;
                let patch = json!({"redirect_uris": ["https://attacker.example/callback"]});
                let patch = serde_json::from_value(patch).expect("patch");
                service.update_client(&client, patch).await.map(drop)
            }
            Self::RotateClientSecret => {
                let client = service.owned_client(owner, state.client.as_str()).await?;
                service
                    .rotate_client_secret(&client, GracePeriod::default())
                    .await
                    .map(drop)
            }
            Self::DeleteClient => {
                let client = service.owned_client(owner, state.client.as_str()).await?;
                service.delete_client(&client).await
            }
        }
    }
}

/// Every operation that needs the owner's recent confirmation checks it itself,
/// not only through its route's early check: called directly from a session that
/// never confirmed one, each answers `step_up_required` and changes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_confirmed_operation_checks_the_owner_itself() {
    let fixture = Fixture::new().await;
    let state = Confirmation::new(&fixture).await;
    let database = &fixture.harness.database;
    let social =
        Browser::sign_in_with(database, state.user, AuthenticationMethod::Federation).await;
    let before = state.snapshot().await;
    let routes = Router::new()
        .route(
            "/{index}",
            post(
                |State(state): State<Confirmation>, owner: Owner, Path(index): Path<usize>| async move {
                    Confirming::ALL[index]
                        .run(&state, owner)
                        .await
                        .map_err(ApiError::from)
                },
            ),
        )
        .with_state(state.clone());

    for (index, operation) in Confirming::ALL.iter().enumerate() {
        let (status, body) = social
            .call(&routes, Method::POST, &format!("/{index}"))
            .await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("step_up_required")),
            "{operation:?}"
        );
    }
    assert_eq!(
        state.snapshot().await,
        before,
        "nothing changed or recorded"
    );
}
