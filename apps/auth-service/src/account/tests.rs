//! Database-backed scenarios of administrators acting on another account through
//! [`AccountService`]: what they may change, how it is recorded, and what refuses
//! them.

use super::*;
use crate::{
    AdminError, AdminService, Operator, Reason,
    admin::tests::{Account, Harness, cli, operator},
    passkey::PasskeyError,
    security::CONFIRMATION_MAX_AGE,
    tests::{Browser, Replicas, sign_out, until_blocked},
};
use axum::http::Method;
use chrono::{Duration, Utc};
use piquel_common::{
    AuthenticationMethod, EmailId, Provider, TokenId, UserId,
    events::{Actor, DomainEvent, RevocationReason},
    protocol::step_up::StepUpRequirement,
};
use piquel_repository::{InsertExternalIdentity, InsertPasskey};
use serde_json::json;
use std::mem::discriminant;

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
/// reads or records anything: one whose rights were revoked reads nothing, and no
/// view of the account is recorded.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_settings_read_checks_its_administrator() {
    let fixture = Fixture::new().await;
    let (target, _) = fixture.target(1).await;
    let revoked = fixture.harness.admin().await;
    AdminService::new(fixture.harness.database.clone())
        .revoke_administrator(&cli(), revoked.user_id)
        .await
        .expect("revoke");
    let viewer = Viewer::operator(target.user_id, operator(revoked, Utc::now()));
    for read in AccountOperation::ALL {
        if let Some(result) = read.read(&fixture.service, &viewer).await {
            assert!(
                matches!(
                    result,
                    Err(AccountError::Operator(AdminError::NotAdministrator))
                ),
                "{read:?}: {result:?}"
            );
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
/// confirmation, checked under the account lock before anything is looked up: a
/// session that never confirmed one is refused, whichever passkey, identity or
/// address it names.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn owners_confirm_the_changes_that_need_it() {
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let social =
        Browser::sign_in_with(&database, owner.user_id, AuthenticationMethod::Federation).await;
    let routes = AccountApplication::new(database).routes();
    let item = |template: &str| template.replace("{id}", &EmailId::new().to_string());
    for (method, path) in [
        (Method::DELETE, item(passkey::ITEM)),
        (
            Method::DELETE,
            federation::IDENTITY.replace("{provider}", "github"),
        ),
        (Method::POST, item(emails::PRIMARY)),
        (Method::DELETE, item(emails::ITEM)),
    ] {
        let (status, body) = social.call(&routes, method.clone(), &path).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("step_up_required")),
            "{method} {path}"
        );
    }
}

/// A change that needs the owner's confirmation checks it on the session as the
/// request's cookie found it, too: a request whose session was confirmed only
/// while it waited for the account lock is refused, so a cookie from before a
/// confirmation never gains it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_confirmation_while_waiting_does_not_count() {
    let database = Replicas::database().await;
    let owner = Browser::new_account(&database).await;
    let social =
        Browser::sign_in_with(&database, owner.user_id, AuthenticationMethod::Federation).await;
    let routes = AccountApplication::new(database.clone()).routes();
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
