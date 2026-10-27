//! Database-backed administration scenarios: who may run each operation, and
//! what it changes.

use super::*;
use crate::recovery::RecoveryLinks;
use crate::security::{CONFIRMATION_MAX_AGE, RequestContext, Session};
use crate::tests::until_blocked;
use chrono::{Duration, Utc};
use piquel_admin_api::EventSearch;
use piquel_common::{
    AccountStatus, AuthenticationMethod, DeliveryId, Handle, HandleError, Personal, SessionId,
    TokenId, UserId,
    config::Origin,
    events::{DomainEvent, RevocationReason},
    protocol::{claims::Acr, step_up::StepUpRequirement},
};
use piquel_crypto::Secret;
use piquel_repository::{
    Channel, Database, DatabaseConfig, DatabaseError, DatabaseTransaction, DeliveryStatus,
    EventFilter, InsertUser, NewDelivery,
};
use serde_json::json;
use std::mem::discriminant;

/// A scenario account and its signed-in session.
#[derive(Clone, Copy)]
pub(crate) struct Account {
    /// The account.
    pub(crate) user_id: UserId,
    /// Its session.
    pub(crate) session_id: SessionId,
}

impl Account {
    /// Signs the account's session out in `tx`, as its browser would.
    async fn sign_out(self, tx: &mut DatabaseTransaction<'_>) {
        crate::tests::sign_out(tx, self.user_id, self.session_id)
            .await
            .expect("sign out");
    }
}

/// The test database the scenarios run on. The shared account settings' and the
/// recoveries' tests use it too.
pub(crate) struct Harness {
    /// The scenario database.
    pub(crate) database: Database,
}

impl Harness {
    /// Connects to the migrated test database.
    pub(crate) async fn new() -> Self {
        let url = piquel_common::config::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name a disposable PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("config"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        Self { database }
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
    pub(crate) async fn account(&self) -> Account {
        self.signed_in(AuthenticationMethod::Passkey).await
    }

    /// Creates an account signed in by `method`.
    pub(crate) async fn signed_in(&self, method: AuthenticationMethod) -> Account {
        let suffix = TokenId::new().to_string();
        let user_id = self.named(&format!("admin-{}", &suffix[24..])).await;
        let mut tx = self.database.begin().await.expect("transaction");
        let secret = Session::create(&mut tx, RequestContext::TEST, user_id, method.into())
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

    /// The service under test.
    fn service(&self) -> AdminService {
        AdminService::new(self.database.clone(), true)
    }

    /// Creates an administrator, granted by the CLI.
    pub(crate) async fn admin(&self) -> Account {
        let account = self.account().await;
        self.grant(account).await
    }

    /// Makes `account` an administrator, from the CLI.
    pub(crate) async fn grant(&self, account: Account) -> Account {
        self.service()
            .grant_administrator(&cli(), account.user_id)
            .await
            .expect("grant");
        account
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
pub(crate) fn cli() -> Operator {
    Operator::Cli {
        os_user: "tester".into(),
        host: "test".into(),
    }
}

/// Auth's origin, which invitations link to.
fn origin() -> Origin {
    "https://auth.piquel.fr".parse().expect("origin")
}

/// `admin` signed in to the dashboard, as its session cookie finds them, with a
/// passkey confirmation of the dashboard at `confirmed_at`.
pub(crate) fn operator(admin: Account, confirmed_at: chrono::DateTime<Utc>) -> Operator {
    Operator::Admin(AdminSession {
        user_id: admin.user_id,
        session_id: admin.session_id,
        confirmed_at: Some(confirmed_at),
        context: RequestContext::TEST,
    })
}

/// A reason any change accepts.
fn reason(text: &str) -> Reason {
    Reason::parse(text.into()).expect("reason")
}

/// Disabling an account ends its sessions at once and records why; enabling it
/// restores it, and both show in the events, attributed to the administrator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn disabling_ends_sessions_and_is_recorded() {
    let capture = piquel_telemetry::Telemetry::capture(crate::TELEMETRY_FILTER);
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let user = harness.account().await;
    let administrator = operator(admin, Utc::now());
    assert!(matches!(
        Reason::parse(String::new()),
        Err(AdminError::InvalidReason)
    ));
    service
        .disable_user(&administrator, user.user_id, reason("Spam"))
        .await
        .expect("disable");
    let stored = harness
        .database
        .users()
        .find_by_id(user.user_id)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.status, AccountStatus::Disabled);
    let id = admin.user_id.to_string();
    assert!(
        capture.logs().iter().any(|log| {
            let has = |key: &str, value: &str| {
                log.attributes_iter().any(|(name, logged)| {
                    name.as_str() == key && format!("{logged:?}").contains(value)
                })
            };
            has("event.kind", "account_disabled") && has("event.administrator", &id)
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
    service
        .enable_user(&administrator, user.user_id)
        .await
        .expect("enable");
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
    let page = service
        .events(
            &administrator,
            EventSearch {
                user: Some(user.user_id),
                kind: Some("account_disabled".into()),
                before: None,
            },
        )
        .await
        .expect("events");
    assert_eq!(page.events[0].actor["user_id"], id);
    assert_eq!(
        page.events[0].event["data"]["reason"],
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
    let service = harness.service();
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
        problems(service.check_handles(&cli()).await.expect("check")),
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
        let service = service.clone();
        async move {
            service
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
        problems(service.check_handles(&cli()).await.expect("check")),
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
    let filter = EventSearch {
        user: Some(user.user_id),
        ..EventSearch::default()
    };
    let page = harness
        .service()
        .events(&operator(admin, Utc::now()), filter)
        .await
        .expect("events");
    assert_eq!(
        page.events[0].event,
        json!({"kind": "from_a_newer_release", "version": 1, "data": data})
    );
}

/// Administrator accounts are out of the dashboard's reach until their rights
/// are revoked, and nobody grants or revokes their own rights there. A
/// revocation applies to the revoked administrator's next request.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn administrators_are_protected_until_revoked() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let other = harness.account().await;
    let (by_admin, by_other) = (operator(admin, Utc::now()), operator(other, Utc::now()));
    service
        .grant_administrator(&by_admin, other.user_id)
        .await
        .expect("grant");
    service
        .search_users(&by_other, "", None)
        .await
        .expect("the new administrator reads");
    let refused = service
        .disable_user(&by_admin, other.user_id, reason("Compromised"))
        .await;
    assert!(
        matches!(refused, Err(AdminError::AdministratorTarget)),
        "{refused:?}"
    );
    let refused = service.revoke_administrator(&by_admin, admin.user_id).await;
    assert!(matches!(refused, Err(AdminError::OwnRights)), "{refused:?}");
    // Refused before any lock, so a grant queued behind the caller's own
    // revocation cannot restore their rights.
    let refused = service.grant_administrator(&by_admin, admin.user_id).await;
    assert!(matches!(refused, Err(AdminError::OwnRights)), "{refused:?}");
    service
        .revoke_administrator(&by_admin, other.user_id)
        .await
        .expect("revoke");
    let refused = service.search_users(&by_other, "", None).await;
    assert!(
        matches!(refused, Err(AdminError::NotAdministrator)),
        "{refused:?}"
    );
    service
        .disable_user(&by_admin, other.user_id, reason("Compromised"))
        .await
        .expect("disable");
    assert_eq!(
        harness.events(other.user_id).await[2..4],
        [
            DomainEvent::AdministratorRevoked {},
            DomainEvent::AdministratorGranted {},
        ][..]
    );
}

/// An invitation link works until an administrator revokes it, which also ends
/// its expiry, for the previous release; revoking it again finds nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn revoked_invitations_cannot_be_redeemed() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = operator(harness.admin().await, Utc::now());
    let created = service
        .create_invitation(&admin, &origin(), "24h".parse().expect("expiry"))
        .await
        .expect("invitation");
    assert_eq!(created.url.path(), crate::routes::page::REGISTER);
    let (_, encoded) = created
        .url
        .query_pairs()
        .find(|(name, _)| name == "invitation")
        .expect("invitation secret");
    let digest = Secret::parse(&encoded).expect("secret").digest();
    let active = || harness.database.security();
    assert!(
        active()
            .invitation_active(digest.as_bytes())
            .await
            .expect("lookup")
    );
    service
        .revoke_invitation(&admin, created.id)
        .await
        .expect("revoke");
    assert!(
        !active()
            .invitation_active(digest.as_bytes())
            .await
            .expect("lookup")
    );
    let listed = service.list_invitations(&admin).await.expect("list");
    let revoked = listed
        .iter()
        .find(|listed| listed.id == created.id)
        .expect("revoked invitation");
    assert!(Some(revoked.expires_at) <= revoked.revoked_at);
    let again = service.revoke_invitation(&admin, created.id).await;
    assert!(
        matches!(again, Err(AdminError::InvitationNotFound)),
        "{again:?}"
    );
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
    user.sign_out(&mut logout).await;
    let service = harness.service();
    let reason = reason("Spam");
    let operator = operator(admin, auth_time);
    let (result, ()) = tokio::join!(
        service.disable_user(&operator, user.user_id, reason),
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
    let service = harness.service();
    let reason = reason("Spam");
    let operator = operator(admin, Utc::now());
    let (result, ()) = tokio::join!(
        service.disable_user(&operator, user.user_id, reason),
        async {
            until_blocked(&mut switch, 1).await;
            // The switch revokes the caller's session without a deadlock.
            admin.sign_out(&mut switch).await;
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
    let reason = reason("Spam");
    let disabled = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        harness
            .service()
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
    let service = harness.service();
    let invitation = service
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
    let (result, ()) = tokio::join!(service.revoke_invitation(&operator, invitation.id), async {
        until_blocked(&mut signup, 1).await;
        // The signup revokes the browser's session without a deadlock.
        admin.sign_out(&mut signup).await;
        signup.commit().await.expect("signup");
    });
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
    let service = harness.service();
    let (a, b) = (harness.admin().await, harness.admin().await);
    for _ in 0..10 {
        let disable = |by: Account, target: Account| {
            let service = service.clone();
            async move {
                let by = operator(by, Utc::now());
                service
                    .disable_user(&by, target.user_id, reason("Rogue"))
                    .await
            }
        };
        let (first, second) = tokio::join!(disable(a, b), disable(b, a));
        for refused in [first, second] {
            assert!(
                matches!(refused, Err(AdminError::AdministratorTarget)),
                "{refused:?}"
            );
        }
    }
}

impl AdminOperation {
    /// Runs the service methods behind this operation as `operator`, if it reads,
    /// with arguments that need not exist, since a read checks its operator before
    /// anything else. `None` for a change, which checks its operator before it
    /// commits. The match is exhaustive, so a new operation must say which it is.
    async fn read(
        self,
        service: &AdminService,
        operator: &Operator,
    ) -> Option<Vec<Result<(), AdminError>>> {
        let (user, client) = (UserId::new(), "notes");
        Some(match self {
            Self::SearchUsers => vec![service.search_users(operator, "", None).await.map(drop)],
            Self::ViewUser => vec![
                service
                    .find_user(operator, &UserRef::Id(user))
                    .await
                    .map(drop),
                service.view_user(operator, user).await.map(drop),
            ],
            Self::ListInvitations => vec![service.list_invitations(operator).await.map(drop)],
            Self::ListClients => vec![service.list_clients(operator).await.map(drop)],
            Self::ViewClient => vec![
                service
                    .client_details(operator, &client.parse().expect("client ID"))
                    .await
                    .map(drop),
            ],
            Self::ListEvents => vec![
                service
                    .events(operator, EventSearch::default())
                    .await
                    .map(drop),
            ],
            Self::ListAdministrators => vec![service.list_administrators(operator).await.map(drop)],
            Self::CheckHandles => vec![service.check_handles(operator).await.map(drop)],
            Self::ListDeliveries => vec![
                service
                    .list_deliveries(operator, None, None, 1)
                    .await
                    .map(drop),
            ],
            Self::DisableUser
            | Self::EnableUser
            | Self::RevokeUserSessions
            | Self::RevokeSession
            | Self::CreateInvitation
            | Self::RevokeInvitation
            | Self::CreateClient
            | Self::ApplyClient
            | Self::UpdateClient
            | Self::EnableClient
            | Self::DisableClient
            | Self::SuspendClient
            | Self::UnsuspendClient
            | Self::DeleteClient
            | Self::RotateClientSecret
            | Self::GrantAdministrator
            | Self::RevokeAdministrator
            | Self::RenameHandle
            | Self::RetryDelivery
            | Self::CancelDelivery
            | Self::RecoverAccount
            | Self::UndoRecovery => return None,
        })
    }
}

impl Harness {
    /// Three administrators who may no longer read, with the refusal each gets:
    /// one whose rights were revoked, one whose session ended, and one whose
    /// session signed in without a passkey.
    pub(crate) async fn refused_readers(&self) -> [(Operator, AdminError); 3] {
        let (revoked, ended) = (self.admin().await, self.admin().await);
        let social = self
            .grant(self.signed_in(AuthenticationMethod::Federation).await)
            .await;
        self.service()
            .revoke_administrator(&cli(), revoked.user_id)
            .await
            .expect("revoke");
        let mut tx = self.database.begin().await.expect("transaction");
        ended.sign_out(&mut tx).await;
        tx.commit().await.expect("commit");
        // Any passkey sign-in, however old, as every read requires.
        let passkey = StepUpRequirement {
            acr: Some(Acr::PhishingResistant),
            max_age: None,
        };
        [
            (operator(revoked, Utc::now()), AdminError::NotAdministrator),
            (operator(ended, Utc::now()), AdminError::SessionEnded),
            (
                operator(social, Utc::now()),
                AdminError::StepUpRequired(passkey),
            ),
        ]
    }
}

/// Asserts that `refused` is `expected`: the same variant and, for a step-up, the
/// same requirement. `case` names the scenario in a failure.
pub(crate) fn assert_refused(refused: &AdminError, expected: &AdminError, case: &str) {
    match (refused, expected) {
        (AdminError::StepUpRequired(actual), AdminError::StepUpRequired(expected)) => {
            assert_eq!(actual, expected, "{case}");
        }
        _ => assert_eq!(
            discriminant(refused),
            discriminant(expected),
            "{case}: {refused:?}"
        ),
    }
}

/// Every read checks its operator itself, as the dashboard calls the service
/// in-process: an administrator whose rights were revoked, whose session ended,
/// or whose session signed in without a passkey reads nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_read_checks_its_administrator() {
    let harness = Harness::new().await;
    let service = harness.service();
    for (operator, refusal) in harness.refused_readers().await {
        for read in AdminOperation::ALL {
            let Some(results) = read.read(&service, &operator).await else {
                continue;
            };
            for result in results {
                assert_refused(
                    &result.expect_err("refused"),
                    &refusal,
                    &format!("{read:?}"),
                );
            }
        }
    }
}

/// A delivery no worker sends, which the tests only retry and cancel.
struct Unsent;

impl Channel for Unsent {
    const NAME: &'static str = "test_admin_unsent";
    type Recipient = ();
    type Payload = ();

    fn deliveries(
        _: &DomainEvent,
        _: Option<UserId>,
        _: &mut DatabaseTransaction<'_>,
    ) -> impl Future<Output = Result<Vec<NewDelivery<Self>>, DatabaseError>> + Send {
        std::future::ready(Ok(vec![]))
    }
}

/// Retrying and cancelling a delivery check their administrator as every change
/// does, before committing: one whose rights were revoked, or whose confirmation
/// is stale, leaves the delivery as it was. A permitted change is recorded, since
/// cancelling one can hold back a notice to a user.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn delivery_changes_check_and_record_their_administrator() {
    let harness = Harness::new().await;
    let service = harness.service();
    let admin = harness.admin().await;
    let revoked = harness.admin().await;
    service
        .revoke_administrator(&cli(), revoked.user_id)
        .await
        .expect("revoke");
    let stale = Utc::now() - Duration::minutes(10);
    let step_up = StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE);
    let queue = async || {
        let delivery = NewDelivery::<Unsent> {
            destination: "https://receiver.example".into(),
            recipient: (),
            payload: (),
            ordering_key: None,
        };
        harness
            .database
            .deliveries()
            .insert(None, delivery)
            .await
            .expect("insert")
    };
    let status = async |id: DeliveryId| {
        let listed = harness
            .database
            .deliveries()
            .list(None, Some(Unsent::NAME), 1000)
            .await;
        let listed = listed.expect("list");
        listed
            .into_iter()
            .find(|delivery| delivery.id == id)
            .expect("delivery")
            .status
    };
    let (pending, cancelled) = (queue().await, queue().await);
    harness
        .database
        .deliveries()
        .cancel(cancelled)
        .await
        .expect("cancel");
    for (operator, refusal) in [
        (operator(revoked, Utc::now()), AdminError::NotAdministrator),
        (operator(admin, stale), AdminError::StepUpRequired(step_up)),
    ] {
        let refused = service
            .cancel_delivery(&operator, pending)
            .await
            .expect_err("cancel");
        assert_refused(&refused, &refusal, "cancel");
        let refused = service
            .retry_delivery(&operator, cancelled)
            .await
            .expect_err("retry");
        assert_refused(&refused, &refusal, "retry");
    }
    assert_eq!(status(pending).await, DeliveryStatus::Pending);
    assert_eq!(status(cancelled).await, DeliveryStatus::Cancelled);

    let admin = operator(admin, Utc::now());
    service
        .cancel_delivery(&admin, pending)
        .await
        .expect("cancel");
    service
        .retry_delivery(&admin, cancelled)
        .await
        .expect("retry");
    assert_eq!(status(pending).await, DeliveryStatus::Cancelled);
    assert_eq!(status(cancelled).await, DeliveryStatus::Pending);
    for (kind, delivery_id) in [
        ("delivery_cancelled", pending),
        ("delivery_retried", cancelled),
    ] {
        let filter = EventFilter {
            kind: Some(kind.into()),
            ..EventFilter::default()
        };
        let events = harness
            .database
            .events()
            .list(&filter, 100)
            .await
            .expect("events");
        let recorded = events
            .iter()
            .find(|stored| {
                matches!(
                    stored.event.known(),
                    Some(DomainEvent::DeliveryCancelled { delivery_id: id }
                        | DomainEvent::DeliveryRetried { delivery_id: id }) if *id == delivery_id
                )
            })
            .unwrap_or_else(|| panic!("{kind} recorded"));
        assert_eq!(recorded.actor, admin.context().actor, "{kind}");
    }
}

/// Nobody is made an administrator while a recovery of the account can still be
/// undone, not even from the CLI: granted during its probation, the rights would
/// go live for whoever used its link once it settles. Once support undid it,
/// nothing is left to refuse.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn no_grant_while_a_recovery_can_be_undone() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let target = harness.account().await.user_id;
    let links = RecoveryLinks::new(origin(), Secret::generate().expect("key"), None);
    let reason = || reason("Lost every passkey");
    let service = harness.service();
    service
        .recover_account(&cli(), target, reason(), &links, None)
        .await
        .expect("recovery");

    let refused = service
        .grant_administrator(&operator(admin, Utc::now()), target)
        .await;
    assert!(
        matches!(refused, Err(AdminError::GrantDuringRecovery)),
        "the dashboard refuses"
    );
    let refused = service.grant_administrator(&cli(), target).await;
    assert!(
        matches!(refused, Err(AdminError::GrantDuringRecovery)),
        "the CLI too"
    );
    let granted = harness.database.administrators().contains(target).await;
    assert!(!granted.expect("rights"), "not granted");

    service
        .undo_recovery(&cli(), target, reason())
        .await
        .expect("support cancels the unused link");
    service
        .grant_administrator(&cli(), target)
        .await
        .expect("granted once nothing can be undone");
}
