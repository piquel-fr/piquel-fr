//! Database-backed administration scenarios: who may run each operation, and
//! what it changes.

use super::*;
use crate::security::RequestContext;
use crate::tests::{AUTH_ORIGIN, Browser, Replicas, until_blocked};
use chrono::{Duration, Utc};
use piquel_common::{
    AccountStatus, AuthenticationMethod, Handle, Personal, SessionId, TokenId, UserId,
    admin::EventSearch, config::Origin, events::DomainEvent, protocol::step_up::StepUpRequirement,
};
use piquel_repository::{Database, DatabaseTransaction, InsertUser};
use std::mem::discriminant;

/// The operator of CLI-side changes.
pub(crate) use crate::tests::operator as cli;

mod accounts;
mod administrators;
mod deliveries;
mod handles;
mod invitations;
mod keys;
mod mutations;
mod reads;

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
        Self {
            database: Replicas::database().await,
        }
    }

    /// Connects to a schema of its own, for a scenario that must know every
    /// administrator, which the shared database's other tests keep adding.
    async fn isolated() -> Self {
        let database = Database::isolated(Replicas::database_config(5))
            .await
            .expect("isolated database");
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
        let browser = Browser::sign_in_with(&self.database, user_id, method).await;
        Account {
            user_id,
            session_id: browser.session_id,
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

/// Auth's origin, which invitations link to.
fn origin() -> Origin {
    AUTH_ORIGIN.parse().expect("origin")
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
