//! The command line covers every admin operation, confirms changes that end
//! access, and runs the operations the admin API runs.

use super::*;
use crate::{
    AdminService,
    admin::AdminOperation,
    tests::{Browser, Replicas, operator},
};
use piquel_common::{
    AccountStatus,
    events::{Actor, DomainEvent},
};

impl AdminOperation {
    /// A full command line that runs this operation, after `auth-service`. The
    /// match is exhaustive, so a new operation does not compile without one.
    const fn invocation(self) -> &'static [&'static str] {
        match self {
            Self::SearchUsers => &["user", "search", "ali"],
            Self::ViewUser => &["user", "show", "alice"],
            Self::DisableUser => &["user", "disable", "alice", "--reason", "Spam"],
            Self::EnableUser => &["user", "enable", "alice"],
            Self::ScheduleDeletion => &["user", "delete", "alice"],
            Self::RestoreUser => &["user", "restore", "alice"],
            Self::PurgeUser => &["user", "delete", "alice", "--immediately"],
            Self::RevokeUserSessions => &["session", "revoke-all", "alice"],
            Self::RevokeSession => &["session", "revoke", AN_ID],
            Self::ListInvitations => &["invite", "list"],
            Self::CreateInvitation => &["invite", "create"],
            Self::RevokeInvitation => &["invite", "revoke", AN_ID],
            Self::ListClients => &["client", "list"],
            Self::ViewClient => &["client", "show", "notes"],
            Self::CreateClient => &[
                "client",
                "create",
                "notes",
                "--name",
                "Notes",
                "--redirect-uri",
                "https://notes.example/callback",
            ],
            Self::ApplyClient => &[
                "client",
                "apply",
                "notes",
                "--name",
                "Notes",
                "--redirect-uri",
                "https://notes.example/callback",
            ],
            Self::UpdateClient => &["client", "update", "notes", "--trusted"],
            Self::EnableClient => &["client", "enable", "notes"],
            Self::DisableClient => &["client", "disable", "notes"],
            Self::SuspendClient => &["client", "suspend", "notes"],
            Self::UnsuspendClient => &["client", "unsuspend", "notes"],
            Self::DeleteClient => &["client", "delete", "notes"],
            Self::RotateClientSecret => &["client", "rotate-secret", "notes"],
            Self::ListEvents => &["audit"],
            Self::ListAdministrators => &["admin", "list"],
            Self::GrantAdministrator => &["admin", "grant", "alice"],
            Self::RevokeAdministrator => &["admin", "revoke", "alice"],
            Self::CheckHandles => &["handle", "check"],
            Self::RenameHandle => &["handle", "rename", "alice", "alicia"],
            Self::ListDeliveries => &["deliveries", "list"],
            Self::RetryDelivery => &["deliveries", "retry", AN_ID],
            Self::CancelDelivery => &["deliveries", "cancel", AN_ID],
        }
    }
}

/// A well-formed UUID for commands that take an ID.
const AN_ID: &str = "0199a000-0000-7000-8000-000000000001";

/// Every operation has a command, and that command runs it: its command line
/// parses to a command naming that operation.
#[test]
fn every_operation_has_its_command() {
    for operation in AdminOperation::ALL {
        let arguments = std::iter::once(&"auth-service").chain(operation.invocation());
        let parsed =
            Cli::try_parse_from(arguments).unwrap_or_else(|error| panic!("{operation:?}: {error}"));
        let Some(Command::Administration(command)) = parsed.command else {
            panic!("{operation:?}: not an administrative command");
        };
        assert_eq!(command.operation(), *operation);
    }
}

/// Without a terminal, a change that needs confirmation runs only with `--yes`. On
/// a terminal, only a yes runs it.
#[test]
fn confirmation_needs_a_terminal_or_yes() {
    let ask = |yes, terminal, answer: &str| {
        Confirm { yes }.ask_on("Disable alice", terminal, answer.as_bytes())
    };
    assert!(matches!(
        ask(false, false, "y\n"),
        Err(CliError::Unconfirmed)
    ));
    assert!(ask(true, false, "").is_ok());
    assert!(ask(false, true, "y\n").is_ok());
    assert!(matches!(ask(false, true, "\n"), Err(CliError::Declined)));
    assert!(matches!(ask(false, true, "no\n"), Err(CliError::Declined)));
}

/// `user disable` runs the admin operation: the account is disabled, signed out,
/// and the change is recorded as the operator's, with the reason.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn user_disable_runs_the_admin_operation() {
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let user = browser.user_id.to_string();
    let Some(Command::Administration(command)) = Cli::try_parse_from([
        "auth-service",
        "user",
        "disable",
        &user,
        "--reason",
        "Spam",
        "--yes",
    ])
    .expect("arguments")
    .command
    else {
        panic!("an administrative command");
    };
    let console = Console {
        service: AdminService::new(database.clone()),
        operator: operator(),
    };
    command.run(&console).await.expect("disable");

    let account = database
        .users()
        .find_by_id(browser.user_id)
        .await
        .expect("lookup")
        .expect("account");
    assert_eq!(account.status, AccountStatus::Disabled);
    let history = database
        .events()
        .history_for_user(browser.user_id, 10)
        .await
        .expect("history");
    let disabled = history
        .iter()
        .find(|event| {
            matches!(
                event.event.known(),
                Some(DomainEvent::AccountDisabled { .. })
            )
        })
        .expect("recorded");
    assert!(matches!(&disabled.actor, Actor::Cli { os_user, .. } if os_user == "test"));
    assert!(history.iter().any(|event| matches!(
        event.event.known(),
        Some(DomainEvent::SessionRevoked { session_id, .. }) if *session_id == browser.session_id
    )));
}
