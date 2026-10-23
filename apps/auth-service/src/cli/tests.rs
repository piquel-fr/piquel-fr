//! The command line covers every admin operation, confirms changes that end
//! access, and runs the operations the admin API runs.

use super::*;
use crate::{
    AdminService,
    admin::AdminOperation,
    tests::{Browser, Replicas, operator},
};
use clap::CommandFactory;
use piquel_common::{
    AccountStatus,
    events::{Actor, DomainEvent},
};

impl AdminOperation {
    /// The command that runs this operation, as words after `auth-service`. The
    /// match is exhaustive, so a new operation does not compile without one.
    const fn command(self) -> &'static [&'static str] {
        match self {
            Self::SearchUsers => &["user", "search"],
            Self::ViewUser => &["user", "show"],
            Self::DisableUser => &["user", "disable"],
            Self::EnableUser => &["user", "enable"],
            Self::RevokeUserSessions => &["session", "revoke-all"],
            Self::RevokeSession => &["session", "revoke"],
            Self::ListInvitations => &["invite", "list"],
            Self::CreateInvitation => &["invite", "create"],
            Self::RevokeInvitation => &["invite", "revoke"],
            Self::ListClients => &["client", "list"],
            Self::ViewClient => &["client", "show"],
            Self::CreateClient => &["client", "create"],
            Self::ApplyClient => &["client", "apply"],
            Self::UpdateClient => &["client", "update"],
            Self::EnableClient => &["client", "enable"],
            Self::DisableClient => &["client", "disable"],
            Self::SuspendClient => &["client", "suspend"],
            Self::UnsuspendClient => &["client", "unsuspend"],
            Self::DeleteClient => &["client", "delete"],
            Self::RotateClientSecret => &["client", "rotate-secret"],
            Self::ListEvents => &["audit"],
            Self::ListAdministrators => &["admin", "list"],
            Self::GrantAdministrator => &["admin", "grant"],
            Self::RevokeAdministrator => &["admin", "revoke"],
            Self::CheckHandles => &["handle", "check"],
            Self::RenameHandle => &["handle", "rename"],
            Self::ListDeliveries => &["deliveries", "list"],
            Self::RetryDelivery => &["deliveries", "retry"],
            Self::CancelDelivery => &["deliveries", "cancel"],
        }
    }
}

/// Every operation names a command that exists, so none is out of the CLI's reach.
#[test]
fn every_operation_has_a_command() {
    let cli = Cli::command();
    for operation in AdminOperation::ALL {
        let mut command = &cli;
        for word in operation.command() {
            command = command
                .find_subcommand(word)
                .unwrap_or_else(|| panic!("{operation:?}: no `{word}` command"));
        }
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
