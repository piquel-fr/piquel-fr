//! The command line covers every admin and shared settings operation, confirms
//! changes that cut off access, and runs the operations the HTTP APIs run.

use super::*;
use crate::{
    AdminService, Operator, Reason,
    account::{AccountOperation, AccountService},
    admin::{AdminOperation, OperatorName},
    tests::{Browser, Replicas, operator},
};
use piquel_common::{
    AccountStatus, Handle, UserId,
    clients::ClientKind,
    config::ConfigurationError,
    events::{Actor, DomainEvent},
};
use piquel_repository::StoredEvent;

impl AdminOperation {
    /// A full command line that runs this operation, after `auth-service`. The
    /// match is exhaustive, so a new operation does not compile without one.
    #[expect(clippy::too_many_lines, reason = "One arm per operation.")]
    const fn invocation(self) -> &'static [&'static str] {
        match self {
            Self::SearchUsers => &["user", "search", "ali"],
            Self::ViewUser => &["user", "show", "alice"],
            Self::DisableUser => &["user", "disable", "alice", "--reason", "Spam"],
            Self::EnableUser => &["user", "enable", "alice"],
            Self::RecoverAccount => &["user", "recover", "alice", "--reason", "Lost phone"],
            Self::UndoRecovery => &["user", "undo-recovery", "alice", "--reason", "Confirmed"],
            Self::ScheduleDeletion => &["user", "delete", "alice", "--reason", "Asked by email"],
            Self::RestoreUser => &["user", "restore", "alice", "--reason", "Changed their mind"],
            Self::PurgeUser => &[
                "user",
                "delete",
                "alice",
                "--immediately",
                "--reason",
                "Spam account",
            ],
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
            Self::ApproveRelatedOrigin => {
                &["client", "origin", "add", "notes", "https://notes.example"]
            }
            Self::RemoveRelatedOrigin => &[
                "client",
                "origin",
                "remove",
                "notes",
                "https://notes.example",
            ],
            Self::ListEvents => &["audit", "list"],
            Self::VerifyAuditChain => &["audit", "verify"],
            Self::PruneAuditChain => &["audit", "prune", "--through", "1"],
            Self::ListAdministrators => &["admin", "list"],
            Self::GrantAdministrator => &["admin", "grant", "alice"],
            Self::RevokeAdministrator => &["admin", "revoke", "alice"],
            Self::CheckHandles => &["handle", "check"],
            Self::RenameHandle => &[
                "handle",
                "rename",
                "alice",
                "alicia",
                "--reason",
                "Impersonation",
            ],
            Self::ReleaseHandle => &["handle", "release", "alice"],
            Self::ReserveHandle => &["handle", "reserve", "alice", "--reason", "For Alice"],
            Self::UnreserveHandle => &["handle", "unreserve", "alice"],
            Self::ListDeliveries => &["deliveries", "list"],
            Self::RetryDelivery => &["deliveries", "retry", AN_ID],
            Self::CancelDelivery => &["deliveries", "cancel", AN_ID],
            Self::ListSigningKeys => &["keys", "list"],
            Self::RotateSigningKey => &["keys", "rotate", "--now"],
            Self::RevokeSigningKey => &["keys", "revoke", "primary"],
            Self::ImportSigningKey => &["keys", "import", "file://key.pem"],
            Self::ListAnnouncements => &["announcement", "list"],
            Self::ViewAnnouncement => &["announcement", "show", AN_ID],
            Self::DraftAnnouncement => &[
                "announcement",
                "draft",
                "--subject",
                "Incident",
                "--body-file",
                "incident.txt",
                "--everyone",
            ],
            Self::EditAnnouncement => &[
                "announcement",
                "edit",
                AN_ID,
                "--subject",
                "Incident",
                "--body-file",
                "-",
                "--to",
                "alice",
            ],
            Self::DiscardAnnouncement => &["announcement", "discard", AN_ID],
            Self::SendAnnouncement => &["announcement", "send", AN_ID, "--revision", "1", "--yes"],
        }
    }
}

impl AccountOperation {
    /// A full command line that runs this operation, after `auth-service`. The
    /// match is exhaustive, so a new operation does not compile without one.
    const fn invocation(self) -> &'static [&'static str] {
        match self {
            Self::ChangeDisplayName => &[
                "account", "alice", "name", "set", "Alice B", "--reason", "Asked",
            ],
            Self::ListPasskeys => &["account", "alice", "passkeys", "list"],
            Self::RenamePasskey => &[
                "account", "alice", "passkeys", "rename", AN_ID, "Phone", "--reason", "Asked",
            ],
            Self::RevokePasskey => &[
                "account", "alice", "passkeys", "revoke", AN_ID, "--reason", "Lost",
            ],
            Self::ListIdentities => &["account", "alice", "identities", "list"],
            Self::UnlinkIdentity => &[
                "account",
                "alice",
                "identities",
                "unlink",
                "github",
                "--reason",
                "Asked",
            ],
            Self::ListEmails => &["account", "alice", "emails", "list"],
            Self::MakeEmailPrimary => &[
                "account", "alice", "emails", "primary", AN_ID, "--reason", "Asked",
            ],
            Self::RemoveEmail => &[
                "account", "alice", "emails", "remove", AN_ID, "--reason", "Asked",
            ],
            Self::ListSessions => &["account", "alice", "sessions", "list"],
            Self::RevokeSession => &[
                "account", "alice", "sessions", "revoke", AN_ID, "--reason", "Lost",
            ],
            Self::RevokeOtherSessions => &[
                "account",
                "alice",
                "sessions",
                "revoke-all",
                "--reason",
                "Lost",
            ],
            Self::ListApps => &["account", "alice", "apps", "list"],
            Self::RemoveApp => &[
                "account", "alice", "apps", "remove", "notes", "--reason", "Asked",
            ],
            Self::ViewHistory => &["account", "alice", "history"],
            Self::ViewPicture => &["account", "alice", "picture", "show"],
            Self::RemovePicture => &[
                "account",
                "alice",
                "picture",
                "remove",
                "--reason",
                "Impersonation",
            ],
            Self::ListNotifications => &["account", "alice", "notifications", "list"],
            Self::ViewNotification => &["account", "alice", "notifications", "show", AN_ID],
        }
    }
}

/// A well-formed UUID for commands that take an ID.
const AN_ID: &str = "0199a000-0000-7000-8000-000000000001";

/// Every operation has a command, and that command runs it: its command line
/// parses to a command naming that operation.
#[test]
fn every_operation_has_its_command() {
    let admin = AdminOperation::ALL
        .iter()
        .map(|operation| (Operation::Admin(*operation), operation.invocation()));
    let account = AccountOperation::ALL
        .iter()
        .map(|operation| (Operation::Account(*operation), operation.invocation()));
    for (operation, invocation) in admin.chain(account) {
        let arguments = std::iter::once(&"auth-service").chain(invocation);
        let parsed =
            Cli::try_parse_from(arguments).unwrap_or_else(|error| panic!("{operation:?}: {error}"));
        let command = parsed.command.expect("a command");
        assert_eq!(command.operation(), Some(operation));
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

/// An operator's name is 1 to 64 characters without spaces, and never
/// `unknown`; `--operator` names one wherever it is given.
#[test]
fn operators_are_named() {
    for valid in ["alice", "ronan@laptop", "deploy"] {
        assert!(valid.parse::<OperatorName>().is_ok(), "{valid}");
    }
    let long = "a".repeat(65);
    for invalid in [
        "",
        "two words",
        "unknown",
        "Unknown",
        "tab\there",
        long.as_str(),
    ] {
        assert!(invalid.parse::<OperatorName>().is_err(), "{invalid:?}");
    }
    for arguments in [
        ["auth-service", "--operator", "alice", "user", "show", "bob"],
        ["auth-service", "user", "show", "bob", "--operator", "alice"],
    ] {
        let cli = Cli::try_parse_from(arguments).expect("arguments");
        assert_eq!(cli.operator, Some("alice".parse().expect("name")));
    }
}

/// Commands run as the operator `--operator` names, else the one the
/// environment names, and refuse when nothing names one.
#[test]
fn the_operator_is_named_or_the_command_refused() {
    let name = |name: &str| Some(name.parse::<OperatorName>().expect("name"));
    let recorded =
        |operator: Result<Operator, CliError>| match operator.expect("operator").context().actor {
            Actor::Cli { os_user, .. } => os_user,
            actor => panic!("{actor:?}"),
        };
    let unread = || -> Result<Option<OperatorName>, ConfigurationError> {
        panic!("--operator wins over the environment")
    };
    assert_eq!(recorded(Console::operator(name("alice"), unread)), "alice");
    assert_eq!(
        recorded(Console::operator(None, || Ok(name("deploy")))),
        "deploy"
    );
    assert!(matches!(
        Console::operator(None, || Ok(None)),
        Err(CliError::UnknownOperator)
    ));
}

/// Revoking a signing key, making a new one sign at once, revoking a client's
/// earlier secrets at once and releasing a handle each ask first, and without a
/// terminal or `--yes` change nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn destructive_commands_confirm() {
    let database = Replicas::database().await;
    let service = AdminService::new(database.clone(), true);
    let owner = Browser::new_account(&database).await;
    let held = database
        .users()
        .find_by_id(owner.user_id)
        .await
        .expect("lookup")
        .expect("account")
        .handle;
    let renamed = format!("renamed-{}", &owner.user_id.to_string()[24..]);
    service
        .rename_handle(
            &operator(),
            owner.user_id,
            Handle::parse(&renamed).expect("handle"),
            Reason::parse("Asked by email".into()).expect("reason"),
            false,
        )
        .await
        .expect("rename");
    let keys = service.list_signing_keys(&operator()).await.expect("keys");
    let name = || Some("test".parse().expect("operator"));
    for arguments in [
        ["auth-service", "keys", "rotate", "--now"],
        ["auth-service", "keys", "revoke", "primary"],
    ] {
        let Some(Command::Keys(command)) =
            Cli::try_parse_from(arguments).expect("arguments").command
        else {
            panic!("a keys command");
        };
        let refused = command.run(database.clone(), name()).await;
        assert!(
            matches!(refused, Err(CliError::Unconfirmed)),
            "{arguments:?}"
        );
    }
    let console = Console::new(database.clone(), name()).expect("console");
    let held = held.to_string();
    for arguments in [
        vec!["handle", "release", held.as_str()],
        vec!["client", "rotate-secret", "notes", "--grace", "0"],
    ] {
        let refused = Administration::parse(&arguments).run(&console).await;
        assert!(
            matches!(refused, Err(CliError::Unconfirmed)),
            "{arguments:?}"
        );
    }
    assert_eq!(
        service.list_signing_keys(&operator()).await.expect("keys"),
        keys,
        "no key changed"
    );
    let released = service
        .list_released_handles(&operator())
        .await
        .expect("released");
    assert!(
        released.iter().any(|kept| kept.handle.as_str() == held),
        "still kept: {released:?}"
    );
}

impl Administration {
    /// Parses `arguments`, after `auth-service`, as an administrative command.
    fn parse(arguments: &[&str]) -> Self {
        let arguments = std::iter::once(&"auth-service").chain(arguments);
        match Cli::try_parse_from(arguments).expect("arguments").command {
            Some(Command::Administration(command)) => command,
            _ => panic!("an administrative command"),
        }
    }

    /// Runs this command on `database` as the test operator.
    async fn run_on(self, database: &Database) {
        let console = Console {
            service: AdminService::new(database.clone(), true),
            account: AccountService::new(database.clone()),
            operator: operator(),
        };
        self.run(&console).await.expect("command");
    }
}

/// The first event of `kind` in `user`'s history, newest first, which must exist.
async fn recorded(
    database: &Database,
    user: UserId,
    kind: impl Fn(&DomainEvent) -> bool,
) -> StoredEvent {
    database
        .events()
        .history_for_user(user, 10)
        .await
        .expect("history")
        .into_iter()
        .find(|event| event.event.known().is_some_and(&kind))
        .expect("recorded")
}

/// `user disable` runs the admin operation: the account is disabled, signed out,
/// and the change is recorded as the operator's, with the reason.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn user_disable_runs_the_admin_operation() {
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let user = browser.user_id.to_string();
    Administration::parse(&["user", "disable", &user, "--reason", "Spam", "--yes"])
        .run_on(&database)
        .await;

    let account = database
        .users()
        .find_by_id(browser.user_id)
        .await
        .expect("lookup")
        .expect("account");
    assert_eq!(account.status, AccountStatus::Disabled);
    let disabled = recorded(&database, browser.user_id, |event| {
        matches!(event, DomainEvent::AccountDisabled { .. })
    })
    .await;
    assert!(matches!(&disabled.actor, Actor::Cli { os_user, .. } if os_user == "test"));
    recorded(&database, browser.user_id, |event| {
        matches!(event, DomainEvent::SessionRevoked { session_id, .. } if *session_id == browser.session_id)
    })
    .await;
}

/// `account … sessions revoke-all` runs the shared operation as the operator: every
/// session of the account ends, recorded as the operator's with the reason.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn account_commands_run_the_shared_operation() {
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let user = browser.user_id.to_string();
    Administration::parse(&[
        "account",
        &user,
        "sessions",
        "revoke-all",
        "--reason",
        "Lost phone",
        "--yes",
    ])
    .run_on(&database)
    .await;

    let revoked = recorded(&database, browser.user_id, |event| {
        matches!(event, DomainEvent::SessionRevoked { session_id, .. } if *session_id == browser.session_id)
    })
    .await;
    assert!(matches!(&revoked.actor, Actor::Cli { os_user, .. } if os_user == "test"));
    assert_eq!(revoked.reason.as_deref(), Some("Lost phone"));
}

/// `account … apps remove` removes the app's access with the operation the
/// settings and the dashboard run: the consent is gone, and its removal is
/// recorded as the operator's, with the reason.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn account_apps_remove_withdraws_the_consent() {
    let database = Replicas::database().await;
    let browser = Browser::new_account(&database).await;
    let client = crate::tests::registration(ClientKind::Public, "https://client.example");
    crate::tests::register(&database, &client)
        .await
        .expect("register");
    database
        .oidc()
        .save_consent(
            browser.user_id,
            &client.id,
            client.id.as_str(),
            &["openid".into()],
        )
        .await
        .expect("consent");
    let user = browser.user_id.to_string();
    Administration::parse(&[
        "account",
        &user,
        "apps",
        "remove",
        client.id.as_str(),
        "--reason",
        "Impersonating app",
    ])
    .run_on(&database)
    .await;

    let apps = database
        .oidc()
        .list_apps(browser.user_id)
        .await
        .expect("apps");
    assert!(apps.is_empty());
    let removed = recorded(&database, browser.user_id, |event| {
        matches!(event, DomainEvent::ConsentRevoked { client_id } if *client_id == client.id)
    })
    .await;
    assert!(matches!(&removed.actor, Actor::Cli { os_user, .. } if os_user == "test"));
    assert_eq!(removed.reason.as_deref(), Some("Impersonating app"));
}
