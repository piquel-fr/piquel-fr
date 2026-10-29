//! The audit history: every recorded domain event, and the tamper-evident chain
//! over them (see `docs/security/audit-history.md`).

use super::{CliError, Confirm, Console, Output};
use crate::{
    AuditError, AuditKeys, PUBLIC_BASE_URL, UserRef,
    audit::{AuditVerification, ChainPoint},
};
use clap::{Args, Subcommand};
use piquel_common::{
    EventId,
    admin::{EventPage, EventSearch},
    events::Actor,
};
use std::path::PathBuf;

/// Paging through, verifying and pruning the audit history.
#[derive(Subcommand)]
pub(super) enum AuditCommand {
    /// Page through recorded events, newest first, 100 at a time.
    List(ListEvents),
    /// Recompute the chain and check every checkpoint against it. Exits non-zero,
    /// naming the first position that does not match, when the chain is broken.
    Verify {
        /// The keys to check checkpoints against.
        #[command(flatten)]
        keys: AuditKeyArgs,
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Delete the events through a checkpoint, once the chain verifies through it.
    /// The checkpoint becomes the anchor the remaining chain extends. Connects as
    /// the schema owner when `AUTH_DATABASE_OWNER_URL` is set: auth's own role may
    /// not delete events.
    Prune {
        /// The position of the checkpoint to prune through.
        #[arg(long)]
        through: u64,
        /// The keys to check checkpoints against.
        #[command(flatten)]
        keys: AuditKeyArgs,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// Which keys checkpoint signatures are checked against.
#[derive(Args)]
pub(super) struct AuditKeyArgs {
    /// A file of verifier keys, one per line, to use instead of the keys committed
    /// to the repository for `AUTH_PUBLIC_BASE_URL`'s host, e.g. a preview's, as
    /// `keys audit` prints it.
    #[arg(long)]
    key: Option<PathBuf>,
}

impl AuditKeyArgs {
    /// The given keys, or the committed ones.
    fn keys(&self) -> Result<AuditKeys, CliError> {
        Ok(match &self.key {
            Some(path) => {
                AuditKeys::given(&std::fs::read_to_string(path).map_err(CliError::AuditKeyFile)?)?
            }
            None => AuditKeys::committed(&PUBLIC_BASE_URL.parse()?)?,
        })
    }
}

impl AuditCommand {
    /// Runs this command through `console`.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        match self {
            Self::List(command) => command.run(console).await,
            Self::Verify { keys, output } => {
                let verification = console
                    .service
                    .verify_audit_chain(&console.operator, &keys.keys()?)
                    .await?;
                output.print(&verification, Self::print_verification)?;
                match verification.broken {
                    Some(broken) => Err(AuditError::Broken(broken).into()),
                    None => Ok(()),
                }
            }
            Self::Prune {
                through,
                keys,
                confirm,
            } => {
                confirm.ask(&format!(
                    "This deletes every audit event through position {through}"
                ))?;
                let deleted = console
                    .service
                    .prune_audit_chain(&console.operator, &keys.keys()?, through)
                    .await?;
                eprintln!("Pruned {deleted} events through position {through}.");
                Ok(())
            }
        }
    }

    /// Prints a verification for people, one fact per line.
    fn print_verification(verification: &AuditVerification) {
        let point = |point: &Option<ChainPoint>| {
            point
                .as_ref()
                .map_or_else(|| "none".to_owned(), ChainPoint::to_string)
        };
        match &verification.broken {
            None => println!("Chain: intact"),
            Some(broken) => println!(
                "Chain: broken at position {}: {}",
                broken.position, broken.problem
            ),
        }
        println!("Events checked: {}", verification.events_checked);
        println!("Checkpoints checked: {}", verification.checkpoints_checked);
        println!("Unsealed: {}", verification.unsealed);
        if verification.anchor.is_some() {
            println!("Pruned through: {}", point(&verification.anchor));
        }
        println!("Newest: {}", point(&verification.newest));
        println!(
            "Latest checkpoint: {}",
            point(&verification.latest_checkpoint)
        );
        println!("Keys: {}", verification.keys);
    }
}

/// Page through recorded events, newest first, 100 at a time.
#[derive(Args)]
pub(super) struct ListEvents {
    /// Only events concerning this account: its handle, ID or verified email.
    #[arg(long)]
    user: Option<UserRef>,
    /// Only events of this kind, e.g. `session_revoked`.
    #[arg(long)]
    kind: Option<String>,
    /// Continue with events older than this one, the last one listed.
    #[arg(long)]
    before: Option<EventId>,
    /// Output format.
    #[command(flatten)]
    output: Output,
}

impl ListEvents {
    /// Prints the page the filters select.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let user = match &self.user {
            Some(user) => Some(console.user(user).await?),
            None => None,
        };
        let search = EventSearch {
            user,
            kind: self.kind,
            before: self.before,
        };
        self.output.print(
            &console.service.events(&console.operator, search).await?,
            Self::print_page,
        )
    }

    /// Prints one event per line, and how to continue if there may be more.
    fn print_page(page: &EventPage) {
        println!("ID\tOCCURRED\tACTOR\tSUBJECT\tKIND");
        for event in &page.events {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                event.id,
                event.occurred_at.to_rfc3339(),
                Self::actor(&event.actor),
                event
                    .subject
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
                event.event["kind"].as_str().unwrap_or("-"),
            );
        }
        if let Some(next) = page.next {
            eprintln!("More may follow: --before {next}");
        }
    }

    /// Names who acted in a few words, or as the stored JSON when this release
    /// does not know the kind of actor.
    fn actor(actor: &serde_json::Value) -> String {
        match serde_json::from_value(actor.clone()) {
            Ok(Actor::User { user_id, .. }) => format!("user {user_id}"),
            Ok(Actor::Admin { user_id, .. }) => format!("admin {user_id}"),
            Ok(Actor::Cli { os_user, host }) => format!("cli {os_user}@{host}"),
            Ok(Actor::Client { client_id }) => format!("client {client_id}"),
            Ok(Actor::System { job }) => format!("job {job:?}"),
            Ok(Actor::Anonymous) => "anonymous".to_owned(),
            Ok(Actor::Unrecorded) => "unrecorded".to_owned(),
            Err(_) => actor.to_string(),
        }
    }
}
