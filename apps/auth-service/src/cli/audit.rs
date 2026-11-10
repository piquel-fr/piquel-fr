//! The audit history: every recorded domain event, and the tamper-evident chain
//! over them (see `docs/dev/security/audit-history.md`).

use super::{
    CliError, Confirm, Console,
    output::{Cell, Style, report},
};
use crate::{
    AuditError, AuditKeys, PUBLIC_BASE_URL, Reason, UserRef,
    audit::{AuditVerification, ChainPoint},
};
use clap::{Args, Subcommand};
use sourceorigin_common::{
    admin::{Event, EventPage, EventSearch},
    events::Actor,
};
use std::path::PathBuf;

/// Paging through, verifying and pruning the audit history.
#[derive(Subcommand)]
pub(super) enum AuditCommand {
    /// Page through recorded events, newest first, with who caused each and why.
    List(ListEvents),
    /// Recompute the chain and check every checkpoint against it, and record what
    /// it found, which the dashboard's Audit tab shows. Exits non-zero, naming the
    /// first position that does not match, when the chain is broken.
    Verify {
        /// The keys to check checkpoints against.
        #[command(flatten)]
        keys: AuditKeyArgs,
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
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
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
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::List(command) => command.run(console).await,
            Self::Verify { keys } => {
                let verification = service.verify_audit_chain(operator, &keys.keys()?).await?;
                out.emit(&verification)?;
                match verification.broken {
                    Some(broken) => Err(AuditError::Broken(broken).into()),
                    None => Ok(()),
                }
            }
            Self::Prune {
                through,
                keys,
                reason,
                confirm,
            } => {
                confirm.ask(
                    out,
                    &format!("This deletes every audit event through position {through}"),
                )?;
                let deleted = service
                    .prune_audit_chain(operator, &keys.keys()?, through, reason)
                    .await?;
                out.info(format_args!(
                    "Pruned {deleted} events through position {through}."
                ))
            }
        }
    }
}

// A verification, one fact per line: whether the chain holds, then what was
// checked.
report!(AuditVerification, self, out, {
    let point = |point: &Option<ChainPoint>| point.as_ref().map(Cell::new).into();
    let chain = match &self.broken {
        None => Cell::new("intact").style(Style::Good),
        Some(broken) => Cell::new(format_args!(
            "broken at position {}: {}",
            broken.position, broken.problem
        ))
        .style(Style::Bad),
    };
    let mut fields = vec![
        ("Chain", chain),
        ("Events checked", self.events_checked.into()),
        ("Checkpoints checked", self.checkpoints_checked.into()),
        ("Unsealed", self.unsealed.into()),
    ];
    if self.anchor.is_some() {
        fields.push(("Pruned through", point(&self.anchor)));
    }
    fields.extend([
        ("Newest", point(&self.newest)),
        ("Latest checkpoint", point(&self.latest_checkpoint)),
        ("Keys", Cell::new(self.keys)),
    ]);
    out.fields(&fields)
});

/// Page through recorded events, newest first.
#[derive(Args)]
pub(super) struct ListEvents {
    /// Only events concerning this account: its handle, ID or verified email.
    #[arg(long)]
    user: Option<UserRef>,
    /// Only events of this kind, e.g. `session_revoked`.
    #[arg(long)]
    kind: Option<String>,
    /// List administrators' and operators' views of accounts too, which are left
    /// out unless `--kind account_viewed` asks for them.
    #[arg(long)]
    views: bool,
    /// The page to list, counting from 1 at the newest events.
    #[arg(long)]
    page: Option<u32>,
}

impl ListEvents {
    /// Prints the page the filters select.
    async fn run(self, console: &Console) -> Result<(), CliError> {
        let user = match &self.user {
            Some(user) => Some(console.user(user).await?),
            None => None,
        };
        let search = EventSearch {
            user,
            kind: self.kind,
            views: self.views,
            page: self.page,
        };
        console
            .out
            .emit(&console.service.events(&console.operator, search).await?)
    }

    /// `event` as a table row: when, who caused it, whose account it concerns,
    /// its kind and why.
    pub(super) fn row(event: &Event) -> [Cell; 6] {
        let reason = match (&event.reason, event.erased) {
            (Some(reason), _) => Cell::new(reason),
            (None, true) => Cell::new("erased").style(Style::Muted),
            (None, false) => Cell::none(),
        };
        [
            Cell::new(event.id),
            event.occurred_at.into(),
            Cell::new(Self::actor(event)),
            event.subject.map(Cell::new).into(),
            event.event["kind"].as_str().into(),
            reason,
        ]
    }

    /// Names who caused `event` in a few words, an administrator by their handle
    /// while their account exists, or as the stored JSON when this release does
    /// not know the kind of actor.
    fn actor(event: &Event) -> String {
        match serde_json::from_value(event.actor.clone()) {
            Ok(Actor::User { user_id, .. }) => format!("user {user_id}"),
            Ok(Actor::Admin { user_id, .. }) => match &event.administrator {
                Some(handle) => format!("admin @{handle}"),
                None => format!("admin {user_id}"),
            },
            Ok(Actor::Cli { os_user, host }) => format!("cli {os_user}@{host}"),
            Ok(Actor::Client { client_id }) => format!("client {client_id}"),
            Ok(Actor::System { job }) => format!("job {job:?}"),
            Ok(Actor::Anonymous) => "anonymous".to_owned(),
            Ok(Actor::Unrecorded) => "unrecorded".to_owned(),
            Err(_) => event.actor.to_string(),
        }
    }
}

// One event per line, with who caused it and why, and how to list the next page.
// `--json` adds where its request came from.
report!(EventPage, self, out, {
    out.table(
        ["ID", "OCCURRED", "ACTOR", "SUBJECT", "KIND", "REASON"],
        "No events.",
        self.events.iter().map(ListEvents::row),
    )?;
    out.paging(self.paging, "events")
});
