//! The audit history: every recorded domain event.

use super::{CliError, Console, Output};
use crate::UserRef;
use clap::Args;
use piquel_common::{
    EventId,
    admin::{EventPage, EventSearch},
    events::Actor,
};

/// Page through recorded events, newest first, 100 at a time.
#[derive(Args)]
pub(super) struct AuditCommand {
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

impl AuditCommand {
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
