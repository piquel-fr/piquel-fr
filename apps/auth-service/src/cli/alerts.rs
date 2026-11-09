//! The alerts administrators are shown, and the updates they post on them.

use super::{CliError, Console, Output};
use crate::Reason;
use clap::Subcommand;
use piquel_common::{
    AlertId,
    alerts::{Alert, AlertDetail, AlertState, AlertStatus, AlertsShown},
};

/// Listing alerts and posting updates on them.
#[derive(Subcommand)]
pub(super) enum AlertsCommand {
    /// List the current alerts, newest first, each with where its handling
    /// stands.
    List {
        /// List the alerts that cleared instead, the most recently cleared
        /// first, at most 100.
        #[arg(long)]
        previous: bool,
        /// Output format. JSON lists every update.
        #[command(flatten)]
        output: Output,
    },
    /// Post an update on a current alert, saying where its handling stands. The
    /// first acknowledges it: it stops counting as a warning, though it stays
    /// current while its condition holds. A new alert is raised if the condition
    /// changes, or clears and comes back.
    Update {
        /// The alert's ID.
        id: AlertId,
        /// Where its handling stands: investigating, fixing or monitoring.
        #[arg(long)]
        status: AlertStatus,
        /// What to add, such as who is on it: 1 to 500 characters.
        #[arg(long)]
        note: Option<Reason>,
    },
}

impl AlertsCommand {
    /// Runs this command through the console's service.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::List { previous, output } => {
                let shown = if previous {
                    AlertsShown::Previous
                } else {
                    AlertsShown::Current
                };
                let alerts = service.alerts(operator, shown).await?;
                output.print(&alerts, |alerts| {
                    println!("ID\tSTATE\tSTATUS\tRAISED\tLAST SEEN\tCLEARED\tALERT");
                    for alert in alerts {
                        Self::print(alert);
                    }
                })?;
            }
            Self::Update { id, status, note } => {
                service.update_alert(operator, id, status, note).await?;
                eprintln!("Alert {id} updated: {status}.");
            }
        }
        Ok(())
    }

    /// Prints one alert as a table row: where it and its handling stand, and
    /// what it says.
    fn print(detail: &AlertDetail) {
        let alert = &detail.alert;
        let state = match alert.state() {
            AlertState::Open => "open",
            AlertState::Acknowledged => "acknowledged",
            AlertState::Cleared => "cleared",
        };
        let status = detail
            .updates
            .last()
            .map_or("-", |update| update.status.as_str());
        let says = alert.alert.as_ref().map_or_else(
            || Alert::UNKNOWN.to_owned(),
            |alert| format!("{}. {}", alert.subject(), alert.body()),
        );
        let cleared = alert
            .cleared_at
            .map_or_else(|| "-".to_owned(), |at| at.to_string());
        println!(
            "{}\t{state}\t{status}\t{}\t{}\t{cleared}\t{says}",
            alert.id, alert.raised_at, alert.seen_at
        );
    }
}
