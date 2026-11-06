//! The alerts administrators are shown.

use super::{CliError, Console, Output};
use crate::Reason;
use clap::Subcommand;
use piquel_common::{
    AlertId,
    alerts::{AlertState, StoredAlert},
};

/// Listing and acknowledging alerts.
#[derive(Subcommand)]
pub(super) enum AlertsCommand {
    /// List the current alerts, then those that cleared, each newest first.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Acknowledge an open alert: it needs no attention while its condition
    /// holds as it says. A new alert is raised if the condition changes, or
    /// clears and comes back.
    Acknowledge {
        /// The alert's ID.
        id: AlertId,
        /// Why, such as who is looking into it, kept with the event as personal
        /// data: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
}

impl AlertsCommand {
    /// Runs this command through the console's service.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::List { output } => {
                let alerts = service.list_alerts(operator).await?;
                output.print(&alerts, |alerts| {
                    println!("ID\tSTATE\tRAISED\tLAST SEEN\tALERT");
                    for alert in alerts {
                        Self::print(alert);
                    }
                })?;
            }
            Self::Acknowledge { id, reason } => {
                service.acknowledge_alert(operator, id, reason).await?;
            }
        }
        Ok(())
    }

    /// Prints one alert as a table row: its subject, and what it says.
    fn print(alert: &StoredAlert) {
        let state = match alert.state() {
            AlertState::Open => "open",
            AlertState::Acknowledged => "acknowledged",
            AlertState::Cleared => "cleared",
        };
        let says = alert.alert.as_ref().map_or_else(
            || "an alert this release cannot show".to_owned(),
            |alert| format!("{} {}", alert.subject(), alert.body()),
        );
        println!(
            "{}\t{state}\t{}\t{}\t{says}",
            alert.id, alert.raised_at, alert.seen_at
        );
    }
}
