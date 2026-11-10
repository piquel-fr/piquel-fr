//! The alerts administrators are shown, and the updates they post on them.

use super::{
    CliError, Console,
    output::{Cell, report},
};
use crate::Reason;
use clap::Subcommand;
use sourceorigin_common::{
    AlertId,
    alerts::{Alert, AlertDetail, AlertStatus, AlertsShown},
};

/// Listing alerts and posting updates on them.
#[derive(Subcommand)]
pub(super) enum AlertsCommand {
    /// List the current alerts, newest first, each with where its handling
    /// stands. `--json` lists every update too.
    List {
        /// List the alerts that cleared instead, the most recently cleared
        /// first, at most 100.
        #[arg(long)]
        previous: bool,
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
        /// What to add, such as who is on it, recorded as the update's reason: 1
        /// to 500 characters.
        #[arg(long)]
        note: Reason,
    },
}

impl AlertsCommand {
    /// Runs this command through the console's service.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::List { previous } => {
                let shown = if previous {
                    AlertsShown::Previous
                } else {
                    AlertsShown::Current
                };
                out.emit(&service.alerts(operator, shown).await?[..])?;
            }
            Self::Update { id, status, note } => {
                service.update_alert(operator, id, status, note).await?;
                out.info(format_args!("Alert {id} updated: {status}."))?;
            }
        }
        Ok(())
    }
}

// One alert per line: where it and its handling stand, and what it says.
report!([AlertDetail], self, out, {
    out.table(
        [
            "ID",
            "STATE",
            "STATUS",
            "RAISED",
            "LAST SEEN",
            "CLEARED",
            "ALERT",
        ],
        "No alerts.",
        self.iter().map(|detail| {
            let alert = &detail.alert;
            let says = alert.alert.as_ref().map_or_else(
                || Cell::new(Alert::UNKNOWN),
                |alert| Cell::new(format_args!("{}. {}", alert.subject(), alert.body())),
            );
            [
                Cell::new(alert.id),
                alert.state().into(),
                detail
                    .updates
                    .last()
                    .map(|update| update.status.as_str())
                    .into(),
                alert.raised_at.into(),
                alert.seen_at.into(),
                alert.cleared_at.into(),
                says,
            ]
        }),
    )
});
