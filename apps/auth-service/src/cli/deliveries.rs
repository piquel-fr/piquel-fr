//! The break-glass view of the outbound delivery queue.

use super::{
    CliError, Console,
    output::{Cell, Style, report},
};
use crate::Reason;
use clap::Subcommand;
use sourceorigin_common::{DeliveryId, admin::DeliverySummary};
use sourceorigin_repository::DeliveryStatus;

/// Inspecting, retrying and cancelling outbound deliveries.
#[derive(Subcommand)]
pub(super) enum DeliveriesCommand {
    /// List deliveries, newest first.
    List {
        /// Only deliveries with this status: pending, succeeded, failed or cancelled.
        #[arg(long)]
        status: Option<DeliveryStatus>,
        /// Only deliveries on this channel.
        #[arg(long)]
        channel: Option<String>,
        /// The most deliveries to list.
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Attempt a failed delivery, or a cancelled unordered one, again now.
    Retry {
        /// The delivery's ID.
        id: DeliveryId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
    /// Cancel a pending or failed delivery, which unblocks the deliveries ordered after it.
    Cancel {
        /// The delivery's ID.
        id: DeliveryId,
        /// Why, recorded with the change: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
    },
}

impl DeliveriesCommand {
    /// Runs this command through the console's service.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service: admin,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::List {
                status,
                channel,
                limit,
            } => out.emit(
                &admin
                    .list_deliveries(operator, status, channel.as_deref(), limit)
                    .await?[..],
            )?,
            Self::Retry { id, reason } => {
                admin.retry_delivery(operator, id, reason).await?;
                out.info(format_args!("Delivery {id} will be attempted again now."))?;
            }
            Self::Cancel { id, reason } => {
                admin.cancel_delivery(operator, id, reason).await?;
                out.info(format_args!("Cancelled delivery {id}."))?;
            }
        }
        Ok(())
    }
}

// One delivery per line, newest first.
report!([DeliverySummary], self, out, {
    out.table(
        [
            "ID",
            "CHANNEL",
            "STATUS",
            "ATTEMPTS",
            "ORDER",
            "DUE OR FINISHED",
            "LAST ERROR",
            "DESTINATION",
        ],
        "No deliveries.",
        self.iter().map(|delivery| {
            [
                Cell::new(delivery.id),
                Cell::new(&delivery.channel),
                delivery.status.into(),
                delivery.attempts.into(),
                delivery
                    .ordering
                    .as_ref()
                    .map(|(key, ordinal)| Cell::new(format_args!("{key}#{ordinal}")))
                    .into(),
                delivery
                    .finished_at
                    .unwrap_or(delivery.next_attempt_at)
                    .into(),
                delivery
                    .last_error
                    .as_deref()
                    .map(|error| Cell::new(error).style(Style::Bad))
                    .into(),
                Cell::new(&delivery.destination),
            ]
        }),
    )
});
