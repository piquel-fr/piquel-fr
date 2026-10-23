//! The break-glass view of the outbound delivery queue.

use super::{CliError, Console};
use clap::Subcommand;
use piquel_common::DeliveryId;
use piquel_repository::DeliveryStatus;

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
    },
    /// Cancel a pending or failed delivery, which unblocks the deliveries ordered after it.
    Cancel {
        /// The delivery's ID.
        id: DeliveryId,
    },
}

impl DeliveriesCommand {
    /// Runs this command through the console's service.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let admin = &console.service;
        match self {
            Self::List {
                status,
                channel,
                limit,
            } => {
                let deliveries = admin
                    .list_deliveries(status, channel.as_deref(), limit)
                    .await?;
                println!(
                    "ID\tCHANNEL\tSTATUS\tATTEMPTS\tORDER\tDUE OR FINISHED\tLAST ERROR\tDESTINATION"
                );
                for delivery in deliveries {
                    let order = delivery.ordering.map_or_else(
                        || "-".to_owned(),
                        |(key, ordinal)| format!("{key}#{ordinal}"),
                    );
                    println!(
                        "{}\t{}\t{}\t{}\t{order}\t{}\t{}\t{}",
                        delivery.id,
                        delivery.channel,
                        delivery.status,
                        delivery.attempts,
                        delivery.finished_at.unwrap_or(delivery.next_attempt_at),
                        delivery.last_error.as_deref().unwrap_or("-"),
                        delivery.destination,
                    );
                }
            }
            Self::Retry { id } => admin.retry_delivery(id).await?,
            Self::Cancel { id } => admin.cancel_delivery(id).await?,
        }
        Ok(())
    }
}
