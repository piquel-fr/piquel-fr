//! The `email` channel: messages to account holders.
//!
//! A verification link's delivery stores the account and the address's ID, not
//! the address: the sender reads it when it sends, through
//! [`EmailRepository::pending_address`], so an address removed or verified in the
//! meantime receives nothing. Nothing secret is stored either: the link's token is
//! derived from the address's ID when the message is sent. Notices to an address
//! that stopped being primary, or was removed, copy the address instead, so a
//! removal cannot cancel them.

use super::{Channel, NewDelivery};
use crate::{
    DatabaseError, DatabaseTransaction,
    repositories::{EmailRepository, RepositoryExecutor},
};
use piquel_common::{EmailId, UserId, events::DomainEvent};
use serde::{Deserialize, Serialize};

/// Email to account holders, sent over SMTP by auth-service.
pub struct Email;

/// What an email says, and to which address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmailMessage {
    /// The link that verifies a newly added address, sent to that address while
    /// it waits for verification.
    VerifyAddress {
        /// The unverified address.
        email_id: EmailId,
    },
    /// Tells the previous primary address that another one replaced it.
    PrimaryAddressChanged {
        /// The previous primary address.
        address: String,
    },
    /// Tells a verified address that it was removed from the account.
    AddressRemoved {
        /// The removed address.
        address: String,
    },
}

/// An unverified address whose verification link still works, and the account
/// it would join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAddress {
    /// The address.
    pub address: String,
    /// The account's username, which the message names so its reader knows whose
    /// account they would confirm the address for.
    pub username: String,
}

impl EmailMessage {
    /// The message `event` sends, and the ID of the address it goes to. Runs in
    /// the event's transaction, before a removed address is deleted.
    async fn for_event(
        event: &DomainEvent,
        user_id: UserId,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Option<(EmailId, Self)>, DatabaseError> {
        Ok(match event {
            DomainEvent::EmailAdded { email_id, .. } => Some((
                *email_id,
                Self::VerifyAddress {
                    email_id: *email_id,
                },
            )),
            DomainEvent::PrimaryEmailChanged {
                previous_email_id: Some(previous),
                ..
            } => tx.emails().find(user_id, *previous).await?.map(|email| {
                let address = email.normalized_email;
                (*previous, Self::PrimaryAddressChanged { address })
            }),
            DomainEvent::EmailRemoved { email_id } => tx
                .emails()
                .find(user_id, *email_id)
                .await?
                .filter(|email| email.verified_at.is_some())
                .map(|email| {
                    let address = email.normalized_email;
                    (*email_id, Self::AddressRemoved { address })
                }),
            _ => None,
        })
    }
}

impl Channel for Email {
    const NAME: &'static str = "email";
    type Recipient = UserId;
    type Payload = EmailMessage;

    /// One message to the event's subject, for the events that send one. Its
    /// `destination` names the account and the address's ID, never the address.
    async fn deliveries(
        event: &DomainEvent,
        subject: Option<UserId>,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
        let Some(user_id) = subject else {
            return Ok(vec![]);
        };
        let message = EmailMessage::for_event(event, user_id, tx).await?;
        Ok(message
            .map(|(email_id, message)| NewDelivery {
                destination: format!("account {user_id}, address {email_id}"),
                recipient: user_id,
                payload: message,
                ordering_key: None,
            })
            .into_iter()
            .collect())
    }
}

impl EmailRepository<'_> {
    /// `user_id`'s address `id`, if it is still unverified with a working
    /// verification link, with the account's username.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn pending_address(
        &mut self,
        user_id: UserId,
        id: EmailId,
    ) -> Result<Option<PendingAddress>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                PendingAddress,
                "SELECT e.normalized_email AS address, u.username
                FROM user_emails e
                JOIN users u ON u.id = e.user_id
                JOIN email_verification_secrets s ON s.email_id = e.id
                WHERE e.user_id = $1 AND e.id = $2 AND e.verified_at IS NULL
                AND s.expires_at > now()",
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )
    }
}
