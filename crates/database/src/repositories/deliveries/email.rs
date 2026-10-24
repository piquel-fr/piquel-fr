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
use piquel_common::{EmailId, RecoveryId, UserId, events::DomainEvent};
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
    /// The link of a recovery, sent to the account's primary verified address
    /// while the link works.
    RecoveryLink {
        /// The recovery, which the link's token is derived from.
        recovery_id: RecoveryId,
        /// The primary address when the recovery started.
        email_id: EmailId,
    },
    /// Tells a verified address that a recovery enrolled a passkey, which an older
    /// passkey can undo.
    Recovered {
        /// The address.
        address: String,
    },
}

/// A recovery whose link still works, and where it goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRecovery {
    /// The verified address the link goes to.
    pub address: String,
    /// The account's username, which the message names.
    pub username: String,
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
    /// The messages `event` sends, each with the ID of the address it goes to.
    /// Runs in the event's transaction, before a removed address is deleted.
    async fn for_event(
        event: &DomainEvent,
        user_id: UserId,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<(EmailId, Self)>, DatabaseError> {
        Ok(match event {
            // A recovery's link goes to one address, the primary one; the notice
            // that it enrolled a passkey to every verified address, so a
            // compromised one cannot hide it.
            DomainEvent::RecoveryStarted { recovery_id, .. } => tx
                .emails()
                .list(user_id)
                .await?
                .into_iter()
                .filter(|email| email.is_primary && email.verified_at.is_some())
                .map(|email| {
                    let message = Self::RecoveryLink {
                        recovery_id: *recovery_id,
                        email_id: email.id,
                    };
                    (email.id, message)
                })
                .collect(),
            DomainEvent::RecoveryCompleted { .. } => tx
                .emails()
                .list(user_id)
                .await?
                .into_iter()
                .filter(|email| email.verified_at.is_some())
                .map(|email| {
                    let address = email.normalized_email;
                    (email.id, Self::Recovered { address })
                })
                .collect(),
            event => Self::for_address(event, user_id, tx)
                .await?
                .into_iter()
                .collect(),
        })
    }

    /// The one message `event` sends about an address, and that address's ID.
    async fn for_address(
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
        let messages = EmailMessage::for_event(event, user_id, tx).await?;
        Ok(messages
            .into_iter()
            .map(|(email_id, message)| NewDelivery {
                destination: format!("account {user_id}, address {email_id}"),
                recipient: user_id,
                payload: message,
                ordering_key: None,
            })
            .collect())
    }
}

impl EmailRepository<'_> {
    /// `user_id`'s verified address `email_id`, if recovery `recovery_id` of the
    /// account still has a working link, with the account's username.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn pending_recovery(
        &mut self,
        user_id: UserId,
        recovery_id: RecoveryId,
        email_id: EmailId,
    ) -> Result<Option<PendingRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                PendingRecovery,
                "SELECT e.normalized_email AS address, u.username
                FROM user_emails e
                JOIN users u ON u.id = e.user_id
                JOIN account_recoveries r ON r.user_id = e.user_id
                WHERE e.user_id = $1 AND e.id = $3 AND e.verified_at IS NOT NULL
                AND r.id = $2 AND r.completed_at IS NULL AND r.cancelled_at IS NULL
                AND r.undone_at IS NULL AND r.expires_at > now()",
                user_id.as_uuid(),
                recovery_id.as_uuid(),
                email_id.as_uuid(),
            )
        )
    }

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
