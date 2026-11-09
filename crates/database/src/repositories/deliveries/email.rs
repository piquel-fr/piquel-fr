//! The `email` channel: messages to account holders.
//!
//! A verification link's delivery stores the account and the address's ID, not
//! the address: the sender reads it when it sends, through
//! [`EmailRepository::pending_address`], so an address removed or verified in the
//! meantime, or of an account no longer active, receives nothing. Nothing secret is
//! stored either: the link's token is derived from the address's ID when the
//! message is sent.
//!
//! Every notification an event gives its subject is emailed too, to the addresses
//! [`Notification::addressees`] names, and says what the inbox says. Its delivery
//! copies the address and the notification, so removing the address cannot
//! cancel it.

use super::{Channel, NewDelivery};
use crate::{
    DatabaseError, DatabaseTransaction, Notified,
    repositories::{EmailRepository, RepositoryExecutor},
};
use piquel_common::{
    EmailId, Handle, NotificationId, RecoveryId, UserId,
    events::DomainEvent,
    notifications::{Addressees, Notification},
};
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
    /// The link of a recovery, sent to the account's primary verified address
    /// while the link works.
    RecoveryLink {
        /// The recovery, which the link's token is derived from.
        recovery_id: RecoveryId,
        /// The primary address when the recovery started.
        email_id: EmailId,
    },
    /// A notification of the account's, to one of the addresses it goes to.
    Notification {
        /// The address, copied when the notification was written.
        address: String,
        /// The notification, whose page the email links.
        notification_id: NotificationId,
        /// What it says.
        notification: Notification,
        /// The recovery it is about, while one of the account's passkeys can still
        /// undo it, whose undo page the email links.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_id: Option<RecoveryId>,
    },
}

/// A recovery whose link still works, and where it goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRecovery {
    /// The verified address the link goes to.
    pub address: String,
    /// The account's handle, which the message names.
    pub handle: Handle,
    /// SHA-256 of the link's token, which tells the key that derived it.
    pub secret_digest: Vec<u8>,
}

/// An unverified address whose verification link still works, and the account
/// it would join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAddress {
    /// The address.
    pub address: String,
    /// The account's handle, which the message names so its reader knows whose
    /// account they would confirm the address for.
    pub handle: Handle,
    /// SHA-256 of the link's token, which tells the key that derived it.
    pub secret_digest: Vec<u8>,
}

impl EmailMessage {
    /// The link `event` mails its subject, `user_id`, if it is one that mails a
    /// link, with the ID of the address it goes to.
    async fn links(
        event: &DomainEvent,
        user_id: UserId,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<(EmailId, Self)>, DatabaseError> {
        // Only the events that mail a link read the addresses.
        if !matches!(
            event,
            DomainEvent::EmailAdded { .. } | DomainEvent::RecoveryStarted { revoke: None, .. }
        ) {
            return Ok(Vec::new());
        }
        let emails = tx.emails().list(user_id).await?;
        Ok(match event {
            // An address a provider imported verified needs no link.
            DomainEvent::EmailAdded { email_id, .. } => emails
                .iter()
                .filter(|email| email.id == *email_id && email.verified_at.is_none())
                .map(|email| {
                    let message = Self::VerifyAddress { email_id: email.id };
                    (email.id, message)
                })
                .collect(),
            // A recovery's link goes to one address, the current primary one, or
            // nowhere without one. A recovery started with `--revoke` mails no
            // link, since the account's addresses may be someone else's.
            DomainEvent::RecoveryStarted {
                recovery_id,
                revoke: None,
                ..
            } => emails
                .iter()
                .filter(|email| email.verified_at.is_some() && email.is_primary)
                .map(|email| {
                    let message = Self::RecoveryLink {
                        recovery_id: *recovery_id,
                        email_id: email.id,
                    };
                    (email.id, message)
                })
                .collect(),
            _ => Vec::new(),
        })
    }

    /// The emails of `notified`, which `event` wrote, each with the ID of the
    /// address it goes to: one to each verified address of its account that its
    /// addressees name. Runs in the event's transaction, before a removed address
    /// is deleted.
    async fn notifying(
        event: &DomainEvent,
        notified: &Notified,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<(EmailId, Self)>, DatabaseError> {
        let emails = tx.emails().list(notified.user_id).await?;
        // The affected address and the recovery are the event's subject's: only
        // the subject's own notifications are about them.
        let affected = match event {
            DomainEvent::PrimaryEmailChanged {
                previous_email_id, ..
            } => *previous_email_id,
            DomainEvent::EmailRemoved { email_id } => Some(*email_id),
            _ => None,
        };
        let recovery_id = match (event, &notified.notification) {
            (
                DomainEvent::RecoveryStarted { recovery_id, .. },
                Notification::AccountSecured { kept: true },
            )
            | (DomainEvent::RecoveryCompleted { recovery_id, .. }, Notification::Recovered) => {
                Some(*recovery_id)
            }
            _ => None,
        };
        let addressees = notified.notification.addressees();
        Ok(emails
            .into_iter()
            .filter(|email| email.verified_at.is_some())
            .filter(|email| match addressees {
                Addressees::Verified => true,
                Addressees::Affected => affected == Some(email.id),
                Addressees::Primary => email.is_primary,
            })
            .map(|email| {
                let message = Self::Notification {
                    address: email.normalized_email,
                    notification_id: notified.id,
                    notification: notified.notification.clone(),
                    recovery_id,
                };
                (email.id, message)
            })
            .collect())
    }
}

impl Channel for Email {
    const NAME: &'static str = "email";
    type Recipient = UserId;
    type Payload = EmailMessage;

    /// The link the event mails its subject, if any, and one message to each
    /// address of each notified account that its notification goes to. Its
    /// `destination` names the account and the address's ID, never the address.
    async fn deliveries(
        event: &DomainEvent,
        subject: Option<UserId>,
        notified: &[Notified],
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
        let mut messages = Vec::new();
        if let Some(user_id) = subject {
            for (email_id, message) in EmailMessage::links(event, user_id, tx).await? {
                messages.push((user_id, email_id, message));
            }
        }
        for notified in notified {
            for (email_id, message) in EmailMessage::notifying(event, notified, tx).await? {
                messages.push((notified.user_id, email_id, message));
            }
        }
        Ok(messages
            .into_iter()
            .map(|(user_id, email_id, message)| NewDelivery {
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
    /// active account still has a working link, with the account's handle.
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
                r#"SELECT e.normalized_email AS address, h.handle AS "handle: Handle", r.secret_digest
                FROM user_emails e
                JOIN users u ON u.id = e.user_id
                JOIN handles h ON h.user_id = e.user_id AND h.released_at IS NULL
                JOIN account_recoveries r ON r.user_id = e.user_id
                WHERE e.user_id = $1 AND e.id = $3 AND e.verified_at IS NOT NULL
                AND r.id = $2 AND r.completed_at IS NULL AND r.cancelled_at IS NULL
                AND r.undone_at IS NULL AND r.expires_at > clock_timestamp()
                AND u.status = 'active'"#,
                user_id.as_uuid(),
                recovery_id.as_uuid(),
                email_id.as_uuid(),
            )
        )
    }

    /// `user_id`'s address `id`, if it is still unverified with a working
    /// verification link and the account is active, with the account's handle.
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
                r#"SELECT e.normalized_email AS address, h.handle AS "handle: Handle", s.secret_digest
                FROM user_emails e
                JOIN users u ON u.id = e.user_id
                JOIN handles h ON h.user_id = e.user_id AND h.released_at IS NULL
                JOIN email_verification_secrets s ON s.email_id = e.id
                WHERE e.user_id = $1 AND e.id = $2 AND e.verified_at IS NULL
                AND s.expires_at > now() AND u.status = 'active'"#,
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )
    }
}
