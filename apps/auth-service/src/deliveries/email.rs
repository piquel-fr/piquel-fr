//! Sends the `email` channel over SMTP.
//!
//! A verification link's delivery names the account and the address's ID: the
//! sender reads the address when it sends, so an address removed or verified in
//! the meantime receives nothing, and derives the link's token again from the ID,
//! so it is stored nowhere. Notices carry the address they go to.
//!
//! Every attempt sends the same content, with the delivery's ID as `Message-ID`.
//! SMTP is at least once like the queue: if the connection breaks after the relay
//! accepted the message, the delivery is sent again, and mail clients that
//! deduplicate on `Message-ID` hide the copy.

use super::{DeliveryError, Failure, Sender};
use crate::{config::EmailConfig, emails::VERIFICATION_LIFETIME, emails::VerificationKey};
use askama::Template;
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
};
use piquel_common::{DeliveryId, ErrorChain, UserId, config::PublicUrl};
use piquel_repository::{Database, Delivery, Email, EmailMessage};
use std::time::Duration;

/// Sends a built message, classifying failures for the retry policy. The SMTP
/// relay in production; tests use a fake.
pub(crate) trait Mailer: Send + Sync + 'static {
    /// Hands `message` to the relay.
    fn send(&self, message: Message) -> impl Future<Output = Result<(), DeliveryError>> + Send;
}

impl Mailer for AsyncSmtpTransport<Tokio1Executor> {
    /// A permanent (5xx) reply fails the delivery. Temporary (4xx) replies, a
    /// rejected login (530, 534, 535), timeouts and connection or TLS failures are
    /// retried: a login fails on the relay's key, not the message, so sending
    /// resumes once the key is fixed.
    async fn send(&self, message: Message) -> Result<(), DeliveryError> {
        let Err(error) = AsyncTransport::send(self, message).await else {
            return Ok(());
        };
        // The relay's reply text can quote the recipient, so it stays out of the
        // delivery and the default logs.
        tracing::debug!(error = %ErrorChain(&error), "SMTP send failed");
        let code = error.status().map(u16::from);
        let failure = match code {
            Some(code) => Failure::Smtp(code),
            None if error.is_timeout() => Failure::Timeout,
            None => Failure::Connection,
        };
        Err(
            if error.is_permanent() && !matches!(code, Some(530 | 534 | 535)) {
                DeliveryError::Permanent(failure)
            } else {
                DeliveryError::Retryable {
                    failure,
                    retry_after: None,
                }
            },
        )
    }
}

/// Sends account holders' email through `M`.
pub(crate) struct EmailSender<M> {
    /// Where the targeted addresses are read.
    database: Database,
    /// The relay; `None` while email is disabled, which drops every delivery.
    mailer: Option<M>,
    /// The `From` of every message, whose domain ends every `Message-ID`.
    from: Mailbox,
    /// Account settings, which every link points under.
    settings_url: PublicUrl,
    /// Derives verification tokens.
    verification_key: VerificationKey,
}

impl EmailSender<AsyncSmtpTransport<Tokio1Executor>> {
    /// Sends through the configured relay, or drops everything without one.
    pub(crate) fn new(database: Database, config: &EmailConfig) -> Self {
        Self::with_mailer(database, config.smtp.clone(), config)
    }
}

impl<M: Mailer> EmailSender<M> {
    /// Sends through `mailer`, with `config`'s sender, links and key.
    pub(crate) fn with_mailer(database: Database, mailer: Option<M>, config: &EmailConfig) -> Self {
        Self {
            database,
            mailer,
            from: config.from.clone(),
            settings_url: config.settings_url.clone(),
            verification_key: config.verification_key.clone(),
        }
    }

    /// Sends `message` about `user_id`'s account, as the delivery `id`. Does
    /// nothing while email is disabled, or once a verification link's address was
    /// verified, replaced or removed, so the delivery succeeds rather than retrying.
    async fn deliver(
        &self,
        id: DeliveryId,
        user_id: UserId,
        message: &EmailMessage,
    ) -> Result<(), DeliveryError> {
        let Some(mailer) = &self.mailer else {
            tracing::info!(%id, "email is disabled; delivery dropped");
            return Ok(());
        };
        let Some(content) = self.content(user_id, message).await? else {
            tracing::info!(%id, "verification link is no longer needed; delivery dropped");
            return Ok(());
        };
        mailer.send(self.compose(id, &content)?).await
    }

    /// What `message` says, with its links and the address it goes to: the one it
    /// copied, or, for a verification link, the address that still waits for it.
    async fn content(
        &self,
        user_id: UserId,
        message: &EmailMessage,
    ) -> Result<Option<Content>, DeliveryError> {
        let settings = self.settings_url.as_url().as_str().trim_end_matches('/');
        let history = format!("{settings}/history");
        Ok(Some(match message {
            EmailMessage::VerifyAddress { email_id } => {
                let pending = self
                    .database
                    .emails()
                    .pending_address(user_id, *email_id)
                    .await
                    .map_err(|error| {
                        tracing::error!(error = %ErrorChain(&error), "could not read email recipient");
                        DeliveryError::Retryable {
                            failure: Failure::Database,
                            retry_after: None,
                        }
                    })?;
                let Some(pending) = pending else {
                    return Ok(None);
                };
                let token = self.verification_key.token(*email_id).map_err(|error| {
                    tracing::error!(error = %ErrorChain(&error), "could not derive verification token");
                    DeliveryError::Permanent(Failure::Message)
                })?;
                Content::VerifyAddress {
                    address: pending.address,
                    username: pending.username,
                    link: format!("{settings}/emails/verify#token={}", token.encoded()),
                    hours: VERIFICATION_LIFETIME.num_hours(),
                }
            }
            EmailMessage::PrimaryAddressChanged { address } => Content::PrimaryAddressChanged {
                address: address.clone(),
                history,
            },
            EmailMessage::AddressRemoved { address } => Content::AddressRemoved {
                address: address.clone(),
                history,
            },
        }))
    }

    /// Builds the message. Every attempt of a delivery builds the same one, with
    /// its ID as `Message-ID`.
    fn compose(&self, id: DeliveryId, content: &Content) -> Result<Message, DeliveryError> {
        let built = |error: &dyn std::error::Error| {
            tracing::error!(error = %ErrorChain(error), %id, "could not build email");
            DeliveryError::Permanent(Failure::Message)
        };
        let text = Text { content }.render().map_err(|error| built(&error))?;
        let html = Html { content }.render().map_err(|error| built(&error))?;
        let to: Address = content
            .address()
            .parse()
            .map_err(|_| DeliveryError::Permanent(Failure::InvalidAddress))?;
        Message::builder()
            .from(self.from.clone())
            .to(Mailbox::new(None, to))
            .subject(content.subject())
            .message_id(Some(format!("<{id}@{}>", self.from.email.domain())))
            .multipart(MultiPart::alternative_plain_html(text, html))
            .map_err(|error| built(&error))
    }
}

impl<M: Mailer> Sender for EmailSender<M> {
    type Channel = Email;
    /// A verification link expires after a day, and a notice that late is stale.
    const MAX_AGE: Duration = Duration::from_hours(24);

    async fn send(&self, delivery: &Delivery<Email>) -> Result<(), DeliveryError> {
        self.deliver(delivery.id, delivery.recipient, &delivery.payload)
            .await
    }
}

/// What a message says, with everything its templates show. Each
/// [`EmailMessage`] becomes one of these.
enum Content {
    /// A verification link.
    VerifyAddress {
        /// The address to verify.
        address: String,
        /// The account it would join, named so its reader can tell whether they
        /// added it themselves.
        username: String,
        /// The settings page that verifies it, with the token in its fragment, so
        /// it never reaches a server log.
        link: String,
        /// How many hours the link works.
        hours: i64,
    },
    /// The notice to a previous primary address.
    PrimaryAddressChanged {
        /// The previous primary address.
        address: String,
        /// The account's security history.
        history: String,
    },
    /// The notice to a removed address.
    AddressRemoved {
        /// The removed address.
        address: String,
        /// The account's security history.
        history: String,
    },
}

impl Content {
    /// Where the message goes.
    fn address(&self) -> &str {
        match self {
            Self::VerifyAddress { address, .. }
            | Self::PrimaryAddressChanged { address, .. }
            | Self::AddressRemoved { address, .. } => address,
        }
    }

    /// The message's subject.
    const fn subject(&self) -> &'static str {
        match self {
            Self::VerifyAddress { .. } => "Confirm your email address for Piquel",
            Self::PrimaryAddressChanged { .. } => "Your Piquel primary email address changed",
            Self::AddressRemoved { .. } => "Your email address was removed from Piquel",
        }
    }
}

/// The plain-text body, from `templates/email/message.txt`.
#[derive(Template)]
#[template(path = "email/message.txt")]
struct Text<'a> {
    /// What it says.
    content: &'a Content,
}

/// The HTML body, from `templates/email/message.html`: no images, no tracking,
/// links only to the settings site.
#[derive(Template)]
#[template(path = "email/message.html")]
struct Html<'a> {
    /// What it says.
    content: &'a Content,
}

/// Retries, address resolution and rendering, with a fake relay.
#[cfg(test)]
mod tests;
