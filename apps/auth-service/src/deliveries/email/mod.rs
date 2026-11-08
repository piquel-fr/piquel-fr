//! Sends the `email` and `announcement` channels over SMTP.
//!
//! A link's delivery names the account and the address's ID, and a recovery link's
//! the recovery's too: the sender reads the address when it sends, so an address
//! verified or removed, or a recovery used or undone, in the meantime receives
//! nothing, and derives the link's token again from the ID, under the key that
//! made its stored digest, so it is stored nowhere and survives a change of token
//! digest key. A notification's email carries the address it goes to and the
//! notification, and says what the inbox says.
//!
//! Every attempt sends the same content, with the delivery's ID as `Message-ID`.
//! SMTP is at least once like the queue: if the connection breaks after the relay
//! accepted the message, the delivery is sent again, and mail clients that
//! deduplicate on `Message-ID` hide the copy.

use super::{DeliveryError, Failure, Sender};
use crate::{
    config::EmailConfig,
    emails::{VERIFICATION_LIFETIME, VerificationKeys},
    recovery::{self, RecoveryLinks},
    routes::page::settings,
};
use askama::Template;
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
};
use piquel_common::{
    AnnouncementId, DeliveryId, ErrorChain, Handle, UserId, admin, config::Origin,
};
use piquel_crypto::CryptoError;
use piquel_repository::{Announcement, Database, DatabaseError, Delivery, Email, EmailMessage};
use std::{fmt::Display, time::Duration};

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
        // The relay's reply text can quote the recipient, so only its status code
        // or failure category is kept, as the delivery's error, which the worker
        // logs. The error itself is never logged, at any level.
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
    /// Auth's origin, whose settings pages every link opens.
    origin: Origin,
    /// Derives verification tokens.
    verification_keys: VerificationKeys,
    /// Builds recovery links.
    recovery_links: RecoveryLinks,
}

impl EmailSender<AsyncSmtpTransport<Tokio1Executor>> {
    /// Sends through the configured relay, or drops everything without one.
    pub(crate) fn new(database: Database, config: &EmailConfig) -> Self {
        Self::with_mailer(database, config.smtp.clone(), config)
    }
}

impl<M: Mailer> EmailSender<M> {
    /// Sends through `mailer`, with `config`'s sender, links and keys.
    pub(crate) fn with_mailer(database: Database, mailer: Option<M>, config: &EmailConfig) -> Self {
        Self {
            database,
            mailer,
            from: config.from.clone(),
            origin: config.origin.clone(),
            verification_keys: config.verification_keys.clone(),
            recovery_links: config.recovery_links.clone(),
        }
    }

    /// Sends `message` about `user_id`'s account, as the delivery `id`. Does
    /// nothing while email is disabled, or once a link is no longer needed, so the
    /// delivery succeeds rather than retrying: a verification link's address was
    /// verified, replaced or removed, or a recovery's link was used, replaced or
    /// undone, or expired, or the account is no longer active.
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
            tracing::info!(%id, "link is no longer needed; delivery dropped");
            return Ok(());
        };
        mailer.send(self.compose(id, &content)?).await
    }

    /// Sends the announcement `announcement` to `user_id`'s primary verified
    /// address, as the delivery `id`. Does nothing while email is disabled, or
    /// once the account has no such address or is no longer a recipient, as after
    /// a purge, so the delivery succeeds rather than retrying.
    async fn announce(
        &self,
        id: DeliveryId,
        user_id: UserId,
        announcement: AnnouncementId,
    ) -> Result<(), DeliveryError> {
        let Some(mailer) = &self.mailer else {
            tracing::info!(%id, "email is disabled; delivery dropped");
            return Ok(());
        };
        let Some(content) = self.announcement(user_id, announcement).await? else {
            tracing::info!(%id, "the account has no primary address to announce to; delivery dropped");
            return Ok(());
        };
        mailer.send(self.compose(id, &content)?).await
    }

    /// What the announcement `id` says to `user_id`, at its primary verified
    /// address now, if it still has one and still receives it.
    async fn announcement(
        &self,
        user_id: UserId,
        id: AnnouncementId,
    ) -> Result<Option<Content>, DeliveryError> {
        let email = self
            .database
            .emails()
            .announcement(user_id, id)
            .await
            .map_err(|error| Self::unread(&error))?;
        Ok(email.map(|email| {
            Content::announcement(
                email.address,
                email.subject,
                email.body,
                email.everyone,
                &self.origin,
            )
        }))
    }

    /// What `message` says, with its links and the address it goes to: the one it
    /// copied, or, for a link, the address that still waits for it.
    async fn content(
        &self,
        user_id: UserId,
        message: &EmailMessage,
    ) -> Result<Option<Content>, DeliveryError> {
        Ok(Some(match message {
            EmailMessage::VerifyAddress { email_id } => {
                let pending = self
                    .database
                    .emails()
                    .pending_address(user_id, *email_id)
                    .await
                    .map_err(|error| Self::unread(&error))?;
                let Some(pending) = pending else {
                    return Ok(None);
                };
                let token = Self::rebuilt(
                    self.verification_keys
                        .rebuild(*email_id, &pending.secret_digest),
                    "verification",
                    email_id,
                )?;
                Content::VerifyAddress {
                    address: pending.address,
                    handle: pending.handle,
                    link: format!(
                        "{}#token={}",
                        self.origin.join(settings::VERIFY),
                        token.encoded()
                    ),
                    hours: VERIFICATION_LIFETIME.num_hours(),
                }
            }
            EmailMessage::RecoveryLink {
                recovery_id,
                email_id,
            } => {
                let pending = self
                    .database
                    .emails()
                    .pending_recovery(user_id, *recovery_id, *email_id)
                    .await
                    .map_err(|error| Self::unread(&error))?;
                let Some(pending) = pending else {
                    return Ok(None);
                };
                let link = Self::rebuilt(
                    self.recovery_links
                        .link(*recovery_id, &pending.secret_digest),
                    "recovery",
                    recovery_id,
                )?;
                Content::RecoveryLink {
                    address: pending.address,
                    handle: pending.handle,
                    link: link.into(),
                    hours: recovery::LINK_LIFETIME.num_hours(),
                    undo: self.recovery_links.undo_url(*recovery_id).into(),
                }
            }
            EmailMessage::Notification {
                address,
                notification_id,
                notification,
                recovery_id,
            } => Content::Notification {
                address: address.clone(),
                subject: notification.subject().to_owned(),
                body: notification.body(),
                page: self
                    .origin
                    .join(&settings::NOTIFICATION.replace("{id}", &notification_id.to_string())),
                undo: recovery_id.map(|id| self.recovery_links.undo_url(id).into()),
            },
        }))
    }

    /// A failed read of a link's recipient, retried.
    fn unread(error: &DatabaseError) -> DeliveryError {
        tracing::error!(error = %ErrorChain(error), "could not read email recipient");
        DeliveryError::Retryable {
            failure: Failure::Database,
            retry_after: None,
        }
    }

    /// A `link` of what `id` names, or its token, `rebuilt` under the key that
    /// made its stored digest. A failed derivation fails the delivery, and so does
    /// a key removed before the link was sent, which operators see, rather than
    /// send a link that matches nothing.
    fn rebuilt<T>(
        rebuilt: Result<Option<T>, CryptoError>,
        link: &'static str,
        id: &dyn Display,
    ) -> Result<T, DeliveryError> {
        match rebuilt {
            Ok(Some(rebuilt)) => return Ok(rebuilt),
            Ok(None) => tracing::error!(link, %id, "no configured key derives the link's token"),
            Err(error) => {
                let error = ErrorChain(&error);
                tracing::error!(%error, link, %id, "could not derive a link's token");
            }
        }
        Err(DeliveryError::Permanent(Failure::Message))
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
    /// A link expires after a day, and a notice that late is stale.
    const MAX_AGE: Duration = Duration::from_hours(24);

    async fn send(&self, delivery: &Delivery<Email>) -> Result<(), DeliveryError> {
        self.deliver(delivery.id, delivery.recipient, &delivery.payload)
            .await
    }
}

/// Sends announcements' email through `M`, as [`EmailSender`] sends account
/// holders', on a channel of their own, so an announcement to every account never
/// holds back a verification or recovery link.
pub(crate) struct AnnouncementSender<M>(EmailSender<M>);

impl AnnouncementSender<AsyncSmtpTransport<Tokio1Executor>> {
    /// Sends through the configured relay, or drops everything without one.
    pub(crate) fn new(database: Database, config: &EmailConfig) -> Self {
        Self(EmailSender::new(database, config))
    }

    /// The plain-text body of `announcement`'s email, linking the inbox on
    /// `auth`, auth's origin, which the dashboard shows before it is sent.
    ///
    /// # Errors
    /// Fails when the template cannot render.
    pub(crate) fn preview(
        announcement: &admin::Announcement,
        auth: &Origin,
    ) -> Result<String, askama::Error> {
        let content = Content::announcement(
            String::new(),
            announcement.subject.clone(),
            announcement.body.clone(),
            announcement.everyone,
            auth,
        );
        Text { content: &content }.render()
    }
}

impl<M: Mailer> Sender for AnnouncementSender<M> {
    type Channel = Announcement;
    /// An announcement stays worth reading for days, through a long relay outage
    /// or a slow send to every account.
    const MAX_AGE: Duration = Duration::from_hours(72);

    async fn send(&self, delivery: &Delivery<Announcement>) -> Result<(), DeliveryError> {
        self.0
            .announce(delivery.id, delivery.recipient, delivery.payload)
            .await
    }
}

/// What a message says, with everything its templates show. Each
/// [`EmailMessage`], and each announcement's email, becomes one of these.
enum Content {
    /// A verification link.
    VerifyAddress {
        /// The address to verify.
        address: String,
        /// The account it would join, named so its reader can tell whether they
        /// added it themselves.
        handle: Handle,
        /// The settings page that verifies it, with the token in its fragment, so
        /// it never reaches a server log.
        link: String,
        /// How many hours the link works.
        hours: i64,
    },
    /// A recovery's link, to the account's primary address.
    RecoveryLink {
        /// The primary address.
        address: String,
        /// The account it recovers.
        handle: Handle,
        /// The recovery page, with the token in its fragment.
        link: String,
        /// How many hours the link works.
        hours: i64,
        /// The recovery's undo page, where a passkey the owner still has cancels
        /// it.
        undo: String,
    },
    /// A notification of the account's.
    Notification {
        /// The address it goes to.
        address: String,
        /// Its subject, which the email's is.
        subject: String,
        /// What it says.
        body: String,
        /// Its page in the inbox.
        page: String,
        /// The undo page of the recovery it is about, while a passkey can undo it.
        undo: Option<String>,
    },
    /// An announcement administrators sent, to the account's primary address.
    Announcement {
        /// The primary address.
        address: String,
        /// Its subject, as they wrote it.
        subject: String,
        /// Its text, as they wrote it, for the plain-text body.
        body: String,
        /// The same text as paragraphs of lines, for the HTML body.
        paragraphs: Vec<Vec<String>>,
        /// Whether it went to every account, rather than to chosen ones.
        everyone: bool,
        /// The inbox, where the account reads it again.
        inbox: String,
    },
}

impl Content {
    /// An announcement's email to `address`, saying `subject` and `body`, which
    /// links the account's inbox on `origin`.
    fn announcement(
        address: String,
        subject: String,
        body: String,
        everyone: bool,
        origin: &Origin,
    ) -> Self {
        let paragraphs = admin::Announcement::paragraphs(&body)
            .into_iter()
            .map(|lines| lines.into_iter().map(str::to_owned).collect())
            .collect();
        Self::Announcement {
            address,
            subject,
            body,
            paragraphs,
            everyone,
            inbox: origin.join(settings::NOTIFICATIONS),
        }
    }

    /// Where the message goes.
    fn address(&self) -> &str {
        match self {
            Self::VerifyAddress { address, .. }
            | Self::RecoveryLink { address, .. }
            | Self::Notification { address, .. }
            | Self::Announcement { address, .. } => address,
        }
    }

    /// The message's subject.
    fn subject(&self) -> &str {
        match self {
            Self::VerifyAddress { .. } => "Confirm your email address for Piquel",
            Self::RecoveryLink { .. } => "Recover your Piquel account",
            Self::Notification { subject, .. } | Self::Announcement { subject, .. } => subject,
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
/// links only to auth's settings pages.
#[derive(Template)]
#[template(path = "email/message.html")]
struct Html<'a> {
    /// What it says.
    content: &'a Content,
}

/// Retries, address resolution and rendering, with a fake relay.
#[cfg(test)]
mod tests;
