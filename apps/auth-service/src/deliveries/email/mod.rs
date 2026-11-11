//! Sends the `email`, `announcement` and `invitation` channels over SMTP.
//!
//! A link's delivery names the account and the address's ID, and a recovery link's
//! the recovery's too: the sender reads the address when it sends, so an address
//! verified or removed, or a recovery used or undone, in the meantime receives
//! nothing, and derives the link's token again from the ID, under the key that
//! made its stored digest, so it is stored nowhere and survives a change of token
//! digest key. A notification's email carries the address it goes to and the
//! notification, and says what the inbox says. A security notification's email
//! also carries a link that signs the account out everywhere, derived from the
//! notification's ID like an unsubscribe link from the account's.
//!
//! Every attempt sends the same content, with the delivery's ID as `Message-ID`.
//! SMTP is at least once like the queue: if the connection breaks after the relay
//! accepted the message, the delivery is sent again, and mail clients that
//! deduplicate on `Message-ID` hide the copy.

use super::{DeliveryError, Failure, Sender};
use crate::{
    admin::Letter,
    config::{DashboardConfig, EmailConfig},
    emails::{VERIFICATION_LIFETIME, VerificationKeys},
    invitations::InvitationLinks,
    notifications::{SignOutLinks, UnsubscribeLinks},
    recovery::{self, RecoveryLinks},
    routes::{
        self,
        page::{self, settings},
    },
};
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{
        Mailbox, MultiPart,
        header::{HeaderName, HeaderValue},
    },
};
use sourceorigin_common::{
    AnnouncementId, DeliveryId, ErrorChain, TokenId, UserId, admin,
    config::Origin,
    notifications::{Notification, NotificationAction},
};
use sourceorigin_crypto::CryptoError;
use sourceorigin_repository::{
    Announcement, Database, DatabaseError, Delivery, Email, EmailMessage, Invitation,
    InvitationKey, OpenInvitation,
};
use sourceorigin_ui::{EmailContent, Mail};
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
    /// Builds invitation links.
    invitation_links: InvitationLinks,
    /// Builds announcements' unsubscribe links.
    unsubscribe_links: UnsubscribeLinks,
    /// Builds security notifications' sign-out links.
    sign_out_links: SignOutLinks,
    /// The admin dashboard's Alerts tab, which an alert's notification links,
    /// unless the dashboard is off.
    alerts: Option<String>,
}

impl EmailSender<AsyncSmtpTransport<Tokio1Executor>> {
    /// Sends through the configured relay, or drops everything without one,
    /// linking alerts on the `dashboard`, if auth serves one.
    pub(crate) fn new(
        database: Database,
        config: &EmailConfig,
        dashboard: Option<&DashboardConfig>,
    ) -> Self {
        Self::with_mailer(database, config.smtp.clone(), config)
            .linking(dashboard.map(|dashboard| &dashboard.origin))
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
            invitation_links: config.invitation_links.clone(),
            unsubscribe_links: config.unsubscribe_links.clone(),
            sign_out_links: config.sign_out_links.clone(),
            alerts: None,
        }
    }

    /// Links alerts' notifications to the Alerts tab of the dashboard at
    /// `dashboard`.
    pub(crate) fn linking(self, dashboard: Option<&Origin>) -> Self {
        let alerts = dashboard.map(|dashboard| dashboard.join(routes::dashboard::ALERTS));
        Self { alerts, ..self }
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
        mailer.send(self.compose(id, &content).await?).await
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
        mailer.send(self.compose(id, &content).await?).await
    }

    /// Sends the invitation `invitation_id`'s link to the address it invites, as
    /// the delivery `id`. Does nothing while email is disabled, or once the
    /// invitation was redeemed, revoked or expired, so the delivery succeeds
    /// rather than retrying.
    async fn invite(&self, id: DeliveryId, invitation_id: TokenId) -> Result<(), DeliveryError> {
        let Some(mailer) = &self.mailer else {
            tracing::info!(%id, "email is disabled; delivery dropped");
            return Ok(());
        };
        let Some(content) = self.invitation(invitation_id).await? else {
            tracing::info!(%id, "invitation is no longer open; delivery dropped");
            return Ok(());
        };
        mailer.send(self.compose(id, &content).await?).await
    }

    /// What the invitation `id`'s email says, with its link rebuilt, if it is
    /// still open and was mailed to an address.
    async fn invitation(&self, id: TokenId) -> Result<Option<Content>, DeliveryError> {
        let invitation = self
            .database
            .security()
            .open_invitation(InvitationKey::Id(id))
            .await
            .map_err(|error| Self::unread(&error))?;
        let Some(OpenInvitation {
            email: Some(address),
            secret_digest,
            expires_at,
            ..
        }) = invitation
        else {
            return Ok(None);
        };
        let link = Self::rebuilt(
            self.invitation_links.link(id, &secret_digest),
            "invitation",
            &id,
        )?;
        Ok(Some(Content {
            said: EmailContent::Invitation {
                address: address.clone(),
                link: link.into(),
                expires_at,
            },
            address,
        }))
    }

    /// What the announcement `id` says to `user_id`, at its primary verified
    /// address now, if it still has one and still receives it, with the link
    /// turning announcements' email off unless it is essential.
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
        let Some(email) = email else {
            return Ok(None);
        };
        let unsubscribe = if email.essential {
            None
        } else {
            let link = self.unsubscribe_links.link(user_id).map(Some);
            Some(Self::rebuilt(link, "unsubscribe", &user_id)?)
        };
        Ok(Some(Content::announcement(
            email.address,
            Announced {
                subject: email.subject,
                body: email.body,
                everyone: email.everyone,
                unsubscribe,
            },
            &self.origin,
        )))
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
                Content {
                    said: EmailContent::VerifyAddress {
                        address: pending.address.clone(),
                        handle: pending.handle,
                        link: format!(
                            "{}#token={}",
                            self.origin.join(settings::VERIFY),
                            token.encoded()
                        ),
                        hours: VERIFICATION_LIFETIME.num_hours(),
                    },
                    address: pending.address,
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
                Content {
                    address: pending.address,
                    said: EmailContent::RecoveryLink {
                        handle: pending.handle,
                        link: link.into(),
                        hours: recovery::LINK_LIFETIME.num_hours(),
                        undo: self.recovery_links.undo_url(*recovery_id).into(),
                    },
                }
            }
            // Administrators' own words, which read as their announcements do.
            EmailMessage::Notification {
                address,
                notification: Notification::Message { title, text },
                ..
            } => Content::message(address.clone(), title.clone(), text.clone(), &self.origin),
            EmailMessage::Notification {
                address,
                notification_id,
                notification,
                recovery_id,
            } => Content {
                address: address.clone(),
                said: EmailContent::Notification {
                    subject: notification.subject().to_owned(),
                    body: notification.body(),
                    page: self.origin.join(
                        &settings::NOTIFICATION.replace("{id}", &notification_id.to_string()),
                    ),
                    action: notification.action().and_then(|action| {
                        let href = match action {
                            NotificationAction::UndoRecovery => {
                                recovery_id.map(|id| self.recovery_links.undo_url(id).into())
                            }
                            NotificationAction::SeeAlerts => self.alerts.clone(),
                        };
                        href.map(|href| (action, href))
                    }),
                    sign_out: if notification.security() {
                        let link = self.sign_out_links.link(*notification_id).map(Some);
                        Some(Self::rebuilt(link, "sign-out", notification_id)?)
                    } else {
                        None
                    },
                },
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
    async fn compose(&self, id: DeliveryId, content: &Content) -> Result<Message, DeliveryError> {
        let built = |error: &dyn std::error::Error| {
            tracing::error!(error = %ErrorChain(error), %id, "could not build email");
            DeliveryError::Permanent(Failure::Message)
        };
        let mail = content.said.mail();
        let html = mail.html().await.map_err(|error| built(&*error))?;
        let to: Address = content
            .address
            .parse()
            .map_err(|_| DeliveryError::Permanent(Failure::InvalidAddress))?;
        let domain = self.from.email.domain();
        let mut message = Message::builder();
        for (name, value) in content.stream().headers(domain) {
            message = message.raw_header(HeaderValue::new(
                HeaderName::new_from_ascii_str(name),
                value,
            ));
        }
        message
            .from(self.from.clone())
            .to(Mailbox::new(None, to))
            .subject(&mail.subject)
            .message_id(Some(format!("<{id}@{domain}>")))
            .multipart(MultiPart::alternative_plain_html(mail.text(), html))
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

impl EmailSender<AsyncSmtpTransport<Tokio1Executor>> {
    /// The email sending `letter` as a message, linking the inbox on `auth`,
    /// auth's origin, which the dashboard shows before it is sent.
    pub(crate) fn preview(letter: &Letter, auth: &Origin) -> Mail {
        let content = Content::message(
            String::new(),
            letter.subject.clone(),
            letter.body.clone(),
            auth,
        );
        content.said.mail()
    }
}

/// Sends announcements' email through `M`, as [`EmailSender`] sends account
/// holders', on a channel of their own, so an announcement to every account never
/// holds back a verification or recovery link.
pub(crate) struct AnnouncementSender<M>(EmailSender<M>);

impl AnnouncementSender<AsyncSmtpTransport<Tokio1Executor>> {
    /// Sends through the configured relay, or drops everything without one.
    pub(crate) fn new(database: Database, config: &EmailConfig) -> Self {
        Self(EmailSender::new(database, config, None))
    }

    /// `announcement`'s email, linking the inbox on `auth`, auth's origin, which
    /// the dashboard shows before it is sent.
    pub(crate) fn preview(announcement: &admin::Announcement, auth: &Origin) -> Mail {
        // The unsubscribe link names the recipient, so the preview shows the
        // page it opens.
        let unsubscribe = (!announcement.essential).then(|| auth.join(page::UNSUBSCRIBE));
        let content = Content::announcement(
            String::new(),
            Announced {
                subject: announcement.subject.clone(),
                body: announcement.body.clone(),
                everyone: announcement.everyone,
                unsubscribe,
            },
            auth,
        );
        content.said.mail()
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

/// Sends invitations' email through `M`, as [`EmailSender`] sends account
/// holders', on a channel of their own, since an invitation's recipient has no
/// account yet.
pub(crate) struct InvitationSender<M>(EmailSender<M>);

impl InvitationSender<AsyncSmtpTransport<Tokio1Executor>> {
    /// Sends through the configured relay, or drops everything without one.
    pub(crate) fn new(database: Database, config: &EmailConfig) -> Self {
        Self(EmailSender::new(database, config, None))
    }
}

impl<M: Mailer> Sender for InvitationSender<M> {
    type Channel = Invitation;
    /// An invitation stays worth sending for days, through a long relay outage.
    const MAX_AGE: Duration = Duration::from_hours(72);

    async fn send(&self, delivery: &Delivery<Invitation>) -> Result<(), DeliveryError> {
        self.0.invite(delivery.id, delivery.recipient).await
    }
}

/// An email to send: where it goes, and what it says. Each [`EmailMessage`],
/// and each announcement's email, becomes one of these.
struct Content {
    /// Where it goes.
    address: String,
    /// What it says.
    said: EmailContent,
}

/// The kind of mail an email is, which decides the headers that tell mail
/// clients how to treat it.
enum Stream<'a> {
    /// About the account itself: links, notices and support's messages, which
    /// its owner cannot turn off.
    Transactional,
    /// Sent to many accounts at once: announcements.
    Bulk {
        /// The recipient's one-click unsubscribe link, unless they cannot turn
        /// it off, as for an essential announcement.
        unsubscribe: Option<&'a str>,
    },
}

impl Stream<'_> {
    /// The headers of mail sent from `domain` in this stream. Bulk mail names
    /// its list (RFC 2919), so mail clients can sort and filter it, and offers
    /// its unsubscribe link, which clients post to in one click (RFC 8058).
    fn headers(&self, domain: &str) -> Vec<(&'static str, String)> {
        let Self::Bulk { unsubscribe } = self else {
            return Vec::new();
        };
        let mut headers = vec![(
            "List-Id",
            format!("SourceOrigin announcements <announcements.{domain}>"),
        )];
        if let Some(link) = unsubscribe {
            headers.push(("List-Unsubscribe", format!("<{link}>")));
            headers.push(("List-Unsubscribe-Post", "List-Unsubscribe=One-Click".into()));
        }
        headers
    }
}

/// What an announcement's email says, whoever it goes to.
struct Announced {
    /// Its subject, as administrators wrote it.
    subject: String,
    /// Its text, as they wrote it.
    body: String,
    /// Whether it went to every account, rather than to chosen ones.
    everyone: bool,
    /// The link turning announcements' email off, unless it is essential.
    unsubscribe: Option<String>,
}

impl Content {
    /// The kind of mail it is. Every kind of email is named, so a new one
    /// decides.
    #[deny(clippy::wildcard_enum_match_arm)]
    fn stream(&self) -> Stream<'_> {
        match &self.said {
            EmailContent::Announcement { unsubscribe, .. } => Stream::Bulk {
                unsubscribe: unsubscribe.as_deref(),
            },
            EmailContent::VerifyAddress { .. }
            | EmailContent::RecoveryLink { .. }
            | EmailContent::Invitation { .. }
            | EmailContent::Notification { .. }
            | EmailContent::Message { .. } => Stream::Transactional,
        }
    }

    /// An announcement's email to `address`, saying what was `announced`, which
    /// links the account's inbox on `origin`.
    fn announcement(address: String, announced: Announced, origin: &Origin) -> Self {
        let Announced {
            subject,
            body,
            everyone,
            unsubscribe,
        } = announced;
        Self {
            address,
            said: EmailContent::Announcement {
                subject,
                body,
                everyone,
                inbox: origin.join(settings::NOTIFICATIONS),
                unsubscribe,
            },
        }
    }

    /// A message's email to `address`, with its `subject` and `body` as
    /// administrators wrote them, which links the account's inbox on `origin`.
    fn message(address: String, subject: String, body: String, origin: &Origin) -> Self {
        Self {
            address,
            said: EmailContent::Message {
                subject,
                body,
                inbox: origin.join(settings::NOTIFICATIONS),
            },
        }
    }
}

/// Retries, address resolution and rendering, with a fake relay.
#[cfg(test)]
mod tests;
