//! What each kind of email says.

use super::{Block, Inline, Mail};
use chrono::{DateTime, Utc};
use sourceorigin_common::{
    Handle,
    notifications::{NotificationAction, SIGN_OUT_LINK_LIFETIME},
};

/// What an email says, with every link it gives, which [`EmailContent::mail`]
/// writes out. Auth builds one for each email it sends.
#[derive(Clone, Debug)]
pub enum EmailContent {
    /// A link verifying an address the account added.
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
    /// An invitation administrators mailed to someone without an account.
    Invitation {
        /// The address it invites, which the account created with it starts
        /// with, verified.
        address: String,
        /// The registration page, with the invitation's token.
        link: String,
        /// When the link stops working.
        expires_at: DateTime<Utc>,
    },
    /// A notification of the account's.
    Notification {
        /// Its subject, which the email's is.
        subject: String,
        /// What it says.
        body: String,
        /// Its page in the inbox.
        page: String,
        /// What it offers to do, and the page that does it, while it can be
        /// done: a recovery's undo page, or the dashboard's Alerts tab.
        action: Option<(NotificationAction, String)>,
        /// The link signing the account out everywhere, for a security
        /// notification's.
        sign_out: Option<String>,
    },
    /// A message administrators sent the account, to its primary address.
    Message {
        /// Its subject, as they wrote it.
        subject: String,
        /// Its text, as they wrote it.
        body: String,
        /// The inbox, where the account reads it again.
        inbox: String,
    },
    /// An announcement administrators sent, to the account's primary address.
    Announcement {
        /// Its subject, as they wrote it.
        subject: String,
        /// Its text, as they wrote it.
        body: String,
        /// Whether it went to every account, rather than to chosen ones.
        everyone: bool,
        /// The inbox, where the account reads it again.
        inbox: String,
        /// The link turning announcements' email off, unless it is essential.
        unsubscribe: Option<String>,
    },
}

impl EmailContent {
    /// The email: its subject and what it says.
    #[must_use]
    pub fn mail(&self) -> Mail {
        Mail {
            subject: self.subject().to_owned(),
            blocks: self.blocks(),
        }
    }

    /// The email's subject.
    fn subject(&self) -> &str {
        match self {
            Self::VerifyAddress { .. } => "Confirm your email address for your Origin Account",
            Self::RecoveryLink { .. } => "Recover your Origin Account",
            Self::Invitation { .. } => "You’re invited to SourceOrigin",
            Self::Notification { subject, .. }
            | Self::Message { subject, .. }
            | Self::Announcement { subject, .. } => subject,
        }
    }

    /// What the email says.
    #[expect(
        clippy::too_many_lines,
        reason = "One arm per kind of email, each with its own words."
    )]
    fn blocks(&self) -> Vec<Block> {
        let inbox = |href: &str| Inline::Link {
            text: "your Origin Account notifications",
            href: href.to_owned(),
        };
        match self {
            Self::VerifyAddress {
                address,
                handle,
                link,
                hours,
            } => vec![
                Block::Paragraph(inlines![
                    "Someone, hopefully you, added ",
                    Inline::Strong(address.clone().into()),
                    " to the Origin Account ",
                    Inline::Strong(format!("@{handle}").into()),
                    ". If that is your account, open the link below and select “Confirm this address”.",
                ]),
                Block::Action {
                    label: "Confirm this address",
                    href: link.clone(),
                },
                Block::Paragraph(inlines![format!(
                    "The link works once, for {hours} hours. If you didn’t add this address, ignore this email: the address will be removed when the link expires."
                )]),
            ],
            Self::RecoveryLink {
                handle,
                link,
                hours,
                undo,
            } => vec![
                Block::Paragraph(inlines![
                    "SourceOrigin support started a recovery of the Origin Account ",
                    Inline::Strong(format!("@{handle}").into()),
                    ", so its owner can add a new passkey. The account was signed out everywhere. If it is yours, open the link below and follow the steps to add a passkey.",
                ]),
                Block::Action {
                    label: "Add a passkey",
                    href: link.clone(),
                },
                Block::Paragraph(inlines![
                    format!(
                        "The link works once, for {hours} hours. If you didn’t ask for this, contact SourceOrigin support. If you still have a passkey, you can also "
                    ),
                    Inline::Link {
                        text: "cancel the recovery",
                        href: undo.clone(),
                    },
                    ".",
                ]),
            ],
            Self::Invitation {
                address,
                link,
                expires_at,
            } => vec![
                Block::Paragraph(inlines![
                    "SourceOrigin invited you to create an Origin Account, the account you sign in to SourceOrigin and its apps with. Open the link below to choose a handle and add a passkey.",
                ]),
                Block::Action {
                    label: "Create your account",
                    href: link.clone(),
                },
                Block::Paragraph(inlines![
                    "Your account starts with this address, ",
                    Inline::Strong(address.clone().into()),
                    format!(
                        ", already confirmed. The link works once, until {} UTC.",
                        expires_at.format("%-d %B %Y, %H:%M")
                    ),
                ]),
                Block::Fine(inlines![
                    "If you weren’t expecting this invitation, ignore this email: no account is created unless someone opens the link.",
                ]),
            ],
            Self::Notification {
                subject,
                body,
                page,
                action,
                sign_out,
            } => {
                let mut blocks = vec![
                    Block::Paragraph(inlines![Inline::Strong(format!("{subject}.").into())]),
                    Block::Written(body.clone()),
                ];
                blocks.extend(action.iter().map(|(action, href)| Block::Action {
                    label: action.label(),
                    href: href.clone(),
                }));
                blocks.push(Block::Paragraph(inlines!["Read it in ", inbox(page), "."]));
                blocks.extend(sign_out.iter().map(|sign_out| {
                    Block::Fine(inlines![
                        "If this wasn’t you and you can’t sign in to secure your account, ",
                        Inline::Link {
                            text: "sign it out of every device and app",
                            href: sign_out.clone(),
                        },
                        format!(
                            ", without signing in. The link works once, for {} days.",
                            SIGN_OUT_LINK_LIFETIME.num_days()
                        ),
                    ])
                }));
                blocks
            }
            Self::Message {
                body, inbox: page, ..
            } => vec![
                Block::Written(body.clone()),
                Block::Fine(inlines![
                    "SourceOrigin support wrote this message about your Origin Account. It is also in ",
                    inbox(page),
                    " whenever you can sign in.",
                ]),
            ],
            Self::Announcement {
                body,
                everyone,
                inbox: page,
                unsubscribe,
                ..
            } => {
                let sent = if *everyone {
                    "SourceOrigin sent this announcement to every account."
                } else {
                    "SourceOrigin sent this announcement to your account."
                };
                let mut blocks = vec![
                    Block::Written(body.clone()),
                    Block::Fine(inlines![
                        sent,
                        " You can read it again in ",
                        inbox(page),
                        "."
                    ]),
                ];
                blocks.extend(unsubscribe.iter().map(|unsubscribe| {
                    Block::Fine(inlines![Inline::Link {
                        text: "Stop receiving announcements by email",
                        href: unsubscribe.clone(),
                    }])
                }));
                blocks
            }
        }
    }
}
