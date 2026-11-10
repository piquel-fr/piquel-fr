//! Announcements to accounts, such as a security incident or a change to the
//! privacy policy: drafted first, then sent.

use super::{
    CliError, Confirm, Console,
    output::{Cell, Single, Style, Time, report},
};
use crate::{AnnouncementDraft, AnnouncementRecipients, Letter, UserRef};
use clap::{Args, Subcommand};
use sourceorigin_common::{
    AnnouncementId,
    admin::{Announcement, AnnouncementDetail},
};
use std::{io::Read, path::PathBuf};

/// Drafting, sending and reading announcements. A draft goes to nobody until
/// `announcement send`, so its text can be checked with `announcement show` first.
#[derive(Subcommand)]
pub(super) enum AnnouncementCommand {
    /// List announcements, drafts and sent ones, newest first.
    List,
    /// Show an announcement: its text, whom it goes to, how many of them its
    /// email reaches, and once sent, how its emails fared.
    Show {
        /// The announcement's ID, as `announcement list` shows it.
        id: AnnouncementId,
    },
    /// Draft an announcement, and print its ID. Nothing is sent yet.
    Draft(DraftArgs),
    /// Replace a draft's subject, text and recipients.
    Edit {
        /// The draft's ID.
        id: AnnouncementId,
        /// What it becomes.
        #[command(flatten)]
        draft: DraftArgs,
    },
    /// Delete a draft.
    Discard {
        /// The draft's ID.
        id: AnnouncementId,
    },
    /// Send a draft: email it to each recipient with a primary verified address,
    /// and put it in every recipient's inbox. It cannot be taken back.
    Send {
        /// The draft's ID.
        id: AnnouncementId,
        /// The revision `announcement show` printed, which is sent only if the
        /// draft has not changed since.
        #[arg(long)]
        revision: u64,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// What a draft says, and whom it goes to.
#[derive(Args)]
pub(super) struct DraftArgs {
    /// Its subject and text.
    #[command(flatten)]
    letter: LetterArgs,
    /// Send it to every account, as of its sending.
    #[arg(long, conflicts_with = "to", required_unless_present = "to")]
    everyone: bool,
    /// Send it to this account, by handle, ID or verified email. Repeat for up to
    /// 1,000 accounts.
    #[arg(long)]
    to: Vec<UserRef>,
    /// Email it to every recipient with a primary verified address, even those
    /// who turned announcements' email off: for a security incident, or a change
    /// to the privacy policy or terms. Without it, they only find it in their
    /// inbox.
    #[arg(long)]
    essential: bool,
}

/// What an announcement or a message says.
#[derive(Args)]
pub(super) struct LetterArgs {
    /// The email's subject: one line of up to 150 characters.
    #[arg(long)]
    subject: String,
    /// The file holding the text, or `-` for standard input: up to 20,000
    /// characters, paragraphs separated by blank lines. The email starts with
    /// "Hello," and ends with "SourceOrigin".
    #[arg(long)]
    body_file: PathBuf,
}

impl LetterArgs {
    /// The letter, with its text read from `--body-file`.
    pub(super) fn letter(self) -> Result<Letter, CliError> {
        let body = if self.body_file.as_os_str() == "-" {
            let mut body = String::new();
            std::io::stdin()
                .read_to_string(&mut body)
                .map_err(CliError::BodyFile)?;
            body
        } else {
            std::fs::read_to_string(&self.body_file).map_err(CliError::BodyFile)?
        };
        Ok(Letter::new(&self.subject, &body)?)
    }
}

impl DraftArgs {
    /// The draft, with its text read from `--body-file`.
    fn draft(self) -> Result<AnnouncementDraft, CliError> {
        let recipients = if self.everyone {
            AnnouncementRecipients::Everyone
        } else {
            AnnouncementRecipients::Accounts(self.to)
        };
        Ok(AnnouncementDraft::new(
            self.letter.letter()?,
            recipients,
            self.essential,
        )?)
    }
}

impl AnnouncementCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service,
            operator,
            out,
            ..
        } = console;
        match self {
            Self::List => out.emit(&service.list_announcements(operator).await?[..])?,
            Self::Show { id } => out.emit(&service.view_announcement(operator, id).await?)?,
            Self::Draft(draft) => {
                let id = service
                    .draft_announcement(operator, &draft.draft()?)
                    .await?;
                out.emit(&Single {
                    name: "id",
                    value: id,
                })?;
            }
            Self::Edit { id, draft } => {
                let revision = service
                    .edit_announcement(operator, id, &draft.draft()?)
                    .await?;
                out.info(format_args!(
                    "Saved as revision {revision}: send it with --revision {revision}."
                ))?;
            }
            Self::Discard { id } => {
                service.discard_announcement(operator, id).await?;
                out.info(format_args!("Discarded draft {id}."))?;
            }
            Self::Send {
                id,
                revision,
                confirm,
            } => {
                let detail = service.view_announcement(operator, id).await?;
                let announcement = &detail.announcement;
                let essential = if announcement.essential {
                    "essential "
                } else {
                    ""
                };
                confirm.ask(
                    out,
                    &format!(
                        "Send the {essential}announcement \"{}\" to {} accounts, emailing the {} {}",
                        announcement.subject,
                        announcement.recipients,
                        detail.mailed,
                        announcement.emailed()
                    ),
                )?;
                let recipients = service.send_announcement(operator, id, revision).await?;
                out.info(format_args!("Sent to {recipients} accounts."))?;
            }
        }
        Ok(())
    }
}

// Announcements, newest first: drafts, and when the others were sent.
report!([Announcement], self, out, {
    out.table(
        ["ID", "STATUS", "RECIPIENTS", "SUBJECT"],
        "No announcements.",
        self.iter().map(|announcement| {
            let status = announcement.sent_at.map_or_else(
                || Cell::new("draft").style(Style::Notice),
                |at| Cell::new(format_args!("sent {}", Time(at))),
            );
            let recipients = if announcement.recipients_kept {
                Cell::new(announcement.recipients)
            } else {
                Cell::new("deleted").style(Style::Muted)
            };
            [
                Cell::new(announcement.id),
                status,
                recipients,
                Cell::new(&announcement.subject),
            ]
        }),
    )
});

// An announcement: one fact per line, the accounts it was chosen for, then its
// text. Whom a year-old announcement went to was deleted, so its counts are
// left out.
report!(AnnouncementDetail, self, out, {
    let announcement = &self.announcement;
    let to = if announcement.everyone {
        "everyone"
    } else {
        "chosen accounts"
    };
    out.title(&announcement.subject)?;
    let mut fields = vec![
        ("ID", Cell::new(announcement.id)),
        ("Revision", Cell::new(announcement.revision)),
        ("Essential", Cell::new(announcement.essentiality())),
    ];
    if announcement.recipients_kept {
        fields.extend([
            (
                "To",
                Cell::new(format_args!("{to}: {} accounts", announcement.recipients)),
            ),
            (
                "Emailed",
                Cell::new(format_args!("{} {}", self.mailed, announcement.emailed())),
            ),
        ]);
    } else {
        fields.push((
            "To",
            Cell::new(format_args!(
                "{to}: recipients deleted a year after sending"
            )),
        ));
    }
    match announcement.sent_at {
        Some(at) => {
            fields.push(("Sent", at.into()));
            if announcement.recipients_kept {
                fields.push((
                    "Read",
                    Cell::new(format_args!("{} of {}", self.read, announcement.recipients)),
                ));
            }
            let emails = self.emails;
            fields.push((
                "Emails",
                Cell::new(format_args!(
                    "{} pending, {} succeeded, {} failed, {} cancelled",
                    emails.pending, emails.succeeded, emails.failed, emails.cancelled
                )),
            ));
        }
        None => fields.push(("Sent", Cell::new("not yet: a draft").style(Style::Notice))),
    }
    out.fields(&fields)?;
    if !self.accounts.is_empty() {
        out.section("Accounts")?;
        out.table(
            ["HANDLE", "ID"],
            "",
            self.accounts
                .iter()
                .map(|account| [Cell::new(&account.handle), Cell::new(account.id)]),
        )?;
    }
    out.blank()?;
    out.text(&announcement.body)?;
    out.blank()
});
