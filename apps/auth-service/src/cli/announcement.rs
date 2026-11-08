//! Announcements to accounts, such as a security incident or a change to the
//! privacy policy: drafted first, then sent.

use super::{CliError, Confirm, Console, Output};
use crate::{AnnouncementDraft, AnnouncementRecipients, UserRef};
use clap::{Args, Subcommand};
use piquel_common::AnnouncementId;
use std::{io::Read, path::PathBuf};

/// Drafting, sending and reading announcements. A draft goes to nobody until
/// `announcement send`, so its text can be checked with `announcement show` first.
#[derive(Subcommand)]
pub(super) enum AnnouncementCommand {
    /// List announcements, drafts and sent ones, newest first.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Show an announcement: its text, whom it goes to, how many of them its
    /// email reaches, and once sent, how its emails fared.
    Show {
        /// The announcement's ID, as `announcement list` shows it.
        id: AnnouncementId,
        /// Output format.
        #[command(flatten)]
        output: Output,
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
    /// The email's subject: one line of up to 150 characters.
    #[arg(long)]
    subject: String,
    /// The file holding the text, or `-` for standard input: up to 20,000
    /// characters, paragraphs separated by blank lines. The email starts with
    /// "Hello," and ends with "Piquel".
    #[arg(long)]
    body_file: PathBuf,
    /// Send it to every account, as of its sending.
    #[arg(long, conflicts_with = "to", required_unless_present = "to")]
    everyone: bool,
    /// Send it to this account, by handle, ID or verified email. Repeat for up to
    /// 1,000 accounts.
    #[arg(long)]
    to: Vec<UserRef>,
}

impl DraftArgs {
    /// The draft, with its text read from `--body-file`.
    fn draft(self) -> Result<AnnouncementDraft, CliError> {
        let body = if self.body_file.as_os_str() == "-" {
            let mut body = String::new();
            std::io::stdin()
                .read_to_string(&mut body)
                .map_err(CliError::BodyFile)?;
            body
        } else {
            std::fs::read_to_string(&self.body_file).map_err(CliError::BodyFile)?
        };
        let recipients = if self.everyone {
            AnnouncementRecipients::Everyone
        } else {
            AnnouncementRecipients::Accounts(self.to)
        };
        Ok(AnnouncementDraft::new(&self.subject, &body, recipients)?)
    }
}

impl AnnouncementCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::List { output } => {
                let announcements = service.list_announcements(operator).await?;
                output.print(&announcements, |announcements| {
                    println!("ID\tSTATUS\tRECIPIENTS\tSUBJECT");
                    for announcement in announcements {
                        let status = announcement.sent_at.map_or_else(
                            || "draft".to_owned(),
                            |at| format!("sent {}", at.to_rfc3339()),
                        );
                        let recipients = if announcement.recipients_kept {
                            announcement.recipients.to_string()
                        } else {
                            "deleted".to_owned()
                        };
                        println!(
                            "{}\t{status}\t{recipients}\t{}",
                            announcement.id, announcement.subject
                        );
                    }
                })?;
            }
            Self::Show { id, output } => {
                let detail = service.view_announcement(operator, id).await?;
                output.print(&detail, |detail| {
                    let announcement = &detail.announcement;
                    let to = if announcement.everyone {
                        "everyone"
                    } else {
                        "chosen accounts"
                    };
                    println!("ID\t{}", announcement.id);
                    println!("SUBJECT\t{}", announcement.subject);
                    println!("REVISION\t{}", announcement.revision);
                    if announcement.recipients_kept {
                        println!("TO\t{to}: {} accounts", announcement.recipients);
                        println!("EMAILED\t{} with a primary verified address", detail.mailed);
                    } else {
                        println!("TO\t{to}: recipients deleted a year after sending");
                    }
                    match announcement.sent_at {
                        Some(at) => {
                            let emails = detail.emails;
                            println!("SENT\t{}", at.to_rfc3339());
                            if announcement.recipients_kept {
                                println!("READ\t{} of {}", detail.read, announcement.recipients);
                            }
                            println!(
                                "EMAILS\t{} pending, {} succeeded, {} failed, {} cancelled",
                                emails.pending, emails.succeeded, emails.failed, emails.cancelled
                            );
                        }
                        None => println!("SENT\tnot yet: a draft"),
                    }
                    for account in &detail.accounts {
                        println!("ACCOUNT\t{}\t{}", account.handle, account.id);
                    }
                    println!("\n{}", announcement.body);
                })?;
            }
            Self::Draft(draft) => {
                let id = service
                    .draft_announcement(operator, &draft.draft()?)
                    .await?;
                println!("{id}");
            }
            Self::Edit { id, draft } => {
                let revision = service
                    .edit_announcement(operator, id, &draft.draft()?)
                    .await?;
                eprintln!("Saved as revision {revision}: send it with --revision {revision}.");
            }
            Self::Discard { id } => service.discard_announcement(operator, id).await?,
            Self::Send {
                id,
                revision,
                confirm,
            } => {
                let detail = service.view_announcement(operator, id).await?;
                let announcement = &detail.announcement;
                confirm.ask(&format!(
                    "Send \"{}\" to {} accounts, emailing the {} with a primary verified address",
                    announcement.subject, announcement.recipients, detail.mailed
                ))?;
                let recipients = service.send_announcement(operator, id, revision).await?;
                println!("Sent to {recipients} accounts");
            }
        }
        Ok(())
    }
}
