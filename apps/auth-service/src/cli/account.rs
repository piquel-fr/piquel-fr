//! Changing one account's settings on its owner's behalf, with the owner's own
//! operations.

use super::{CliError, Confirm, Console, Output};
use crate::{
    Reason, UserRef,
    account::{AccountOperation, Subject, Viewer},
    emails::EmailView,
    history::HistoryPage,
    sessions::{Revoked, SessionItem},
};
use clap::{Args, Subcommand};
use piquel_common::{
    EmailId, EventId, PasskeyId, Provider, SessionId, UserId,
    protocol::api::{Identity, Passkey},
};

/// One account's settings, as its owner sees and changes them. Every change needs
/// a reason, recorded with it and shown to the owner in their security history.
#[derive(Args)]
pub(super) struct AccountCommand {
    /// The account: its handle, ID or verified email.
    user: UserRef,
    /// The setting to read or change.
    #[command(subcommand)]
    setting: Setting,
}

/// The settings an operator may read or change: never one that adds a way to
/// sign in or to receive the account's email.
#[derive(Subcommand)]
enum Setting {
    /// List, rename or remove passkeys.
    #[command(subcommand)]
    Passkeys(Passkeys),
    /// List or unlink social sign-ins.
    #[command(subcommand)]
    Identities(Identities),
    /// List email addresses, choose the primary one, or remove one.
    #[command(subcommand)]
    Emails(Emails),
    /// List sessions, or sign them out.
    #[command(subcommand)]
    Sessions(Sessions),
    /// Page through the security history as the owner sees it, newest first.
    History {
        /// Continue with entries older than this one, the last one listed.
        #[arg(long)]
        before: Option<EventId>,
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
}

/// The account's passkeys.
#[derive(Subcommand)]
enum Passkeys {
    /// List the active passkeys.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Rename a passkey.
    Rename {
        /// The passkey's ID, as `list` shows it.
        passkey: PasskeyId,
        /// The new name.
        name: String,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
    /// Remove a passkey and sign the account out everywhere. One passkey always
    /// remains.
    Revoke {
        /// The passkey's ID, as `list` shows it.
        passkey: PasskeyId,
        /// Why.
        #[command(flatten)]
        change: Change,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// The account's linked social sign-ins.
#[derive(Subcommand)]
enum Identities {
    /// List the linked providers.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Unlink a provider and sign the account out everywhere.
    Unlink {
        /// The provider: `github` or `google`.
        provider: Provider,
        /// Why.
        #[command(flatten)]
        change: Change,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// The account's email addresses.
#[derive(Subcommand)]
enum Emails {
    /// List the addresses, primary first.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Make a verified address the primary one, which applications receive. The
    /// previous one is told.
    Primary {
        /// The address's ID, as `list` shows it.
        email: EmailId,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
    /// Remove an address, which is told if it was verified. The primary address
    /// goes last.
    Remove {
        /// The address's ID, as `list` shows it.
        email: EmailId,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
}

/// The account's sessions, one per signed-in browser.
#[derive(Subcommand)]
enum Sessions {
    /// List the active sessions, most recently active first.
    List {
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Sign one session out, with its applications' refresh tokens.
    Revoke {
        /// The session's ID, as `list` shows it.
        session: SessionId,
        /// Why.
        #[command(flatten)]
        change: Change,
    },
    /// Sign every session out, with their applications' refresh tokens.
    RevokeAll {
        /// Why.
        #[command(flatten)]
        change: Change,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
}

/// The `--reason` every change takes.
#[derive(Args)]
struct Change {
    /// Why: 1 to 500 characters, recorded with the change. The account's owner
    /// sees it in their security history.
    #[arg(long)]
    reason: Reason,
}

impl Change {
    /// The operator at this terminal changing `user`, for this reason.
    fn on(self, user: UserId, console: &Console) -> Subject {
        Subject::operator(user, console.operator.clone(), self.reason)
    }
}

impl AccountCommand {
    /// The operation this command runs. The match is exhaustive, so a new command
    /// does not compile until it names one.
    pub(super) const fn operation(&self) -> AccountOperation {
        type Op = AccountOperation;
        match &self.setting {
            Setting::Passkeys(command) => match command {
                Passkeys::List { .. } => Op::ListPasskeys,
                Passkeys::Rename { .. } => Op::RenamePasskey,
                Passkeys::Revoke { .. } => Op::RevokePasskey,
            },
            Setting::Identities(command) => match command {
                Identities::List { .. } => Op::ListIdentities,
                Identities::Unlink { .. } => Op::UnlinkIdentity,
            },
            Setting::Emails(command) => match command {
                Emails::List { .. } => Op::ListEmails,
                Emails::Primary { .. } => Op::MakeEmailPrimary,
                Emails::Remove { .. } => Op::RemoveEmail,
            },
            Setting::Sessions(command) => match command {
                Sessions::List { .. } => Op::ListSessions,
                Sessions::Revoke { .. } => Op::RevokeSession,
                Sessions::RevokeAll { .. } => Op::RevokeOtherSessions,
            },
            Setting::History { .. } => Op::ViewHistory,
        }
    }

    /// Runs this command as the operator at this terminal. Reads are recorded as
    /// views of the account, as `user show` is.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Self { user, setting } = self;
        let id = console.user(&user).await?;
        let account = &console.account;
        let read = || Viewer::operator(id, console.operator.clone());
        match setting {
            Setting::Passkeys(Passkeys::List { output }) => {
                output.print(&account.passkeys(&read()).await?[..], Self::print_passkeys)?;
            }
            Setting::Passkeys(Passkeys::Rename {
                passkey,
                name,
                change,
            }) => {
                account
                    .rename_passkey(&change.on(id, console), passkey, name)
                    .await?;
            }
            Setting::Passkeys(Passkeys::Revoke {
                passkey,
                change,
                confirm,
            }) => {
                confirm.ask(&format!(
                    "Remove passkey {passkey} of {user} ({id}) and sign it out everywhere"
                ))?;
                let subject = change.on(id, console);
                account.revoke_passkey(&subject, passkey).await?;
            }
            Setting::Identities(Identities::List { output }) => {
                output.print(
                    &account.identities(&read()).await?[..],
                    Self::print_identities,
                )?;
            }
            Setting::Identities(Identities::Unlink {
                provider,
                change,
                confirm,
            }) => {
                confirm.ask(&format!(
                    "Unlink {provider} from {user} ({id}) and sign it out everywhere"
                ))?;
                let subject = change.on(id, console);
                account.unlink_identity(&subject, provider).await?;
            }
            Setting::Emails(Emails::List { output }) => {
                output.print(&account.emails(&read()).await?[..], Self::print_emails)?;
            }
            Setting::Emails(Emails::Primary { email, change }) => {
                let subject = change.on(id, console);
                account.make_primary_email(&subject, email).await?;
            }
            Setting::Emails(Emails::Remove { email, change }) => {
                let subject = change.on(id, console);
                account.remove_email(&subject, email).await?;
            }
            Setting::Sessions(Sessions::List { output }) => {
                output.print(&account.sessions(&read()).await?[..], Self::print_sessions)?;
            }
            Setting::Sessions(Sessions::Revoke { session, change }) => {
                account
                    .revoke_session(&change.on(id, console), session)
                    .await?;
            }
            Setting::Sessions(Sessions::RevokeAll { change, confirm }) => {
                confirm.ask(&format!("Sign {user} ({id}) out everywhere"))?;
                let Revoked { revoked } = account
                    .revoke_other_sessions(&change.on(id, console))
                    .await?;
                eprintln!("Signed out {revoked} sessions.");
            }
            Setting::History { before, output } => {
                output.print(
                    &account.history(&read(), before).await?,
                    Self::print_history,
                )?;
            }
        }
        Ok(())
    }

    /// Prints one passkey per line.
    fn print_passkeys(passkeys: &[Passkey]) {
        println!("ID\tNAME");
        for passkey in passkeys {
            println!("{}\t{}", passkey.id, passkey.friendly_name);
        }
    }

    /// Prints one linked provider per line.
    fn print_identities(identities: &[Identity]) {
        println!("PROVIDER\tEMAIL");
        for identity in identities {
            println!(
                "{}\t{}",
                identity.provider,
                identity.linked_email.as_deref().unwrap_or("-")
            );
        }
    }

    /// Prints one address per line.
    fn print_emails(emails: &[EmailView]) {
        println!("ID\tADDRESS\tVERIFIED\tPRIMARY");
        for email in emails {
            println!(
                "{}\t{}\t{}\t{}",
                email.id, email.address, email.verified, email.primary
            );
        }
    }

    /// Prints one session per line.
    fn print_sessions(sessions: &[SessionItem]) {
        println!("ID\tMETHODS\tDEVICE\tIP\tSIGNED IN\tLAST SEEN\tEXPIRES");
        for session in sessions {
            let methods: Vec<_> = session.methods.iter().map(ToString::to_string).collect();
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                session.id,
                methods.join(","),
                session
                    .device
                    .map_or_else(|| "-".to_owned(), |device| device.to_string()),
                session
                    .ip
                    .map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                session.authenticated_at.to_rfc3339(),
                session.last_seen_at.to_rfc3339(),
                session.expires_at.to_rfc3339()
            );
        }
    }

    /// Prints one entry per line, by its `kind`, and how to continue if there may
    /// be more.
    fn print_history(page: &HistoryPage) {
        println!("ID\tTIME\tKIND\tBY\tREASON");
        for item in &page.entries {
            // An entry holds no map, so it always serializes.
            let entry = serde_json::to_value(&item.entry).unwrap_or_default();
            println!(
                "{}\t{}\t{}\t{}\t{}",
                item.id,
                item.occurred_at.to_rfc3339(),
                entry["kind"].as_str().unwrap_or("-"),
                item.actor,
                item.reason.as_deref().unwrap_or("-")
            );
        }
        if let Some(next) = page.next {
            eprintln!("More may follow: --before {next}");
        }
    }
}
