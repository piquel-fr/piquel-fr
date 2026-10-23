//! Finding, showing, disabling and reactivating accounts.

use super::{CliError, Confirm, Console, Output};
use crate::{Reason, UserRef};
use clap::Subcommand;
use piquel_admin_api::{UserDetail, UserPage};
use piquel_common::UserId;

/// Accounts, in any status.
#[derive(Subcommand)]
pub(super) enum UserCommand {
    /// Search accounts by ID, or by part of a username, display name or email,
    /// ignoring case. Lists 50 at a time, by ID.
    Search {
        /// What to look for. Lists every account when empty.
        #[arg(default_value = "")]
        query: String,
        /// Continue after this account ID, the last one listed.
        #[arg(long)]
        cursor: Option<UserId>,
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Show an account's profile, status, emails, passkeys, linked identities,
    /// sessions and consents. Recorded, since it shows personal data.
    Show {
        /// The account: its username, ID or verified email.
        user: UserRef,
        /// Output format.
        #[command(flatten)]
        output: Output,
    },
    /// Disable an account and end its sessions and refresh tokens.
    Disable {
        /// The account: its username, ID or verified email.
        user: UserRef,
        /// Why, kept with the event as personal data: 1 to 500 characters.
        #[arg(long)]
        reason: Reason,
        /// Confirmation.
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Let a disabled account sign in again.
    Enable {
        /// The account: its username, ID or verified email.
        user: UserRef,
    },
}

impl UserCommand {
    /// Runs this command as the operator at this terminal.
    pub(super) async fn run(self, console: &Console) -> Result<(), CliError> {
        let Console {
            service, operator, ..
        } = console;
        match self {
            Self::Search {
                query,
                cursor,
                output,
            } => output.print(
                &service.search_users(&query, cursor).await?,
                Self::print_page,
            )?,
            Self::Show { user, output } => {
                let id = console.user(&user).await?;
                output.print(&service.view_user(operator, id).await?, Self::print_detail)?;
            }
            Self::Disable {
                user,
                reason,
                confirm,
            } => {
                let id = console.user(&user).await?;
                confirm.ask(&format!("Disable {user} ({id}) and end its sessions"))?;
                service.disable_user(operator, id, reason).await?;
            }
            Self::Enable { user } => {
                let id = console.user(&user).await?;
                service.enable_user(operator, id).await?;
            }
        }
        Ok(())
    }

    /// Prints one account per line, and how to continue if there may be more.
    fn print_page(page: &UserPage) {
        println!("ID\tUSERNAME\tSTATUS\tCREATED\tNAME");
        for user in &page.users {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                user.id,
                user.username,
                user.status,
                user.created_at.to_rfc3339(),
                user.display_name
            );
        }
        if let Some(next) = page.next {
            eprintln!("More may follow: --cursor {next}");
        }
    }

    /// Prints an account's facts, then one section per kind of record.
    fn print_detail(detail: &UserDetail) {
        let user = &detail.user;
        println!("{} ({})", user.username, user.id);
        println!("Name:\t{}", user.display_name);
        println!("Status:\t{}", user.status);
        println!("Created:\t{}", user.created_at.to_rfc3339());
        println!("Administrator:\t{}", detail.administrator);
        println!("\nEMAIL\tVERIFIED\tPRIMARY");
        for email in &detail.emails {
            println!(
                "{}\t{}\t{}",
                email.address,
                email
                    .verified_at
                    .map_or_else(|| "-".to_owned(), |at| at.to_rfc3339()),
                email.primary
            );
        }
        println!("\nPASSKEY\tNAME");
        for passkey in &detail.passkeys {
            println!("{}\t{}", passkey.id, passkey.friendly_name);
        }
        println!("\nPROVIDER\tEMAIL");
        for identity in &detail.identities {
            println!(
                "{}\t{}",
                identity.provider,
                identity.linked_email.as_deref().unwrap_or("-")
            );
        }
        println!("\nSESSION\tMETHODS\tSIGNED IN\tLAST SEEN\tEXPIRES");
        for session in &detail.sessions {
            let methods: Vec<_> = session.methods.iter().map(ToString::to_string).collect();
            println!(
                "{}\t{}\t{}\t{}\t{}",
                session.id,
                methods.join(","),
                session.authenticated_at.to_rfc3339(),
                session.last_seen_at.to_rfc3339(),
                session.expires_at.to_rfc3339()
            );
        }
        println!("\nCLIENT\tSCOPES");
        for consent in &detail.consents {
            println!("{}\t{}", consent.client_id, consent.scopes.join(" "));
        }
    }
}
