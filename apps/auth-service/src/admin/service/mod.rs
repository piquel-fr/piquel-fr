//! Every administrative operation, shared by the admin dashboard and the CLI.

/// Invitations and administrator rights: who may join, and who administers.
mod access;
/// Accounts: finding, viewing, disabling and deleting them, their sessions and
/// their handles.
mod accounts;
/// The alerts administrators are shown, and acknowledging them.
mod alerts;

pub(crate) use alerts::ALERTS_SHOWN;
/// OIDC clients and the origins approved for their pages.
mod clients;
/// The event log, the audit chain that signs it, and the deliveries events cause.
mod events;
/// Signing keys, through the key store the caller holds.
mod keys;
/// Recovering an account whose owner lost every passkey, and undoing it.
mod recovery;

use super::{AdminError, Operator, Reason};
use piquel_common::{
    UserId,
    events::{DomainEvent, EventContext},
};
use piquel_repository::{Database, DatabaseTransaction};

/// Owns each administrative operation. Dashboard pages and CLI commands are thin
/// adapters that say which [`Operator`] acts. Every mutation, and viewing an
/// account's details, records a domain event attributed to it in the same
/// transaction.
///
/// Every operation takes its [`Operator`] and checks it, so a caller in the same
/// process, such as the dashboard, needs no check of its own. Reads first require
/// an administrator to still hold their rights and session, signed in with a
/// passkey (`Operator::authorize_read`). Mutations recheck that an administrator
/// still holds their rights, session and recent confirmation after their last
/// write, just before committing. Those on accounts refuse
/// administrator accounts unless the CLI acts, so a stolen dashboard session
/// cannot lock other administrators out; revoking their rights comes first, and is itself
/// guarded. Nothing, the CLI included, revokes, disables or deletes the last
/// active administrator: each asks `AdministratorRepository::is_last_active`
/// under the administrator lock, so two such changes cannot both pass.
#[derive(Clone)]
pub struct AdminService {
    /// Accounts, sessions, invitations, clients, events, deliveries and administrators.
    pub(super) database: Database,
    /// Whether email is enabled, so a recovery link can be mailed.
    mails: bool,
}

impl AdminService {
    /// Operates on `database`, mailing recovery links if `mails`, as email is
    /// enabled.
    #[must_use]
    pub const fn new(database: Database, mails: bool) -> Self {
        Self { database, mails }
    }

    /// Ends every mutation: rechecks `operator`, records `events` about `subject`,
    /// then commits. The check runs after the mutation's last write, so it waits
    /// for nothing afterwards, and a failure rolls the writes back.
    async fn finish(
        mut tx: DatabaseTransaction<'_>,
        operator: &Operator,
        subject: Option<UserId>,
        events: Vec<DomainEvent>,
    ) -> Result<(), AdminError> {
        operator.authorize(&mut tx).await?;
        let context = operator.context();
        for event in events {
            tx.record(&context, subject, event).await?;
        }
        Ok(tx.commit().await?)
    }

    /// Shows each stored record without what the dashboard and CLI never show.
    fn views<S: Into<T>, T>(records: Vec<S>) -> Vec<T> {
        records.into_iter().map(Into::into).collect()
    }

    /// Attributes a change to `operator`, with their `reason`, which the owner
    /// sees in their history.
    fn context(operator: &Operator, reason: Reason) -> EventContext {
        EventContext {
            reason: Some(reason.into_inner()),
            ..operator.context()
        }
    }
}
