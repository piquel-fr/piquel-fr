//! Who runs an administrative operation: an administrator signed in to the admin
//! dashboard, or an operator at the terminal.

use super::AdminError;
use crate::security::{CONFIRMATION_MAX_AGE, RequestContext};
use chrono::{DateTime, Duration, Utc};
use sourceorigin_common::{
    SessionId, UserId,
    config::{ConfigurationError, Variable},
    events::{Actor, DomainEvent, EventContext, RequestOrigin},
    protocol::{claims::Acr, step_up::StepUpRequirement},
};
use sourceorigin_repository::{
    Database, DatabaseError, DatabaseTransaction, SessionAuthentication, StoredSession, StoredUser,
};
use std::str::FromStr;
use thiserror::Error;

/// Who runs commands at this terminal, when `--operator` does not say.
const OPERATOR: Variable = Variable::new("AUTH_OPERATOR");
/// The operating system user, who runs commands when neither `--operator` nor
/// `AUTH_OPERATOR` says who does.
const OS_USER: Variable = Variable::new("USER");
/// The machine's host name, for systems without `/proc`.
const HOST_NAME: Variable = Variable::new("HOSTNAME");
/// Where Linux exposes the host name.
const HOST_NAME_FILE: &str = "/proc/sys/kernel/hostname";
/// What nobody may be named, and the host recorded when its name cannot be read.
const UNKNOWN: &str = "unknown";
/// Maximum characters in an operator's name.
const MAX_OPERATOR_CHARS: usize = 64;

/// Any passkey sign-in, however old: what every read needs.
const PASSKEY: StepUpRequirement = StepUpRequirement {
    acr: Some(Acr::PhishingResistant),
    max_age: None,
};
/// A passkey confirmation recent enough for a mutation.
const RECENT_PASSKEY: StepUpRequirement = StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE);
/// How long one recorded view of an account covers the same viewer's later reads
/// of it, so an investigation reloading the account's pages records one view an
/// hour, not one per page.
const VIEW_WINDOW: Duration = Duration::hours(1);

/// Who runs an administrative operation: an administrator through the admin
/// dashboard, or an operator at the command line.
#[derive(Clone, Debug)]
pub enum Operator {
    /// An administrator, signed in to the dashboard.
    Admin(AdminSession),
    /// An operator running `auth-service`.
    Cli {
        /// Who they are.
        name: OperatorName,
        /// The machine's host name.
        host: String,
    },
}

/// Who runs a command at the terminal, as the events it causes record them: 1 to
/// 64 characters, without whitespace or control characters, and never
/// `unknown`, so no change is recorded as nobody's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorName(String);

/// An operator's name that breaks [`OperatorName`]'s rule.
#[derive(Debug, Error)]
#[error("must be 1 to 64 characters without spaces, and not `unknown`")]
pub struct InvalidOperatorName;

impl FromStr for OperatorName {
    type Err = InvalidOperatorName;
    /// Accepts `value` unchanged if it satisfies the rule.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.chars().count() > MAX_OPERATOR_CHARS
            || value.chars().any(|c| c.is_whitespace() || c.is_control())
            || value.eq_ignore_ascii_case(UNKNOWN)
        {
            return Err(InvalidOperatorName);
        }
        Ok(Self(value.to_owned()))
    }
}

impl OperatorName {
    /// The operator the environment names: `AUTH_OPERATOR`, else `$USER`, which
    /// `piquelctl app exec` sets neither of.
    ///
    /// # Errors
    /// [`ConfigurationError`] when the variable read is not a valid name.
    pub(crate) fn from_environment() -> Result<Option<Self>, ConfigurationError> {
        match OPERATOR.parse_optional()? {
            Some(name) => Ok(Some(name)),
            None => OS_USER.parse_optional(),
        }
    }
}

/// An administrator signed in to the admin dashboard. Its fields are private to
/// the admin module, so only [`DashboardSignIn`](super::DashboardSignIn) creates
/// one, from the dashboard's session cookie: no other code can act as an
/// administrator.
#[derive(Clone, Copy, Debug)]
pub struct AdminSession {
    /// The administrator's account.
    pub(super) user_id: UserId,
    /// The auth session the dashboard's session rests on.
    pub(super) session_id: SessionId,
    /// When a passkey last confirmed the dashboard's session, for it: a
    /// confirmation of the auth session never counts.
    pub(super) confirmed_at: Option<DateTime<Utc>>,
    /// Where the administrator's request came from.
    pub(super) context: RequestContext,
}

impl Operator {
    /// `name` running a command at this terminal, on this host, or `unknown` where
    /// its name cannot be read.
    pub(crate) fn terminal(name: OperatorName) -> Result<Self, ConfigurationError> {
        let host = std::fs::read_to_string(HOST_NAME_FILE)
            .ok()
            .map(|host| host.trim().to_owned())
            .or(HOST_NAME.optional()?)
            .filter(|host| !host.is_empty());
        Ok(Self::Cli {
            name,
            host: host.unwrap_or_else(|| UNKNOWN.to_owned()),
        })
    }

    /// Attributes events to this operator: an administrator from their browser's
    /// request, an operator from the terminal, which has no client origin.
    #[must_use]
    pub fn context(&self) -> EventContext {
        match self.clone() {
            Self::Admin(session) => session.context.actor(Actor::Admin {
                user_id: session.user_id,
                session_id: session.session_id,
            }),
            Self::Cli { name, host } => EventContext {
                actor: Actor::Cli {
                    os_user: name.0,
                    host,
                },
                origin: RequestOrigin::default(),
                reason: None,
            },
        }
    }

    /// Records in `tx` that this operator viewed `user_id`'s account, which holds
    /// personal data, unless they already did, in this same session, within
    /// [`VIEW_WINDOW`]. Two reads at once may both record; a page's reads run one
    /// after another.
    pub(crate) async fn record_view(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<(), DatabaseError> {
        let context = self.context();
        let event = DomainEvent::AccountViewed {};
        let since = Utc::now() - VIEW_WINDOW;
        if !tx
            .events()
            .caused_since(&context.actor, user_id, event.kind(), since)
            .await?
        {
            tx.record(&context, Some(user_id), event).await?;
        }
        Ok(())
    }

    /// Whether the operator's passkey confirmation will still meet a mutation's
    /// requirement `ahead` from now, so that a form shown now can still be
    /// submitted. The terminal needs none.
    pub(crate) fn is_confirmed(&self, ahead: Duration) -> bool {
        self.confirmation_left() >= ahead
    }

    /// How much longer the operator's passkey confirmation meets a mutation's
    /// requirement: less than zero once it ended, and the least there is without
    /// one. The terminal's never ends.
    pub(crate) fn confirmation_left(&self) -> Duration {
        match self {
            Self::Admin(session) => session.confirmed_at.map_or(Duration::MIN, |at| {
                at + Duration::seconds(CONFIRMATION_MAX_AGE.into()) - Utc::now()
            }),
            Self::Cli { .. } => Duration::MAX,
        }
    }

    /// The auth session an administrator acts in; the terminal has none.
    pub(crate) const fn session(&self) -> Option<SessionId> {
        match self {
            Self::Admin(session) => Some(session.session_id),
            Self::Cli { .. } => None,
        }
    }

    /// The administrator's account, if an administrator acts.
    pub(super) const fn administrator(&self) -> Option<UserId> {
        match self {
            Self::Admin(session) => Some(session.user_id),
            Self::Cli { .. } => None,
        }
    }

    /// Refuses an administrator changing their own rights, which the CLI may.
    pub(super) fn refuse_own_rights(&self, user_id: UserId) -> Result<(), AdminError> {
        match self.administrator() {
            Some(administrator) if administrator == user_id => Err(AdminError::OwnRights),
            _ => Ok(()),
        }
    }

    /// Locks the account `user_id` for a change, and returns it. An administrator
    /// may not change another administrator's account, which only the CLI may:
    /// granting rights takes the same account lock, so the account cannot become an
    /// administrator before `tx` commits, and a known administrator is refused
    /// before waiting for the lock, too.
    pub(crate) async fn lock(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<StoredUser, AdminError> {
        let checked = self.administrator().is_some();
        if checked && tx.administrators().contains(user_id).await? {
            return Err(AdminError::AdministratorTarget);
        }
        let user = tx
            .users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        if checked && tx.administrators().contains(user_id).await? {
            return Err(AdminError::AdministratorTarget);
        }
        Ok(user)
    }

    /// Requires an administrator to still hold their rights, their session and a
    /// passkey confirmation recent enough for a mutation. The rights stay
    /// share-locked until `tx` ends, so revoking them waits for the operation, or
    /// wins before it; only revocations, which serialize on their own table lock,
    /// ever lock that row, so this lock joins no cycle.
    ///
    /// Mutations call it after their last write, just before committing (see
    /// `AdminService::finish`), so the times are compared with the clock when
    /// nothing is left to wait for. The session is read then, not locked: a
    /// session lock taken last could still meet a transaction that holds it and
    /// waits for one of this one's, such as the caller's own sign-in or social
    /// linking. A sign-out or account disablement that commits between this read
    /// and the commit does not stop the operation.
    pub(crate) async fn authorize(
        &self,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<(), AdminError> {
        let Self::Admin(session) = self else {
            return Ok(());
        };
        let held = tx
            .administrators()
            .contains_for_share(session.user_id)
            .await?;
        let stored = tx.sessions().find_active_by_id(session.session_id).await?;
        session.check(stored, held, RECENT_PASSKEY)
    }

    /// Share-locks an administrator's rights until `tx` ends, refusing one who no
    /// longer holds them, before anything in `tx` locks their account: a purge
    /// of them, which deletes the rights first, then waits rather than
    /// deadlocks. A change takes it before recording an event that may notify
    /// every administrator, which locks their rights too. Checks nothing else,
    /// so what the caller needs stays as it was.
    pub(crate) async fn hold_rights(
        &self,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<(), AdminError> {
        let Self::Admin(session) = self else {
            return Ok(());
        };
        if tx
            .administrators()
            .contains_for_share(session.user_id)
            .await?
        {
            Ok(())
        } else {
            Err(AdminError::NotAdministrator)
        }
    }

    /// Requires an administrator to still hold their rights and their session,
    /// signed in with a passkey: what every read needs, before it reads. Reads
    /// lock nothing, so this reads `database` directly. The CLI may always read.
    pub(crate) async fn authorize_read(&self, database: &Database) -> Result<(), AdminError> {
        let Self::Admin(session) = self else {
            return Ok(());
        };
        session.check(
            database
                .sessions()
                .find_active_by_id(session.session_id)
                .await?,
            database.administrators().contains(session.user_id).await?,
            PASSKEY,
        )
    }
}

impl AdminSession {
    /// Requires `stored`, the auth session as read now, to be active and this
    /// administrator's, the account to still be an administrator (`held`), and the
    /// session to meet `requirement`: signed in with a passkey, and for a mutation,
    /// the dashboard's own confirmation recent enough. Every check of an
    /// administrator comes down to this one.
    fn check(
        &self,
        stored: Option<StoredSession>,
        held: bool,
        requirement: StepUpRequirement,
    ) -> Result<(), AdminError> {
        let stored = stored
            .filter(|session| session.user_id == self.user_id && session.expires_at > Utc::now())
            .ok_or(AdminError::SessionEnded)?;
        if !held {
            return Err(AdminError::NotAdministrator);
        }
        let signed_in = SessionAuthentication::from(&stored).acr;
        requirement
            .check(Some(&signed_in), self.confirmed_at, Utc::now())
            .map_err(AdminError::StepUpRequired)
    }
}
