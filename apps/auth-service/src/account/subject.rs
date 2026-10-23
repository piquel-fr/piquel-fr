//! The account a shared settings request reads or changes, and who acts on it.

use super::{AccountApplication, AccountError};
use crate::{
    AdminError, Operator, Reason,
    admin::AdminTokens,
    security::{ApiError, CONFIRMATION_MAX_AGE, Confirmed, RequestContext, Session},
};
use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use piquel_common::{
    SessionId, UserId,
    events::{DomainEvent, EventContext},
};
use piquel_repository::{Database, DatabaseTransaction, SessionScope, StoredSession};
use serde::Deserialize;
use std::ops::Deref;

/// Where the shared settings routes are mounted, which decides who acts through
/// them.
#[derive(Clone)]
pub(crate) enum Mount {
    /// `/account` on the public listener: the signed-in owner, through their
    /// browser session, under the browser policy.
    Owner,
    /// `/users/{user_id}/account` on the private admin listener: an administrator,
    /// through an admin API token, on another account.
    Admin(AdminTokens),
}

/// The account a shared settings request reads or changes, and who acts on it.
/// Operations take it instead of a session, so they serve the owner, an
/// administrator and the CLI alike.
pub(crate) struct Subject {
    /// The account.
    pub(crate) user: UserId,
    /// Who acts on it.
    pub(crate) by: ActingAs,
}

/// Who acts on a [`Subject`].
pub(crate) enum ActingAs {
    /// The account's own user, signed in with `session`, from `context`.
    Owner {
        /// The owner's browser session.
        session: StoredSession,
        /// Where the request came from.
        context: RequestContext,
    },
    /// An administrator through the admin mount, or an operator at the command
    /// line. A change carries their reason; a read has none.
    Operator {
        /// Who acts.
        operator: Operator,
        /// Why, for a change.
        reason: Option<Reason>,
    },
}

/// A [`Subject`] whose owner confirmed their session with a passkey at most
/// `MAX_AGE` seconds ago, for changes that need one. Administrators need a recent
/// passkey sign-in for every change on the admin mount, which [`Subject`] already
/// requires of them, and operators at the command line need none.
pub(crate) struct ConfirmedSubject<const MAX_AGE: u32 = CONFIRMATION_MAX_AGE>(pub(crate) Subject);

/// The `{user_id}` of the admin mount's path. Other parameters of the path are
/// the shared route's own.
#[derive(Deserialize)]
struct Target {
    /// The account an administrator acts on.
    user_id: UserId,
}

impl Subject {
    /// An administrator or operator acting on `user`, with `reason` for a change.
    pub(crate) const fn operator(user: UserId, operator: Operator, reason: Option<Reason>) -> Self {
        Self {
            user,
            by: ActingAs::Operator { operator, reason },
        }
    }

    /// Attributes events to whoever acts. An administrator's or operator's reason
    /// goes with them, as personal data the owner sees in their history.
    pub(crate) fn context(&self) -> EventContext {
        match &self.by {
            ActingAs::Owner { session, context } => context.user(session),
            ActingAs::Operator { operator, reason } => EventContext {
                reason: reason.clone().map(Reason::into_inner),
                ..operator.context()
            },
        }
    }

    /// The owner's own session, if the owner acts.
    pub(crate) const fn own_session(&self) -> Option<SessionId> {
        match &self.by {
            ActingAs::Owner { session, .. } => Some(session.id),
            ActingAs::Operator { .. } => None,
        }
    }

    /// The sessions a change ends when it signs the account out elsewhere: every
    /// one but the owner's own, or every one when someone else acts.
    pub(crate) fn others(&self) -> SessionScope {
        self.own_session()
            .map_or(SessionScope::All, SessionScope::AllExcept)
    }

    /// Locks the account for a change. The owner's session is locked after it,
    /// as [`Session::lock`] does, and returned as it is now. An administrator may
    /// not change another administrator's account, which [`Operator::lock`] checks
    /// before and under the lock.
    pub(crate) async fn lock(
        &self,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Option<StoredSession>, AccountError> {
        match &self.by {
            ActingAs::Owner { session, .. } => Ok(Some(Session::lock(tx, session).await?)),
            ActingAs::Operator { operator, .. } => {
                operator.lock(tx, self.user).await?;
                Ok(None)
            }
        }
    }

    /// Commits a change. An administrator's rights, session and passkey
    /// confirmation are checked once more first, after the last write, as every
    /// admin API mutation does, so a grant revoked meanwhile rolls the change back.
    pub(crate) async fn commit(&self, mut tx: DatabaseTransaction<'_>) -> Result<(), AccountError> {
        if let ActingAs::Operator { operator, .. } = &self.by {
            operator.authorize(&mut tx).await?;
        }
        Ok(tx.commit().await?)
    }

    /// Records that an administrator or operator read the account's settings,
    /// which hold personal data, as `user show` is recorded. An owner reading
    /// their own is not.
    pub(crate) async fn viewed(&self, database: &Database) -> Result<(), AccountError> {
        if let ActingAs::Operator { .. } = &self.by {
            let mut tx = database.begin().await?;
            tx.record(
                &self.context(),
                Some(self.user),
                DomainEvent::AccountViewed {},
            )
            .await?;
            tx.commit().await?;
        }
        Ok(())
    }

    /// The administrator a request on the admin mount comes from, with the
    /// reason a change needs, acting on the account its path names. Refuses an
    /// administrator's account before any work, as the admin API does; changes
    /// check again under the account lock.
    async fn administrator(
        parts: &mut Parts,
        tokens: &AdminTokens,
        database: &Database,
    ) -> Result<Self, AccountError> {
        let operator = tokens.caller(parts).await?;
        let reason = if parts.method.is_safe() {
            None
        } else {
            Some(Reason::from_headers(&parts.headers)?)
        };
        // A malformed ID names no account.
        let Ok(Path(Target { user_id: user })) = Path::from_request_parts(parts, &()).await else {
            return Err(AdminError::UserNotFound.into());
        };
        if database.administrators().contains(user).await? {
            return Err(AdminError::AdministratorTarget.into());
        }
        database
            .users()
            .find_by_id(user)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        Ok(Self::operator(user, operator, reason))
    }

    /// The owner of a request on the owner mount, signed in with `session`.
    async fn owner(
        parts: &mut Parts,
        app: &AccountApplication,
        session: StoredSession,
    ) -> Result<Self, ApiError> {
        let context = RequestContext::from_request_parts(parts, app).await?;
        Ok(Self {
            user: session.user_id,
            by: ActingAs::Owner { session, context },
        })
    }
}

impl FromRequestParts<AccountApplication> for Subject {
    type Rejection = ApiError;
    /// Requires a browser session on the owner mount. On the admin mount, requires
    /// an administrator signed in with a passkey, recently for a change, which
    /// must also give its reason.
    async fn from_request_parts(
        parts: &mut Parts,
        app: &AccountApplication,
    ) -> Result<Self, Self::Rejection> {
        match &app.mount {
            Mount::Owner => {
                let Session(session) = Session::from_request_parts(parts, app).await?;
                Self::owner(parts, app, session).await
            }
            Mount::Admin(tokens) => {
                Ok(Self::administrator(parts, tokens, &app.service.database).await?)
            }
        }
    }
}

impl<const MAX_AGE: u32> ConfirmedSubject<MAX_AGE> {
    /// Locks the account as [`Subject::lock`] does, then checks the owner's
    /// confirmation again on their session as it is now.
    pub(crate) async fn lock(&self, tx: &mut DatabaseTransaction<'_>) -> Result<(), AccountError> {
        if let Some(session) = self.0.lock(tx).await? {
            Confirmed::<MAX_AGE>::check(&session)?;
        }
        Ok(())
    }
}

impl<const MAX_AGE: u32> Deref for ConfirmedSubject<MAX_AGE> {
    type Target = Subject;
    /// The subject, whose confirmation was checked.
    fn deref(&self) -> &Subject {
        &self.0
    }
}

impl<const MAX_AGE: u32> FromRequestParts<AccountApplication> for ConfirmedSubject<MAX_AGE> {
    type Rejection = ApiError;
    /// Requires a session confirmed at most `MAX_AGE` seconds ago on the owner
    /// mount, and what [`Subject`] requires on the admin mount.
    async fn from_request_parts(
        parts: &mut Parts,
        app: &AccountApplication,
    ) -> Result<Self, Self::Rejection> {
        match &app.mount {
            Mount::Owner => {
                let Confirmed(session) =
                    Confirmed::<MAX_AGE>::from_request_parts(parts, app).await?;
                Subject::owner(parts, app, session).await.map(Self)
            }
            Mount::Admin(_) => Subject::from_request_parts(parts, app).await.map(Self),
        }
    }
}
