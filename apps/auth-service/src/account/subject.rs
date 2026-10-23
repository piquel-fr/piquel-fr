//! The account a settings operation reads or changes, and who acts on it.

use super::AccountError;
use crate::{
    Operator, Reason,
    security::{ApiError, Confirmed, OptionalSession, RequestContext, Session, SessionError},
};
use axum::{
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use piquel_common::{
    SessionId, UserId,
    events::{DomainEvent, EventContext, RevocationReason},
};
use piquel_repository::{Database, DatabaseTransaction, SessionScope, StoredSession};

/// The signed-in owner of an account, acting through their browser session. Its
/// fields are private and only the extractors build one, from the session cookie,
/// so an operation only the owner may run, such as adding a passkey or an
/// address, takes an `Owner`: no administrator or operator can call it.
pub(crate) struct Owner {
    /// The owner's browser session, as the request found it.
    session: StoredSession,
    /// Where the request came from.
    context: RequestContext,
}

/// The account a settings change applies to, and who makes it. Changes any
/// administrator may also make take it instead of a session, so they serve the
/// owner and operators alike. Its fields are private: an owner's comes only from
/// their session cookie, through the extractor, and an operator's from
/// [`Self::operator`], with their reason and an [`Operator`] only the admin API's
/// authenticator or the CLI creates. An operator cannot make a change without a
/// reason: a read takes a [`Viewer`] instead.
pub(crate) struct Subject {
    /// The account.
    user: UserId,
    /// Who acts on it.
    by: ActingAs,
}

/// Who acts on a [`Subject`].
enum ActingAs {
    /// The account's own user.
    Owner(Owner),
    /// An administrator or operator, and why they make the change.
    Operator {
        /// Who acts.
        operator: Operator,
        /// Why.
        reason: Reason,
    },
}

/// The account a settings read shows, and who reads it. A read changes nothing,
/// so it needs no reason. Its fields are private, like [`Subject`]'s: an owner's
/// comes only from their session cookie, through the extractor.
pub(crate) struct Viewer {
    /// The account.
    user: UserId,
    /// Who reads it.
    by: Reading,
}

/// Who reads a [`Viewer`]'s account.
enum Reading {
    /// The account's own user, signed in with this session.
    Owner(SessionId),
    /// An administrator or operator.
    Operator(Operator),
}

impl Owner {
    /// The owner signed in with `session`, acting from the request `parts`
    /// describes. Only the extractors call it, with the session of the request's
    /// cookie.
    async fn new<S>(parts: &mut Parts, state: &S, session: StoredSession) -> Result<Self, ApiError>
    where
        S: Send + Sync,
    {
        Ok(Self {
            session,
            context: RequestContext::from_request_parts(parts, state).await?,
        })
    }

    /// The owner's account.
    pub(crate) const fn user(&self) -> UserId {
        self.session.user_id
    }

    /// The owner's browser session, as the request found it.
    pub(crate) const fn session(&self) -> &StoredSession {
        &self.session
    }

    /// Where the request came from.
    pub(crate) const fn request(&self) -> RequestContext {
        self.context
    }

    /// Attributes events to the owner, through their session.
    pub(crate) fn context(&self) -> EventContext {
        self.context.user(&self.session)
    }

    /// Locks the account, then the owner's session, as [`Session::lock`] does,
    /// and returns the session as it is now. A sign-out or revocation either
    /// commits first or waits.
    pub(crate) async fn lock(
        &self,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<StoredSession, SessionError> {
        Session::lock(tx, &self.session).await
    }

    /// [`Self::lock`], then requires the session's passkey confirmation, as it is
    /// now, to be recent: what adding a way to sign in or an address needs.
    pub(crate) async fn lock_confirmed(
        &self,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<StoredSession, SessionError> {
        let session = self.lock(tx).await?;
        <Confirmed>::check(&session)?;
        Ok(session)
    }
}

impl Subject {
    /// An administrator or operator changing `user`'s settings, for `reason`.
    pub(crate) const fn operator(user: UserId, operator: Operator, reason: Reason) -> Self {
        Self {
            user,
            by: ActingAs::Operator { operator, reason },
        }
    }

    /// The account.
    pub(crate) const fn user(&self) -> UserId {
        self.user
    }

    /// Attributes events to whoever acts. An administrator's or operator's reason
    /// goes with them, as personal data the owner sees in their history.
    pub(crate) fn context(&self) -> EventContext {
        match &self.by {
            ActingAs::Owner(owner) => owner.context(),
            ActingAs::Operator { operator, reason } => EventContext {
                reason: Some(reason.clone().into_inner()),
                ..operator.context()
            },
        }
    }

    /// The owner's own session, if the owner acts.
    pub(crate) const fn own_session(&self) -> Option<SessionId> {
        match &self.by {
            ActingAs::Owner(owner) => Some(owner.session.id),
            ActingAs::Operator { .. } => None,
        }
    }

    /// The sessions a change ends when it signs the account out elsewhere: every
    /// one but the owner's own, or every one when someone else acts.
    pub(crate) fn others(&self) -> SessionScope {
        self.own_session()
            .map_or(SessionScope::All, SessionScope::AllExcept)
    }

    /// Why sessions this subject signs out end: the owner signed them out from
    /// their devices list, or an administrator or operator did.
    pub(crate) const fn revocation(&self) -> RevocationReason {
        match &self.by {
            ActingAs::Owner(_) => RevocationReason::UserRevoked,
            ActingAs::Operator { .. } => RevocationReason::Admin,
        }
    }

    /// Locks the account for a change. The owner's session is locked after it,
    /// as [`Owner::lock`] does. An administrator may not change another
    /// administrator's account, which [`Operator::lock`] checks before and under
    /// the lock.
    pub(crate) async fn lock(&self, tx: &mut DatabaseTransaction<'_>) -> Result<(), AccountError> {
        match &self.by {
            ActingAs::Owner(owner) => {
                owner.lock(tx).await?;
            }
            ActingAs::Operator { operator, .. } => {
                operator.lock(tx, self.user).await?;
            }
        }
        Ok(())
    }

    /// [`Self::lock`], for a change the owner must have confirmed with a passkey
    /// recently, which [`Owner::lock_confirmed`] checks on their session as it is
    /// now. Operators need no confirmation of the owner's: an administrator's
    /// change checks their own recent passkey before it commits.
    pub(crate) async fn lock_confirmed(
        &self,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<(), AccountError> {
        match &self.by {
            ActingAs::Owner(owner) => {
                owner.lock_confirmed(tx).await?;
                Ok(())
            }
            ActingAs::Operator { .. } => self.lock(tx).await,
        }
    }

    /// Commits a change. An administrator's rights, session and passkey
    /// confirmation are checked once more first, after the last write, as every
    /// admin mutation does, so a grant revoked meanwhile rolls the change back.
    pub(crate) async fn commit(&self, mut tx: DatabaseTransaction<'_>) -> Result<(), AccountError> {
        if let ActingAs::Operator { operator, .. } = &self.by {
            operator.authorize(&mut tx).await?;
        }
        Ok(tx.commit().await?)
    }
}

impl From<Owner> for Subject {
    /// The owner, changing their own account.
    fn from(owner: Owner) -> Self {
        Self {
            user: owner.user(),
            by: ActingAs::Owner(owner),
        }
    }
}

impl Viewer {
    /// An administrator or operator reading `user`'s settings.
    pub(crate) const fn operator(user: UserId, operator: Operator) -> Self {
        Self {
            user,
            by: Reading::Operator(operator),
        }
    }

    /// The account.
    pub(crate) const fn user(&self) -> UserId {
        self.user
    }

    /// The owner's own session, if the owner reads.
    pub(crate) const fn own_session(&self) -> Option<SessionId> {
        match &self.by {
            Reading::Owner(session) => Some(*session),
            Reading::Operator(_) => None,
        }
    }

    /// Authorizes a read before it reads. An administrator must still hold their
    /// rights and session, signed in with a passkey, as every admin read requires
    /// ([`Operator::authorize_read`]), and an administrator's or operator's read
    /// is recorded as a view, as `user show` is, since settings hold personal
    /// data. The extractor already checked an owner's session, and an owner's
    /// reads of their own are not recorded.
    pub(crate) async fn authorize(&self, database: &Database) -> Result<(), AccountError> {
        if let Reading::Operator(operator) = &self.by {
            operator.authorize_read(database).await?;
            let mut tx = database.begin().await?;
            tx.record(
                &operator.context(),
                Some(self.user),
                DomainEvent::AccountViewed {},
            )
            .await?;
            tx.commit().await?;
        }
        Ok(())
    }
}

impl<S> FromRequestParts<S> for Owner
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// The owner of the request's browser session.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Session(session) = Session::from_request_parts(parts, state).await?;
        Self::new(parts, state, session).await
    }
}

impl<S> OptionalFromRequestParts<S> for Owner
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// The owner of the request's browser session, if it has one.
    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let OptionalSession(session) = OptionalSession::from_request_parts(parts, state).await?;
        match session {
            Some(session) => Ok(Some(Self::new(parts, state, session).await?)),
            None => Ok(None),
        }
    }
}

impl<S> FromRequestParts<S> for Subject
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// The owner of the request's browser session.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        <Owner as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(Self::from)
    }
}

impl<S> FromRequestParts<S> for Viewer
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    /// The owner of the request's browser session.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Session(session) = Session::from_request_parts(parts, state).await?;
        Ok(Self {
            user: session.user_id,
            by: Reading::Owner(session.id),
        })
    }
}
