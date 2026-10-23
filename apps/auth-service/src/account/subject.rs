//! The account a settings operation reads or changes, and who acts on it.

use super::{AccountApplication, AccountError};
use crate::{
    Operator, Reason,
    security::{ApiError, CONFIRMATION_MAX_AGE, Confirmed, RequestContext, Session},
};
use axum::{extract::FromRequestParts, http::request::Parts};
use piquel_common::{
    SessionId, UserId,
    events::{DomainEvent, EventContext, RevocationReason},
};
use piquel_repository::{Database, DatabaseTransaction, SessionScope, StoredSession};
use std::ops::Deref;

/// The account a settings change applies to, and who makes it. Changes take it
/// instead of a session, so they serve the owner and operators alike. Its fields
/// are private: an owner's comes only from their session cookie, through the
/// extractor, and an operator's from [`Self::operator`], with their reason and an
/// [`Operator`] only the admin API's authenticator or the CLI creates. An operator
/// cannot make a change without a reason: a read takes a [`Viewer`] instead.
pub(crate) struct Subject {
    /// The account.
    user: UserId,
    /// Who acts on it.
    by: ActingAs,
}

/// Who acts on a [`Subject`].
enum ActingAs {
    /// The account's own user, signed in with `session`, from `context`.
    Owner {
        /// The owner's browser session.
        session: StoredSession,
        /// Where the request came from.
        context: RequestContext,
    },
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

/// A [`Subject`] whose owner confirmed their session with a passkey at most
/// `MAX_AGE` seconds ago, for changes that need one. Operators need none: an
/// administrator's change checks their own recent passkey before it commits.
pub(crate) struct ConfirmedSubject<const MAX_AGE: u32 = CONFIRMATION_MAX_AGE>(Subject);

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
            ActingAs::Owner { session, context } => context.user(session),
            ActingAs::Operator { operator, reason } => EventContext {
                reason: Some(reason.clone().into_inner()),
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

    /// Why sessions this subject signs out end: the owner signed them out from
    /// their devices list, or an administrator or operator did.
    pub(crate) const fn revocation(&self) -> RevocationReason {
        match &self.by {
            ActingAs::Owner { .. } => RevocationReason::UserRevoked,
            ActingAs::Operator { .. } => RevocationReason::Admin,
        }
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

    /// The owner signed in with `session`, acting from the request `parts`
    /// describes. Only the extractors call it, with the session of the request's
    /// cookie.
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

    /// Records that an administrator or operator read the account's settings,
    /// which hold personal data, as `user show` is recorded. An owner reading
    /// their own is not.
    pub(crate) async fn viewed(&self, database: &Database) -> Result<(), AccountError> {
        if let Reading::Operator(operator) = &self.by {
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

impl FromRequestParts<AccountApplication> for Viewer {
    type Rejection = ApiError;
    /// The owner of the request's browser session.
    async fn from_request_parts(
        parts: &mut Parts,
        app: &AccountApplication,
    ) -> Result<Self, Self::Rejection> {
        let Session(session) = Session::from_request_parts(parts, app).await?;
        Ok(Self {
            user: session.user_id,
            by: Reading::Owner(session.id),
        })
    }
}

impl FromRequestParts<AccountApplication> for Subject {
    type Rejection = ApiError;
    /// The owner of the request's browser session.
    async fn from_request_parts(
        parts: &mut Parts,
        app: &AccountApplication,
    ) -> Result<Self, Self::Rejection> {
        let Session(session) = Session::from_request_parts(parts, app).await?;
        Self::owner(parts, app, session).await
    }
}

impl<const MAX_AGE: u32> ConfirmedSubject<MAX_AGE> {
    /// An administrator or operator making a change that needs the owner's
    /// recent confirmation, for `reason`.
    pub(crate) const fn operator(user: UserId, operator: Operator, reason: Reason) -> Self {
        Self(Subject::operator(user, operator, reason))
    }

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
    /// The owner of the request's browser session, confirmed at most `MAX_AGE`
    /// seconds ago.
    async fn from_request_parts(
        parts: &mut Parts,
        app: &AccountApplication,
    ) -> Result<Self, Self::Rejection> {
        let Confirmed(session) = Confirmed::<MAX_AGE>::from_request_parts(parts, app).await?;
        Subject::owner(parts, app, session).await.map(Self)
    }
}
