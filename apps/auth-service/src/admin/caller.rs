//! Who runs an administrative operation, and how the admin API authenticates them.

use super::AdminError;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, header, request::Parts},
};
use chrono::{DateTime, Utc};
use piquel_admin_api::{AUDIENCE, CONFIRMATION_MAX_AGE};
use piquel_common::{
    SessionId, UserId,
    events::{Actor, EventContext, RequestOrigin},
    protocol::{
        claims::{AccessTokenClaims, Acr},
        jwt::TokenType,
        step_up::StepUpRequirement,
    },
};
use piquel_crypto::Rs256Key;
use piquel_repository::{Database, DatabaseTransaction};
use std::sync::Arc;

/// Any passkey sign-in, however old: what every admin API request needs.
const PASSKEY: StepUpRequirement = StepUpRequirement {
    acr: Some(Acr::PhishingResistant),
    max_age: None,
};
/// A passkey confirmation recent enough for a mutation.
const RECENT_PASSKEY: StepUpRequirement = StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE);

/// Who runs an administrative operation: an administrator through the admin API,
/// or an operator at the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operator {
    /// An administrator, authenticated by an access token the dashboard holds.
    Admin {
        /// The administrator's account.
        user_id: UserId,
        /// The session the token was issued from.
        session_id: SessionId,
        /// How that session had authenticated, as the token reports it.
        acr: Option<Acr>,
        /// When it had, as the token reports it.
        auth_time: Option<DateTime<Utc>>,
    },
    /// An operator running `auth-service`.
    Cli {
        /// The operating system user, from `$USER`.
        os_user: String,
        /// The machine's host name.
        host: String,
    },
}

impl Operator {
    /// Attributes events to this operator. Neither carries a client origin: the
    /// admin API's caller is the dashboard's server, not the administrator's browser.
    #[must_use]
    pub fn context(&self) -> EventContext {
        let actor = match self.clone() {
            Self::Admin {
                user_id,
                session_id,
                ..
            } => Actor::Admin {
                user_id,
                session_id,
            },
            Self::Cli { os_user, host } => Actor::Cli { os_user, host },
        };
        EventContext {
            actor,
            origin: RequestOrigin::default(),
        }
    }

    /// The administrator's account, if an administrator acts.
    pub(super) const fn administrator(&self) -> Option<UserId> {
        match self {
            Self::Admin { user_id, .. } => Some(*user_id),
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

    /// Requires an administrator to still hold their rights, their session and a
    /// passkey confirmation recent enough for a mutation. The rights stay
    /// share-locked until `tx` ends, so revoking them waits for the operation, or
    /// wins before it; only revocations, which serialize on their own table lock,
    /// ever lock that row, so this lock joins no cycle.
    ///
    /// Mutations call it after their last write, just before committing (see
    /// `AdminOperations::finish`), so the times are compared with the clock when
    /// nothing is left to wait for. The session is read then, not locked: a
    /// session lock taken last could still meet a transaction that holds it and
    /// waits for one of this one's, such as the caller's own sign-in or social
    /// linking. A sign-out or account disablement that commits between this read
    /// and the commit does not stop the operation.
    pub(super) async fn authorize(
        &self,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<(), AdminError> {
        let Self::Admin {
            user_id,
            session_id,
            acr,
            auth_time,
        } = *self
        else {
            return Ok(());
        };
        if !tx.administrators().contains_for_share(user_id).await? {
            return Err(AdminError::NotAdministrator);
        }
        tx.sessions()
            .find_active_by_id(session_id)
            .await?
            .filter(|session| session.user_id == user_id && session.expires_at > Utc::now())
            .ok_or(AdminError::SessionEnded)?;
        RECENT_PASSKEY
            .check(acr.as_ref(), auth_time, Utc::now())
            .map_err(AdminError::StepUpRequired)
    }
}

/// Verifies admin API access tokens with auth's own signing key.
#[derive(Clone)]
pub(crate) struct AdminTokens {
    /// Key that signed the tokens.
    pub(super) keys: Arc<Rs256Key>,
    /// The issuer the tokens must name.
    pub(super) issuer: String,
    /// Holds the sessions and administrator rights checked on each request.
    pub(super) database: Database,
}

impl AdminTokens {
    /// Authenticates the request's administrator: a valid access token for the
    /// admin API, from an active session of an administrator, whose sign-in meets
    /// `requirement`. The rights and session are read now, not from the token, so
    /// revoking either takes effect on the next request.
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        requirement: StepUpRequirement,
    ) -> Result<Operator, AdminError> {
        let claims: AccessTokenClaims = self
            .keys
            .verify(Self::bearer(headers)?, TokenType::Access, &self.issuer)
            .map_err(AdminError::InvalidToken)?;
        let user_id: UserId = claims.sub.parse().map_err(|_| AdminError::WrongToken)?;
        let session_id = claims
            .authentication
            .sid
            .filter(|_| claims.aud.contains(AUDIENCE))
            .ok_or(AdminError::WrongToken)?;
        self.database
            .sessions()
            .find_active_by_id(session_id)
            .await?
            .filter(|session| session.user_id == user_id)
            .ok_or(AdminError::SessionEnded)?;
        if !self.database.administrators().contains(user_id).await? {
            return Err(AdminError::NotAdministrator);
        }
        requirement
            .check(
                claims.authentication.acr.as_ref(),
                claims.authentication.auth_time,
                Utc::now(),
            )
            .map_err(AdminError::StepUpRequired)?;
        Ok(Operator::Admin {
            user_id,
            session_id,
            acr: claims.authentication.acr,
            auth_time: claims.authentication.auth_time,
        })
    }

    /// The token of the request's one `Authorization: Bearer` header. Another scheme
    /// counts as no token.
    fn bearer(headers: &HeaderMap) -> Result<&str, AdminError> {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return Err(if headers.contains_key(header::AUTHORIZATION) {
                AdminError::MalformedAuthorization
            } else {
                AdminError::MissingToken
            });
        };
        let value = value
            .to_str()
            .map_err(|_| AdminError::MalformedAuthorization)?;
        let (scheme, token) = value.split_once(' ').unwrap_or((value, ""));
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(AdminError::MissingToken);
        }
        match token.trim() {
            "" => Err(AdminError::MalformedAuthorization),
            token => Ok(token),
        }
    }
}

/// An administrator signed in with a passkey. Every read takes it.
pub(crate) struct Admin(pub Operator);
/// An administrator with a passkey confirmation at most [`CONFIRMATION_MAX_AGE`]
/// seconds old. Every mutation takes it, and rechecks the caller with
/// [`Operator::authorize`] inside its transaction.
pub(crate) struct ConfirmedAdmin(pub Operator);

/// Implements extraction for an administrator whose sign-in meets `$requirement`.
macro_rules! admin_extractor {
    ($name:ident, $requirement:expr) => {
        impl<S> FromRequestParts<S> for $name
        where
            AdminTokens: FromRef<S>,
            S: Send + Sync,
        {
            type Rejection = AdminError;
            /// Authenticates the bearer token against the application's state.
            async fn from_request_parts(
                parts: &mut Parts,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                Ok(Self(
                    AdminTokens::from_ref(state)
                        .authenticate(&parts.headers, $requirement)
                        .await?,
                ))
            }
        }
    };
}
admin_extractor!(Admin, PASSKEY);
admin_extractor!(ConfirmedAdmin, RECENT_PASSKEY);
