//! Admin failures, from the API or the CLI, and their one conversion to responses.

use crate::security::ApiError;
use axum::{
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use piquel_common::protocol::{
    challenge::{BearerChallenge, BearerError},
    step_up::StepUpRequirement,
};
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;

/// Failures of an administrative operation, or of authenticating its caller.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The request carried no bearer token.
    #[error("send an access token as Bearer credentials")]
    MissingToken,
    /// `Authorization` was sent twice, or names Bearer without a token.
    #[error("send one Authorization header with a Bearer token")]
    MalformedAuthorization,
    /// The token is not a valid, unexpired access token from this issuer.
    #[error("the access token is invalid")]
    InvalidToken(#[source] CryptoError),
    /// The token is valid, but for another resource, or names no account or session.
    #[error("the access token is not an administrator's admin API token")]
    WrongToken,
    /// The session the token was issued from ended, or its account was disabled.
    #[error("the access token's session has ended")]
    SessionEnded,
    /// The token's account is not an administrator.
    #[error("this account is not an administrator")]
    NotAdministrator,
    /// The token's sign-in does not meet the requirement: a passkey, recent enough
    /// for mutations.
    #[error("sign in again with a passkey to continue")]
    StepUpRequired(StepUpRequirement),
    /// No account has this ID or username.
    #[error("no account has this ID or username")]
    UserNotFound,
    /// No active session has this ID.
    #[error("no active session has this ID")]
    SessionNotFound,
    /// No unredeemed, unrevoked invitation has this ID.
    #[error("no unredeemed, unrevoked invitation has this ID")]
    InvitationNotFound,
    /// No OIDC client has this ID.
    #[error("no OIDC client has this ID")]
    ClientNotFound,
    /// The admin API never acts on administrator accounts, so a stolen admin token
    /// cannot lock other administrators out. Revoke their rights first, or use the CLI.
    #[error("administrator accounts can only be changed after revoking their rights")]
    AdministratorTarget,
    /// The account is already disabled.
    #[error("the account is already disabled")]
    AlreadyDisabled,
    /// The account is already active.
    #[error("the account is already active")]
    AlreadyActive,
    /// Reactivation found a verified email of the account owned by another active account.
    #[error("another active account has claimed one of this account's verified emails")]
    EmailClaimed(#[source] DatabaseError),
    /// The reason is blank, longer than 500 characters or holds control characters.
    #[error("give a reason of 1 to 500 characters, without control characters")]
    InvalidReason,
    /// The invitation lifetime is not 1 to 365 hours or days.
    #[error(transparent)]
    InvalidInviteExpiry(#[from] super::InvalidInviteExpiry),
    /// Only active accounts can become administrators.
    #[error("the account is disabled; enable it before granting administrator rights")]
    AccountDisabled,
    /// The account is already an administrator.
    #[error("the account is already an administrator")]
    AlreadyAdministrator,
    /// The account is not an administrator, so it has no rights to revoke.
    #[error("the account is not an administrator")]
    NotAnAdministrator,
    /// Administrators cannot grant or revoke their own rights through the API.
    #[error("administrators cannot change their own rights")]
    OwnRights,
    /// The last administrator's rights cannot be revoked.
    #[error("the last administrator's rights cannot be revoked")]
    LastAdministrator,
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// Secret generation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A stored event could not be shown.
    #[error("could not serialize a stored event")]
    Event(#[from] serde_json::Error),
}

impl AdminError {
    /// The `WWW-Authenticate` challenge of a caller failure (RFC 6750, RFC 9470).
    fn challenge(&self) -> Option<BearerChallenge> {
        match self {
            Self::MissingToken => Some(BearerChallenge::default()),
            Self::MalformedAuthorization => {
                Some(BearerChallenge::error(BearerError::InvalidRequest))
            }
            Self::InvalidToken(_) | Self::WrongToken | Self::SessionEnded => {
                Some(BearerChallenge::error(BearerError::InvalidToken))
            }
            Self::StepUpRequired(requirement) => Some(BearerChallenge::step_up(*requirement)),
            // The token is fine: the account or the operation is refused.
            Self::NotAdministrator
            | Self::UserNotFound
            | Self::SessionNotFound
            | Self::InvitationNotFound
            | Self::ClientNotFound
            | Self::AdministratorTarget
            | Self::AlreadyDisabled
            | Self::AlreadyActive
            | Self::EmailClaimed(_)
            | Self::InvalidReason
            | Self::InvalidInviteExpiry(_)
            | Self::AccountDisabled
            | Self::AlreadyAdministrator
            | Self::NotAnAdministrator
            | Self::OwnRights
            | Self::LastAdministrator
            | Self::Database(_)
            | Self::Crypto(_)
            | Self::Event(_) => None,
        }
    }
}

impl From<AdminError> for ApiError {
    /// Maps every admin failure to a stable status and its message.
    fn from(error: AdminError) -> Self {
        let message = error.to_string();
        match error {
            AdminError::MalformedAuthorization
            | AdminError::InvalidReason
            | AdminError::InvalidInviteExpiry(_) => Self::bad_request(message),
            AdminError::MissingToken
            | AdminError::InvalidToken(_)
            | AdminError::WrongToken
            | AdminError::SessionEnded
            | AdminError::StepUpRequired(_) => Self::unauthorized(message),
            AdminError::NotAdministrator
            | AdminError::AdministratorTarget
            | AdminError::OwnRights
            | AdminError::LastAdministrator => Self::forbidden(message),
            AdminError::UserNotFound
            | AdminError::SessionNotFound
            | AdminError::InvitationNotFound
            | AdminError::ClientNotFound => Self::not_found(message),
            AdminError::AlreadyDisabled
            | AdminError::AlreadyActive
            | AdminError::EmailClaimed(_)
            | AdminError::AccountDisabled
            | AdminError::AlreadyAdministrator
            | AdminError::NotAnAdministrator => Self::conflict(message),
            AdminError::Database(error) => error.into(),
            error @ (AdminError::Crypto(_) | AdminError::Event(_)) => Self::internal(error),
        }
    }
}

impl IntoResponse for AdminError {
    /// Answers `{"error": message}`, with the challenge of a caller failure.
    fn into_response(self) -> Response {
        let challenge = self
            .challenge()
            .and_then(|challenge| HeaderValue::try_from(challenge.to_string()).ok());
        let mut response = ApiError::from(self).into_response();
        if let Some(challenge) = challenge {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, challenge);
        }
        response
    }
}
