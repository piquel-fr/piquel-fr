//! Admin failures, from the API or the CLI, and their one conversion to responses.

use crate::{ClientRegistryError, security::ApiError};
use axum::response::{IntoResponse, Response};
use piquel_admin_api::REASON_HEADER;
use piquel_common::{
    DeliveryId, HandleError,
    protocol::{
        api::ErrorCode,
        challenge::{BearerChallenge, BearerError},
        step_up::StepUpRequirement,
    },
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
    /// No account has this ID or username, or no active one this verified email.
    #[error("no account has this ID, username or verified email")]
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
    /// No delivery with this ID is in a state the operation applies to.
    #[error("no {states} delivery has ID {id}")]
    DeliveryNotFound {
        /// The requested delivery.
        id: DeliveryId,
        /// The states the operation applies to.
        states: &'static str,
    },
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
    /// A change to another account's settings came without its reason.
    #[error("say why in the {REASON_HEADER} header")]
    MissingReason,
    /// The reason is blank, longer than 500 characters, holds control characters,
    /// or is not percent-encoded UTF-8.
    #[error("give a reason of 1 to 500 characters, without control characters")]
    InvalidReason,
    /// The invitation lifetime is not 1 hour to 365 days.
    #[error("expires_in {0}")]
    InvalidInviteExpiry(#[from] super::InvalidLifetime),
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
    /// The new handle breaks the handle rules, or is reserved.
    #[error(transparent)]
    InvalidHandle(#[from] HandleError),
    /// The account already has this handle.
    #[error("the account already has this handle")]
    SameHandle,
    /// Another account has this handle.
    #[error("another account has this handle")]
    HandleTaken(#[source] DatabaseError),
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// A client change was refused or failed.
    #[error(transparent)]
    Client(#[from] ClientRegistryError),
    /// Secret generation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A stored event could not be shown.
    #[error("could not serialize a stored event")]
    Event(#[from] serde_json::Error),
}

impl AdminError {
    /// Reports `NotFound` as no delivery `id` in `states`.
    pub(super) fn delivery(
        id: DeliveryId,
        states: &'static str,
    ) -> impl FnOnce(DatabaseError) -> Self {
        move |error| match error {
            DatabaseError::NotFound => Self::DeliveryNotFound { id, states },
            error => error.into(),
        }
    }

    /// Names the failure in its log line. Outside `step_up_required` and
    /// `session_ended`, a refused caller sent a token the dashboard never would:
    /// a stolen, forged or non-administrator one.
    const fn reason(&self) -> &'static str {
        match self {
            Self::MissingToken => "missing_token",
            Self::MalformedAuthorization => "malformed_authorization",
            Self::InvalidToken(_) => "invalid_token",
            Self::WrongToken => "wrong_token",
            Self::SessionEnded => "session_ended",
            Self::NotAdministrator => "not_administrator",
            Self::StepUpRequired(_) => "step_up_required",
            Self::UserNotFound => "user_not_found",
            Self::SessionNotFound => "session_not_found",
            Self::InvitationNotFound => "invitation_not_found",
            Self::ClientNotFound => "client_not_found",
            Self::DeliveryNotFound { .. } => "delivery_not_found",
            Self::AdministratorTarget => "administrator_target",
            Self::AlreadyDisabled => "already_disabled",
            Self::AlreadyActive => "already_active",
            Self::EmailClaimed(_) => "email_claimed",
            Self::MissingReason => "missing_reason",
            Self::InvalidReason => "invalid_reason",
            Self::InvalidInviteExpiry(_) => "invalid_invite_expiry",
            Self::AccountDisabled => "account_disabled",
            Self::AlreadyAdministrator => "already_administrator",
            Self::NotAnAdministrator => "not_an_administrator",
            Self::OwnRights => "own_rights",
            Self::LastAdministrator => "last_administrator",
            Self::InvalidHandle(_) => "invalid_handle",
            Self::SameHandle => "same_handle",
            Self::HandleTaken(_) => "handle_taken",
            Self::Database(_) => "database",
            Self::Client(_) => "client",
            Self::Crypto(_) => "crypto",
            Self::Event(_) => "event",
        }
    }

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
            | Self::DeliveryNotFound { .. }
            | Self::AdministratorTarget
            | Self::AlreadyDisabled
            | Self::AlreadyActive
            | Self::EmailClaimed(_)
            | Self::MissingReason
            | Self::InvalidReason
            | Self::InvalidInviteExpiry(_)
            | Self::AccountDisabled
            | Self::AlreadyAdministrator
            | Self::NotAnAdministrator
            | Self::OwnRights
            | Self::LastAdministrator
            | Self::InvalidHandle(_)
            | Self::SameHandle
            | Self::HandleTaken(_)
            | Self::Database(_)
            | Self::Client(_)
            | Self::Crypto(_)
            | Self::Event(_) => None,
        }
    }
}

impl From<AdminError> for ApiError {
    /// Maps every admin failure to a stable status, its message and, for a caller
    /// failure, its challenge. Only responses convert admin failures, the CLI
    /// reports its own, so this also logs the failure's reason in the request's
    /// trace: every refusal can be counted and followed.
    fn from(error: AdminError) -> Self {
        tracing::info!(admin.failure = error.reason(), "admin API request failed");
        let challenge = error.challenge();
        let message = error.to_string();
        let response = match error {
            AdminError::MalformedAuthorization
            | AdminError::MissingReason
            | AdminError::InvalidReason
            | AdminError::InvalidInviteExpiry(_) => Self::bad_request(message),
            AdminError::InvalidHandle(error) => error.into(),
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
            | AdminError::ClientNotFound
            | AdminError::DeliveryNotFound { .. } => Self::not_found(message),
            AdminError::AlreadyDisabled
            | AdminError::AlreadyActive
            | AdminError::EmailClaimed(_)
            | AdminError::AccountDisabled
            | AdminError::AlreadyAdministrator
            | AdminError::NotAnAdministrator
            | AdminError::SameHandle => Self::conflict(message),
            AdminError::HandleTaken(_) => Self::conflict(message).with_code(ErrorCode::HandleTaken),
            AdminError::Database(error) => error.into(),
            AdminError::Client(error) => error.into(),
            error @ (AdminError::Crypto(_) | AdminError::Event(_)) => Self::internal(error),
        };
        response.with_challenge(challenge)
    }
}

impl IntoResponse for AdminError {
    /// Answers `{"error": message}`, with the challenge of a caller failure.
    fn into_response(self) -> Response {
        ApiError::from(self).into_response()
    }
}
