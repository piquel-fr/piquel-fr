//! Admin failures, from the dashboard or the CLI, and their status and message.

use crate::{ClientRegistryError, security::ApiError};
use piquel_common::{
    DeliveryId, HandleError, PasskeyId,
    protocol::{api::ErrorCode, step_up::StepUpRequirement},
};
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;

/// Failures of an administrative operation, or of signing its administrator in.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The administrator's auth session ended, or their account was disabled.
    #[error("your session has ended; sign in again")]
    SessionEnded,
    /// The account is not an administrator.
    #[error("this account is not an administrator")]
    NotAdministrator,
    /// The administrator's sign-in does not meet the requirement: a passkey, and
    /// for a change, the dashboard's own recent confirmation.
    #[error("confirm with your passkey to continue")]
    StepUpRequired(StepUpRequirement),
    /// A sign-in to the dashboard was handed off wrongly: its code is unknown,
    /// used, expired or for another browser, or its request is malformed.
    #[error("this sign-in to the dashboard did not work; sign in again")]
    InvalidHandoff,
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
    /// The dashboard never acts on administrator accounts, so a stolen dashboard
    /// session cannot lock other administrators out. Revoke their rights first, or
    /// use the CLI.
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
    /// The invitation lifetime is not 1 hour to 365 days.
    #[error("expires_in {0}")]
    InvalidInviteExpiry(#[from] super::InvalidLifetime),
    /// Only an active account can be recovered.
    #[error("the account is disabled; enable it before recovering it")]
    RecoveryOfDisabledAccount,
    /// An administrator never sees a recovery link, so only a recovery that mails
    /// it to a primary verified address is theirs to start.
    #[error(
        "the recovery link would not be mailed (no primary verified address, or --revoke); only an operator at the terminal can recover this account, with `auth-service user recover`"
    )]
    RecoveryNeedsEmail,
    /// Whoever used an administrator's recovery link could use its rights before
    /// the owner undoes it, so an administrator is never recovered.
    #[error(
        "the account is an administrator: revoke its rights with `auth-service admin revoke` (grant another administrator first if it is the last), recover it, then grant them again once the recovery settles"
    )]
    RecoveryOfAdministrator,
    /// A recovery of the account is in probation: support finds out who used it,
    /// and undoes it first.
    #[error(
        "the account has a recovery in probation: find out who used it, and undo it with `auth-service user undo-recovery` before starting another"
    )]
    RecoveryInProbation,
    /// A passkey `--keep` named is not an active passkey of the account.
    #[error("passkey {0} is not an active passkey of the account")]
    UnknownPasskey(PasskeyId),
    /// A recovery of the account can still be undone: rights granted now would go
    /// live for whoever used its link once it settles.
    #[error(
        "the account has a recovery that can still be undone: grant the rights once it settles, or after undoing it"
    )]
    GrantDuringRecovery,
    /// The account has no recovery that can still be undone.
    #[error("the account has no recovery that can still be undone")]
    NoRecoveryToUndo,
    /// Only active accounts can become administrators.
    #[error("the account is disabled; enable it before granting administrator rights")]
    AccountDisabled,
    /// The account is already an administrator.
    #[error("the account is already an administrator")]
    AlreadyAdministrator,
    /// The account is not an administrator, so it has no rights to revoke.
    #[error("the account is not an administrator")]
    NotAnAdministrator,
    /// Administrators cannot grant or revoke their own rights from the dashboard.
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
    /// A link could not be written.
    #[error("could not write a link")]
    Link(#[from] piquel_ui::QueryError),
}

impl AdminError {
    /// Names the failure in its log line.
    const fn reason(&self) -> &'static str {
        match self {
            Self::SessionEnded => "session_ended",
            Self::NotAdministrator => "not_administrator",
            Self::StepUpRequired(_) => "step_up_required",
            Self::InvalidHandoff => "invalid_handoff",
            Self::UserNotFound => "user_not_found",
            Self::SessionNotFound => "session_not_found",
            Self::InvitationNotFound => "invitation_not_found",
            Self::ClientNotFound => "client_not_found",
            Self::DeliveryNotFound { .. } => "delivery_not_found",
            Self::AdministratorTarget => "administrator_target",
            Self::AlreadyDisabled => "already_disabled",
            Self::AlreadyActive => "already_active",
            Self::EmailClaimed(_) => "email_claimed",
            Self::InvalidReason => "invalid_reason",
            Self::InvalidInviteExpiry(_) => "invalid_invite_expiry",
            Self::RecoveryOfDisabledAccount => "recovery_of_disabled_account",
            Self::RecoveryNeedsEmail => "recovery_needs_email",
            Self::RecoveryOfAdministrator => "recovery_of_administrator",
            Self::RecoveryInProbation => "recovery_in_probation",
            Self::UnknownPasskey(_) => "unknown_passkey",
            Self::GrantDuringRecovery => "grant_during_recovery",
            Self::NoRecoveryToUndo => "no_recovery_to_undo",
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
            Self::Link(_) => "link",
        }
    }

    /// Logs this refusal of an administrator's request in the request's trace, by
    /// its reason, so every refusal can be counted and followed: one that the
    /// dashboard's own pages never cause, such as a sign-in or a read by an
    /// account that is not an administrator, may be a stolen session.
    pub(crate) fn log_refusal(&self) {
        tracing::info!(
            admin.failure = self.reason(),
            "admin dashboard request refused"
        );
    }

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
}

impl From<AdminError> for ApiError {
    /// Maps every admin failure to a stable status and its message.
    fn from(error: AdminError) -> Self {
        let message = error.to_string();
        match error {
            AdminError::InvalidReason
            | AdminError::InvalidInviteExpiry(_)
            | AdminError::InvalidHandoff => Self::bad_request(message),
            AdminError::InvalidHandle(error) => error.into(),
            AdminError::SessionEnded | AdminError::StepUpRequired(_) => Self::unauthorized(message),
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
            | AdminError::RecoveryOfDisabledAccount
            | AdminError::RecoveryNeedsEmail
            | AdminError::RecoveryOfAdministrator
            | AdminError::RecoveryInProbation
            | AdminError::UnknownPasskey(_)
            | AdminError::NoRecoveryToUndo
            | AdminError::GrantDuringRecovery
            | AdminError::AccountDisabled
            | AdminError::AlreadyAdministrator
            | AdminError::NotAnAdministrator
            | AdminError::SameHandle => Self::conflict(message),
            AdminError::HandleTaken(_) => Self::conflict(message).with_code(ErrorCode::HandleTaken),
            AdminError::Database(error) => error.into(),
            AdminError::Client(error) => error.into(),
            error @ (AdminError::Crypto(_) | AdminError::Event(_) | AdminError::Link(_)) => {
                Self::internal(error)
            }
        }
    }
}
