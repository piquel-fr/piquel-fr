//! Admin failures, from the dashboard or the CLI, and their status and message.

use super::UserRef;
use crate::{
    ClientRegistryError, KeyError, deletion::DeletionError, handles::HandlesError,
    security::ApiError,
};
use sourceorigin_common::{
    DeliveryId, PasskeyId, email::InvalidEmail, protocol::step_up::StepUpRequirement,
};
use sourceorigin_crypto::CryptoError;
use sourceorigin_repository::DatabaseError;

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
    /// No account has this ID or handle, or no active one this verified email.
    #[error("no account has this ID, handle or verified email")]
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
    /// No current alert has this ID.
    #[error("no current alert has this ID: it cleared, or never existed")]
    AlertNotFound,
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
    /// The address to invite is not one email can be sent to.
    #[error("the address to invite is invalid: {0}")]
    InvalidInvitationEmail(#[from] InvalidEmail),
    /// An invitation is mailed only while email is enabled, so mailing one, or
    /// mailing it again, is refused before anything changes.
    #[error(
        "email is disabled, so no invitation can be mailed; only a link to pass on yourself, without an address, can be created"
    )]
    InvitationNeedsEmail,
    /// The sender can't send to the address to invite, though it is a valid one,
    /// so its link would never arrive.
    #[error("email can't be sent to the address to invite; check it, or use another one")]
    InvitationUnsendable(#[source] lettre::address::AddressError),
    /// An active account already holds the address verified: its owner signs in
    /// rather than signing up.
    #[error("an account already holds this address verified; its owner can sign in")]
    InvitationAddressTaken,
    /// Only an invitation mailed to an address can be sent again.
    #[error("this invitation was not mailed, so it has no address to send it to again")]
    InvitationNotMailed,
    /// Only an active account can be recovered.
    #[error("the account is disabled; enable it before recovering it")]
    RecoveryOfDisabledAccount,
    /// An administrator never sees a recovery link, so only a recovery that mails
    /// it to a primary verified address, while email is enabled, is theirs to
    /// start.
    #[error(
        "the recovery link would not be mailed (email is disabled, the account has no primary verified address, or --revoke); only an operator at the terminal can recover this account, with `auth-service user recover`"
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
        "the account has a recovery in probation: find out who used it, and undo it (the dashboard's Undo recovery, or `auth-service user undo-recovery`) before starting another"
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
    #[error(
        "the account is disabled or being deleted; only active accounts can become administrators"
    )]
    AccountDisabled,
    /// The account is scheduled for deletion, which only restoring it ends.
    #[error("the account is scheduled for deletion; restore it first")]
    DeletionScheduled,
    /// The account is already an administrator.
    #[error("the account is already an administrator")]
    AlreadyAdministrator,
    /// The account is not an administrator, so it has no rights to revoke.
    #[error("the account is not an administrator")]
    NotAnAdministrator,
    /// Administrators cannot grant or revoke their own rights from the dashboard.
    #[error("administrators cannot change their own rights")]
    OwnRights,
    /// The last active administrator's rights cannot be revoked, nor their account
    /// disabled, so someone is always left to administer.
    #[error("the account is the last active administrator: grant another administrator first")]
    LastAdministrator,
    /// The handle cannot be the account's: invalid, reserved or not free.
    #[error(transparent)]
    Handle(#[from] HandlesError),
    /// No released handle, or purged account's, is this one; an account's current
    /// handle is never released.
    #[error("this handle is not released: an account holds it, or none ever did")]
    HandleNotReleased,
    /// The handle rules or an administrator reserve the handle, or a look-alike,
    /// already.
    #[error("this handle, or one that looks like it, is reserved already")]
    HandleReserved,
    /// No administrator reserved this handle.
    #[error("this handle is not on the reserved list")]
    HandleNotReserved,
    /// An announcement's or a message's subject is blank, longer than 150
    /// characters, or not one line.
    #[error("give a subject of 1 to 150 characters, on one line")]
    InvalidSubject,
    /// An announcement's or a message's text is blank, longer than 20,000
    /// characters, or holds control characters other than line breaks and tabs.
    #[error("give a text of 1 to 20,000 characters, without control characters")]
    InvalidBody,
    /// An announcement to chosen accounts names none.
    #[error("name at least one account, or send it to everyone")]
    NoRecipients,
    /// An announcement names more accounts than one may be chosen for.
    #[error("name at most 1,000 accounts, or send it to everyone")]
    TooManyRecipients,
    /// An account an announcement names does not exist.
    #[error("no account has the ID, handle or verified email {0}")]
    UnknownRecipient(UserRef),
    /// No announcement has this ID.
    #[error("no announcement has this ID")]
    AnnouncementNotFound,
    /// The draft changed since its sender checked it, such as by another
    /// administrator: they check it again before sending it.
    #[error("the draft changed since you checked it; check it again before sending it")]
    AnnouncementChanged,
    /// The announcement was sent, and what was sent never changes.
    #[error("the announcement was sent, so it can no longer change")]
    AnnouncementSent,
    /// Persistence failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// A client change was refused or failed.
    #[error(transparent)]
    Client(#[from] ClientRegistryError),
    /// Deleting, restoring or purging the account was refused or failed.
    #[error(transparent)]
    Deletion(#[from] DeletionError),
    /// Secret generation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A stored event could not be shown.
    #[error("could not serialize a stored event")]
    Event(#[from] serde_json::Error),
    /// A link could not be written.
    #[error("could not write a link")]
    Link(#[from] sourceorigin_ui::QueryError),
    /// The audit chain could not be verified or pruned.
    #[error(transparent)]
    Audit(#[from] crate::AuditError),
    /// A signing key change was refused or failed.
    #[error(transparent)]
    SigningKey(KeyError),
}

impl From<KeyError> for AdminError {
    /// Keeps the operator's own refusal as it is, so the dashboard asks for a
    /// confirmation or a sign-in as for any change.
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::Refused(refused) => *refused,
            error => Self::SigningKey(error),
        }
    }
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
            Self::AlertNotFound => "alert_not_found",
            Self::AdministratorTarget => "administrator_target",
            Self::AlreadyDisabled => "already_disabled",
            Self::AlreadyActive => "already_active",
            Self::EmailClaimed(_) => "email_claimed",
            Self::InvalidReason => "invalid_reason",
            Self::InvalidInviteExpiry(_) => "invalid_invite_expiry",
            Self::InvalidInvitationEmail(_) => "invalid_invitation_email",
            Self::InvitationNeedsEmail => "invitation_needs_email",
            Self::InvitationUnsendable(_) => "invitation_unsendable",
            Self::InvitationAddressTaken => "invitation_address_taken",
            Self::InvitationNotMailed => "invitation_not_mailed",
            Self::RecoveryOfDisabledAccount => "recovery_of_disabled_account",
            Self::RecoveryNeedsEmail => "recovery_needs_email",
            Self::RecoveryOfAdministrator => "recovery_of_administrator",
            Self::RecoveryInProbation => "recovery_in_probation",
            Self::UnknownPasskey(_) => "unknown_passkey",
            Self::GrantDuringRecovery => "grant_during_recovery",
            Self::NoRecoveryToUndo => "no_recovery_to_undo",
            Self::AccountDisabled => "account_disabled",
            Self::DeletionScheduled => "deletion_scheduled",
            Self::AlreadyAdministrator => "already_administrator",
            Self::NotAnAdministrator => "not_an_administrator",
            Self::OwnRights => "own_rights",
            Self::LastAdministrator => "last_administrator",
            Self::Handle(_) => "handle",
            Self::HandleNotReleased => "handle_not_released",
            Self::HandleReserved => "handle_reserved",
            Self::HandleNotReserved => "handle_not_reserved",
            Self::InvalidSubject => "invalid_subject",
            Self::InvalidBody => "invalid_body",
            Self::NoRecipients => "no_recipients",
            Self::TooManyRecipients => "too_many_recipients",
            Self::UnknownRecipient(_) => "unknown_recipient",
            Self::AnnouncementNotFound => "announcement_not_found",
            Self::AnnouncementSent => "announcement_sent",
            Self::AnnouncementChanged => "announcement_changed",
            Self::Database(_) => "database",
            Self::Client(_) => "client",
            Self::Deletion(_) => "deletion",
            Self::Crypto(_) => "crypto",
            Self::Event(_) => "event",
            Self::Link(_) => "link",
            Self::Audit(_) => "audit",
            Self::SigningKey(_) => "signing_key",
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
            | AdminError::InvalidInvitationEmail(_)
            | AdminError::InvitationUnsendable(_)
            | AdminError::InvalidHandoff
            | AdminError::InvalidSubject
            | AdminError::InvalidBody
            | AdminError::NoRecipients
            | AdminError::TooManyRecipients => Self::bad_request(message),
            AdminError::Handle(error) => error.into(),
            AdminError::SessionEnded | AdminError::StepUpRequired(_) => Self::unauthorized(message),
            AdminError::NotAdministrator
            | AdminError::AdministratorTarget
            | AdminError::OwnRights
            | AdminError::LastAdministrator => Self::forbidden(message),
            AdminError::UserNotFound
            | AdminError::SessionNotFound
            | AdminError::InvitationNotFound
            | AdminError::ClientNotFound
            | AdminError::DeliveryNotFound { .. }
            | AdminError::AlertNotFound
            | AdminError::HandleNotReleased
            | AdminError::HandleNotReserved
            | AdminError::UnknownRecipient(_)
            | AdminError::AnnouncementNotFound
            | AdminError::SigningKey(KeyError::Unknown(_)) => Self::not_found(message),
            AdminError::AlreadyDisabled
            | AdminError::AlreadyActive
            | AdminError::EmailClaimed(_)
            | AdminError::RecoveryOfDisabledAccount
            | AdminError::RecoveryNeedsEmail
            | AdminError::InvitationNeedsEmail
            | AdminError::InvitationAddressTaken
            | AdminError::InvitationNotMailed
            | AdminError::RecoveryOfAdministrator
            | AdminError::RecoveryInProbation
            | AdminError::UnknownPasskey(_)
            | AdminError::NoRecoveryToUndo
            | AdminError::GrantDuringRecovery
            | AdminError::AccountDisabled
            | AdminError::DeletionScheduled
            | AdminError::AlreadyAdministrator
            | AdminError::NotAnAdministrator
            | AdminError::HandleReserved
            | AdminError::AnnouncementSent
            | AdminError::AnnouncementChanged
            // A stored key that cannot sign is refused, and the form says which.
            | AdminError::SigningKey(
                KeyError::Stored { .. } | KeyError::Mismatched(_) | KeyError::NoActiveKey,
            ) => Self::conflict(message),
            AdminError::Database(error) | AdminError::SigningKey(KeyError::Database(error)) => {
                error.into()
            }
            AdminError::Client(error) => error.for_operators(),
            AdminError::Deletion(error) => error.into(),
            error @ (AdminError::Crypto(_)
            | AdminError::Event(_)
            | AdminError::Link(_)
            | AdminError::Audit(_)
            | AdminError::SigningKey(KeyError::Crypto(_) | KeyError::Refused(_))) => {
                Self::internal(error)
            }
        }
    }
}

impl ClientRegistryError {
    /// The registry's refusal, as an administrator reads it: its own words, which
    /// name the client and say what to do, where an owner reads the console's.
    /// Administrators choose IDs and see deleted clients, which owners do not.
    fn for_operators(self) -> ApiError {
        let message = self.to_string();
        match self {
            Self::Unknown(_) | Self::OriginNotApproved { .. } => ApiError::not_found(message),
            Self::Exists { .. }
            | Self::Deleted(_)
            | Self::Suspended(_)
            | Self::QuotaExceeded
            | Self::DailyLimitExceeded
            | Self::TooManyDomains(_)
            | Self::OriginApproved { .. } => ApiError::conflict(message),
            Self::Public(_)
            | Self::MissingSecret(_)
            | Self::Immutable(_)
            | Self::Untrusted(_)
            | Self::NotRedirectOrigin { .. }
            | Self::PublicSuffix(_) => ApiError::bad_request(message),
            Self::Database(error) => error.into(),
            error @ Self::Crypto(_) => ApiError::internal(error),
        }
    }
}
