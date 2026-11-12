//! The sole `SQLx` boundary for the SourceOrigin workspace.
//!
//! Applications receive typed repositories and never a pool, executor, row, or
//! `SQLx` error. Repositories expose only the operations used by the service, plus
//! read-only helpers behind the `test-util` feature for other crates' tests.
/// Validated `PostgreSQL` transport and bounded connection pools.
mod connection;
/// Typed persistence and connection failures.
mod error;
/// Advisory locks for jobs that run on one replica at a time.
mod exclusive;
/// What every table holds about the people behind accounts.
mod inventory;
/// Typed repository families with private SQL execution.
mod repositories;
/// Committed events and pool connections, reported to telemetry.
mod telemetry;
/// Explicit transactions spanning typed repository operations.
mod transaction;

pub use connection::{Database, DatabaseConfig, RuntimeRole};
pub(crate) use connection::{Limit, Scope};
pub use error::{DatabaseConnectionError, DatabaseError, DecodeFailure};
pub use exclusive::{ExclusiveConnection, LockKey};
pub use inventory::{Holds, Table};
#[cfg(any(test, feature = "test-util"))]
pub use repositories::audit::Tamper;
pub use repositories::{
    AccountDeletionRepository, AdministratorRepository, AlertRepository, AnnouncementRepository,
    AuditRepository, DashboardRepository, DeliveryRepository, EmailRepository, EventRepository,
    ExportRepository, FederationRepository, HandleRepository, MaintenanceRepository,
    NotificationRepository, OidcRepository, PasskeyRepository, PictureRepository,
    RecoveryRepository, SecurityRepository, SessionRepository, SigningKeyRepository,
    TokenRepository, UserRepository,
    administrators::AdministratorsLocked,
    announcements::{DraftedAnnouncement, Recipients, SentAnnouncement},
    audit::{ChainLink, ChainedEvent, Checkpoint, EventContent, SealedEvent},
    dashboard::{EndedDashboardSession, InsertHandoff, RedeemedHandoff, StoredDashboardSession},
    deletions::{AccountDeletion, RestoreToken},
    deliveries::{
        Announcement, AnnouncementEmail, BackchannelLogout, Channel, Delivery, DeliveryBacklog,
        DeliveryOutcome, DeliveryStatus, DeliverySummary, Email, EmailMessage, Invitation,
        LogoutRecipient, NewDelivery, PendingAddress, PendingRecovery,
    },
    emails::{InsertUnverifiedEmail, InsertVerifiedEmail, PendingVerification, StoredEmail},
    events::{EventCursor, EventFilter, RecordedEvent, StoredEvent, Verifications},
    exports::{AnnouncementRecord, IdentityRecord, NotificationRecord, SessionRecord},
    federation::{
        ConsumedFederationTransaction, InsertExternalIdentity, InsertFederationTransaction,
        PendingFederation, StoredExternalIdentity,
    },
    handles::{StoredHandle, StoredReservation},
    maintenance::{DigestUsage, DigestedSecret},
    notifications::{Notified, StoredNotification},
    oidc::{
        CodeRedemptionError, ConsumedAuthorizationCode, InsertAuthorizationCode,
        InsertAuthorizationRequest, OidcRedirectKind, OwnedClientCounts, StoredApp,
        StoredAuthorizationRequest, StoredClientSecret, StoredOidcClient,
    },
    passkeys::{CeremonyKind, ConsumedCeremony, InsertCeremony, InsertPasskey, StoredPasskey},
    pictures::StoredPicture,
    recoveries::{InsertRecovery, RecentRecovery, RecoveryPasskey, RecoveryState, StoredRecovery},
    security::{InsertInvitation, InvitationKey, OpenInvitation},
    sessions::{
        InsertSession, LAST_SEEN_INTERVAL, SessionAuthentication, SessionScope, StoredSession,
    },
    signing_keys::{InsertSigningKey, SigningKeyState, SigningKeyType, StoredSigningKey},
    tokens::{
        InsertRefreshFamily, InsertRefreshToken, REFRESH_REUSE_SECONDS, RedeemedRefreshToken,
        RefreshOutcome, RefreshRedemption, RefreshRedemptionError, RefreshSuccessor, RevokedFamily,
        StoredGrant,
    },
    users::{InsertUser, StoredUser},
};
pub use transaction::DatabaseTransaction;
