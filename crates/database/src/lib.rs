//! The sole `SQLx` boundary for the Piquel workspace.
//!
//! Applications receive typed repositories and never a pool, executor, row, or
//! `SQLx` error. Repositories expose only the operations used by the service, plus
//! read-only helpers behind the `test-support` feature for other crates' tests.
/// Validated `PostgreSQL` transport and bounded connection pools.
mod connection;
/// Typed persistence and connection failures.
mod error;
/// Advisory locks for jobs that run on one replica at a time.
mod exclusive;
/// Typed repository families with private SQL execution.
mod repositories;
/// Committed events and pool connections, reported to telemetry.
mod telemetry;
/// Explicit transactions spanning typed repository operations.
mod transaction;

pub use connection::{Database, DatabaseConfig, RuntimeRole};
pub use error::{DatabaseConnectionError, DatabaseError};
pub use exclusive::{ExclusiveConnection, LockKey};
pub use repositories::{
    AdministratorRepository, DashboardRepository, DeliveryRepository, EmailRepository,
    EventRepository, FederationRepository, MaintenanceRepository, OidcRepository,
    PasskeyRepository, RecoveryRepository, SecurityRepository, SessionRepository,
    SigningKeyRepository, TokenRepository, UserRepository,
    dashboard::{InsertHandoff, RedeemedHandoff, StoredDashboardSession},
    deliveries::{
        BackchannelLogout, Channel, Delivery, DeliveryOutcome, DeliveryStatus, DeliverySummary,
        Email, EmailMessage, LogoutRecipient, NewDelivery, PendingAddress, PendingRecovery,
    },
    emails::{InsertUnverifiedEmail, InsertVerifiedEmail, PendingVerification, StoredEmail},
    events::{EventCursor, EventFilter, RecordedEvent, StoredEvent},
    federation::{
        ConsumedFederationTransaction, InsertExternalIdentity, InsertFederationTransaction,
        PendingFederation, StoredExternalIdentity,
    },
    maintenance::{DigestUsage, DigestedSecret},
    oidc::{
        CodeRedemptionError, ConsumedAuthorizationCode, InsertAuthorizationCode,
        InsertAuthorizationRequest, OidcRedirectKind, OwnedClientCounts, StoredApp,
        StoredAuthorizationRequest, StoredClientSecret, StoredOidcClient,
    },
    passkeys::{CeremonyKind, ConsumedCeremony, InsertCeremony, InsertPasskey, StoredPasskey},
    recoveries::{InsertRecovery, RecentRecovery, RecoveryPasskey, RecoveryState, StoredRecovery},
    sessions::{
        InsertSession, LAST_SEEN_INTERVAL, SessionAuthentication, SessionScope, StoredSession,
    },
    signing_keys::{InsertSigningKey, SigningKeyState, SigningKeyType, StoredSigningKey},
    tokens::{
        InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, RevokedFamily,
        RotatedRefreshToken,
    },
    users::{AccountName, InsertUser, StoredUser},
};
pub use transaction::DatabaseTransaction;
