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
    AccountDeletionRepository, AdministratorRepository, DeliveryRepository, EmailRepository,
    EventRepository, FederationRepository, MaintenanceRepository, OidcRepository,
    PasskeyRepository, SecurityRepository, SessionRepository, TokenRepository, UserRepository,
    deletions::AccountDeletion,
    deliveries::{
        BackchannelLogout, Channel, Delivery, DeliveryOutcome, DeliveryStatus, DeliverySummary,
        Email, EmailMessage, LogoutRecipient, NewDelivery, PendingAddress,
    },
    emails::{InsertUnverifiedEmail, InsertVerifiedEmail, PendingVerification, StoredEmail},
    events::{EventCursor, EventFilter, RecordedEvent, StoredEvent},
    federation::{
        ConsumedFederationTransaction, InsertExternalIdentity, InsertFederationTransaction,
        PendingFederation, StoredExternalIdentity,
    },
    oidc::{
        CodeRedemptionError, ConsumedAuthorizationCode, InsertAuthorizationCode,
        InsertAuthorizationRequest, OidcRedirectKind, OwnedClientCounts,
        StoredAuthorizationRequest, StoredClientSecret, StoredOidcClient,
    },
    passkeys::{CeremonyKind, ConsumedCeremony, InsertCeremony, InsertPasskey, StoredPasskey},
    sessions::{
        InsertSession, LAST_SEEN_INTERVAL, SessionAuthentication, SessionScope, StoredSession,
    },
    tokens::{
        InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, RevokedFamily,
        RotatedRefreshToken, StoredGrant,
    },
    users::{AccountName, InsertUser, StoredUser},
};
pub use transaction::DatabaseTransaction;
