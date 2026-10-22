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
/// Explicit transactions spanning typed repository operations.
mod transaction;

pub use connection::{Database, DatabaseConfig};
pub use error::{DatabaseConnectionError, DatabaseError};
pub use exclusive::{ExclusiveConnection, LockKey};
pub use repositories::{
    AdministratorRepository, DeliveryRepository, EmailRepository, EventRepository,
    FederationRepository, MaintenanceRepository, OidcRepository, PasskeyRepository,
    SecurityRepository, SessionRepository, TokenRepository, UserRepository,
    deliveries::{
        Channel, Delivery, DeliveryOutcome, DeliveryStatus, DeliverySummary, NewDelivery,
    },
    emails::{InsertVerifiedEmail, StoredEmail},
    events::{EventCursor, EventFilter, RecordedEvent, StoredEvent},
    federation::{
        ConsumedFederationTransaction, InsertExternalIdentity, InsertFederationTransaction,
        PendingFederation, StoredExternalIdentity,
    },
    oidc::{
        Approval, CodeRedemptionError, ConsumedAuthorizationCode, GrantGeneration,
        InsertAuthorizationCode, InsertAuthorizationRequest, OidcRedirectKind,
        StoredAuthorizationRequest, StoredClientSecret, StoredGrant, StoredOidcClient,
    },
    passkeys::{CeremonyKind, ConsumedCeremony, InsertCeremony, InsertPasskey, StoredPasskey},
    sessions::{InsertSession, SessionAuthentication, StoredSession},
    tokens::{
        InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, RevokedFamily,
        RotatedRefreshToken,
    },
    users::{InsertUser, StoredUser},
};
pub use transaction::DatabaseTransaction;
