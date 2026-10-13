//! The sole `SQLx` boundary for the Piquel workspace.
//!
//! Applications receive typed repositories and never a pool, executor, row, or
//! `SQLx` error. Repositories expose only the operations used by the service.
/// Validated `PostgreSQL` transport and bounded connection pools.
mod connection;
/// Typed persistence and connection failures.
mod error;
/// Typed repository families with private SQL execution.
mod repositories;
/// Explicit transactions spanning typed repository operations.
mod transaction;

pub use connection::{Database, DatabaseConfig};
pub use error::{DatabaseConnectionError, DatabaseError};
pub use repositories::{
    AuditEventRepository, EmailRepository, FederationRepository, OidcRepository, PasskeyRepository,
    SecurityRepository, SessionRepository, TokenRepository, UserRepository,
    audit::{AppendAuditEvent, AuditAction, AuditMetadata, AuditOutcome},
    emails::{InsertVerifiedEmail, StoredEmail},
    federation::{
        ConsumedFederationTransaction, InsertExternalIdentity, InsertFederationTransaction,
        PendingFederation, StoredExternalIdentity,
    },
    oidc::{
        BootstrapOidcClient, ClientConfigurationError, ConsumedAuthorizationCode,
        InsertAuthorizationCode, InsertAuthorizationRequest, OidcRedirectKind,
        StoredAuthorizationRequest, StoredOidcClient,
    },
    passkeys::{CeremonyKind, ConsumedCeremony, InsertCeremony, InsertPasskey, StoredPasskey},
    sessions::{InsertSession, StoredSession},
    tokens::{InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, RotatedRefreshToken},
    users::{InsertUser, StoredUser},
};
pub use transaction::DatabaseTransaction;
