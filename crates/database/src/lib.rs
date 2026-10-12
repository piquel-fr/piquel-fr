//! The sole `SQLx` boundary for the Piquel workspace.
//!
//! Applications receive typed repositories and never a pool, executor, row, or
//! `SQLx` error. Repositories expose only the operations used by the service.

mod connection;
mod error;
mod repositories;
mod transaction;

pub use connection::{Database, DatabaseConfig};
pub use error::{DatabaseConnectionError, DatabaseError};
pub use repositories::{
    AuditEventRepository, EmailRepository, FederationRepository, OidcRepository, PasskeyRepository,
    SecurityRepository, SessionRepository, TokenRepository, UserRepository,
    audit::AppendAuditEvent,
    emails::{InsertVerifiedEmail, StoredEmail},
    federation::{
        ConsumedFederationTransaction, InsertExternalIdentity, InsertFederationTransaction,
        PendingFederation, StoredExternalIdentity,
    },
    oidc::{
        BootstrapOidcClient, ConsumedAuthorizationCode, InsertAuthorizationCode,
        InsertAuthorizationRequest, StoredAuthorizationRequest, StoredOidcClient,
    },
    passkeys::{ConsumedCeremony, InsertCeremony, InsertPasskey, StoredPasskey},
    sessions::{InsertSession, StoredSession},
    tokens::{InsertRefreshFamily, InsertRefreshToken, RefreshRotationError, RotatedRefreshToken},
    users::{InsertUser, StoredUser},
};
pub use transaction::DatabaseTransaction;
