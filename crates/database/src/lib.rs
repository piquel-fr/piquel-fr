//! The sole `SQLx` boundary for the Piquel workspace.
//!
//! Applications receive typed repositories and never a pool, executor, row, or
//! `SQLx` error. Repositories expose only the operations used by the service.
// This unpublished persistence API mirrors the schema; field-by-field rustdoc
// and mechanical accessor annotations would duplicate the migration documentation.
#![allow(missing_docs)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::wildcard_imports
)]

mod connection;
mod error;
mod models;
mod repositories;
mod transaction;

pub use connection::{Database, DatabaseConfig};
pub use error::{DatabaseConnectionError, DatabaseError};
pub use models::*;
pub use repositories::{
    AuditEventRepository, EmailRepository, FederationRepository, OidcRepository, PasskeyRepository,
    SecurityRepository, SessionRepository, TokenRepository, UserRepository,
};
pub use transaction::DatabaseTransaction;
