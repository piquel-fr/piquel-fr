//! The sole `SQLx` boundary for the Piquel workspace.
//!
//! Applications receive typed repositories and never a pool, executor, row, or
//! `SQLx` error. Feature repositories are intentionally scaffolded until their
//! owning auth plan supplies persistence operations.
#![allow(missing_docs)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::wildcard_imports
)]

mod connection;
mod error;
<<<<<<< HEAD
mod models;
=======
>>>>>>> main
mod repositories;
mod transaction;

pub use connection::{Database, DatabaseConfig};
pub use error::{DatabaseConnectionError, DatabaseError};
<<<<<<< HEAD
pub use models::*;
=======
>>>>>>> main
pub use repositories::{
    AuditEventRepository, EmailRepository, FederationRepository, InternalEventRepository,
    OidcRepository, PasskeyRepository, ServiceIdentityRepository, SessionRepository,
    TokenRepository, UserRepository,
};
pub use transaction::DatabaseTransaction;
