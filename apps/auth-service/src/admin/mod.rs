//! Administration: [`AdminService`], which the admin dashboard and the CLI both
//! call in-process, and signing administrators in to the dashboard.
//!
//! Every operation takes the [`Operator`] who runs it and authorizes them itself:
//! an administrator signed in to the dashboard, whom only [`DashboardSignIn`]
//! finds, from the dashboard's session cookie, or an operator at the terminal.

/// Admin failures and their status and message.
mod error;
/// The list of operations the CLI covers.
mod operation;
/// Who runs an administrative operation.
mod operator;
/// The service shared by the dashboard and the CLI.
mod service;
/// Signing administrators in to the dashboard.
mod sign_in;
/// Validated inputs.
mod types;

pub use error::AdminError;
pub(crate) use operation::AdminOperation;
use operator::AdminSession;
pub use operator::Operator;
pub use service::AdminService;
pub(crate) use sign_in::{DashboardSignIn, SignedInAdmin};
pub use types::{
    GracePeriod, HandleIssue, HandleProblem, InvalidLifetime, InviteExpiry, Reason, UserRef,
};

/// Administrative scenarios over the service, and the harness the shared
/// settings' tests also use.
#[cfg(test)]
pub(crate) mod tests;
