//! Failures of startup and administrative commands.

use crate::{
    AdminError, ClientRegistryError, KeyError, StartupError, UserRef, account::AccountError,
};
use sourceorigin_common::{
    clients::{InvalidCount, InvalidDisplayName, InvalidRedirectUri, InvalidScopeName},
    config::{ConfigurationError, SecretError},
};
use sourceorigin_crypto::CryptoError;
use sourceorigin_repository::{DatabaseConnectionError, DatabaseError};
use sourceorigin_telemetry::TelemetryError;
use thiserror::Error;

/// Failures of startup and administrative commands, preserving their original causes.
#[derive(Debug, Error)]
pub(super) enum CliError {
    /// A required operator setting is missing or invalid.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    /// The authentication database could not be connected.
    #[error("could not connect to authentication database")]
    Connection(#[from] DatabaseConnectionError),
    /// An administrative database operation failed.
    #[error("authentication database command failed")]
    Database(#[from] DatabaseError),
    /// An administrative operation was refused or failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
    /// A change to an account's settings was refused or failed.
    #[error(transparent)]
    Account(#[from] AccountError),
    /// The audit chain is broken, or the keys to check it against are invalid.
    #[error(transparent)]
    Audit(#[from] crate::AuditError),
    /// The text given with `--body-file` could not be read.
    #[error("could not read the text given with --body-file")]
    BodyFile(#[source] std::io::Error),
    /// The file given with `--key` could not be read.
    #[error("could not read the verifier keys given with --key")]
    AuditKeyFile(#[source] std::io::Error),
    /// A signing key change was refused or failed.
    #[error(transparent)]
    Keys(#[from] KeyError),
    /// The account an operator named could not be found.
    #[error("account {user}")]
    User {
        /// The reference, as given.
        user: UserRef,
        /// Why it was not found.
        #[source]
        source: AdminError,
    },
    /// Nothing names who runs an administrative command.
    #[error(
        "who runs this command is unknown: pass --operator NAME, or set AUTH_OPERATOR, as piquelctl app exec sets no $USER"
    )]
    UnknownOperator,
    /// A change that needs confirmation ran without a terminal or `--yes`.
    #[error("this command needs confirmation: run it on a terminal, or pass --yes")]
    Unconfirmed,
    /// The operator did not confirm a change.
    #[error("cancelled")]
    Declined,
    /// The confirmation could not be read.
    #[error("could not read the confirmation")]
    Prompt(#[source] std::io::Error),
    /// A client change was refused.
    #[error(transparent)]
    Client(#[from] ClientRegistryError),
    /// A display name, given or stored, is invalid.
    #[error(transparent)]
    DisplayName(#[from] InvalidDisplayName),
    /// A redirect URI, given or stored, is invalid.
    #[error(transparent)]
    RedirectUri(#[from] InvalidRedirectUri),
    /// A scope, given or stored, is invalid.
    #[error(transparent)]
    Scope(#[from] InvalidScopeName),
    /// A registration list has too few or too many values.
    #[error("invalid {field}")]
    Count {
        /// The list, e.g. `redirect URIs`.
        field: &'static str,
        /// The allowed and given counts.
        #[source]
        source: InvalidCount,
    },
    /// The secret given with `--secret` could not be read.
    #[error("could not read the client secret given with --secret")]
    SecretUnreadable(#[from] SecretError),
    /// The secret given with `--secret` is not 256 random bits in base64url.
    #[error("the client secret given with --secret must be 32 bytes in unpadded base64url")]
    WeakSecret(#[source] CryptoError),
    /// A URI to remove is not registered.
    #[error("{0} is not registered for this client")]
    NotRegistered(String),
    /// Command output could not be encoded.
    #[error("could not encode JSON output")]
    Json(#[from] serde_json::Error),
    /// Command output could not be written.
    #[error("could not write the command's output")]
    Output(#[source] std::io::Error),
    /// HTTP applications or embedded assets could not be initialized.
    #[error(transparent)]
    Startup(#[from] StartupError),
    /// The service listener could not be bound or served.
    #[error("authentication HTTP listener failed")]
    Listener(#[from] std::io::Error),
    /// A background job panicked.
    #[error("a background job panicked")]
    Job(#[from] tokio::task::JoinError),
    /// Telemetry could not be installed.
    #[error(transparent)]
    Telemetry(#[from] TelemetryError),
}

impl CliError {
    /// Names the registration list, e.g. `redirect URIs`, whose count was out of bounds.
    pub(super) fn count(field: &'static str) -> impl FnOnce(InvalidCount) -> Self {
        move |source| Self::Count { field, source }
    }
}
