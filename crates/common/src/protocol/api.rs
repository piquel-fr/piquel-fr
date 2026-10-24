//! Bodies shared by auth's first-party JSON APIs: the account API, for the
//! signed-in user, and the admin API.
//!
//! ```
//! use piquel_common::protocol::api::{ErrorBody, ErrorCode};
//!
//! let body: ErrorBody = serde_json::from_str(
//!     r#"{"error": "Confirm with your passkey to continue.", "code": "step_up_required", "max_age": 300}"#,
//! )?;
//! assert_eq!(body.code, Some(ErrorCode::StepUpRequired { max_age: 300 }));
//! let plain: ErrorBody = serde_json::from_str(r#"{"error": "Not found."}"#)?;
//! assert_eq!(plain.code, None);
//! # Ok::<(), serde_json::Error>(())
//! ```

use crate::{PasskeyId, Provider};
use serde::{Deserialize, Serialize};

/// The body of an error response: `{"error": message}`, plus a machine-readable
/// `code` when the caller can resolve it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// What went wrong, specific enough to act on.
    pub error: String,
    /// What the caller can do about it, with its parameters beside it.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorCode>,
}

/// Errors a caller can resolve, serialized as `"code"` with their parameters beside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ErrorCode {
    /// The action needs a passkey confirmation of this session. Frontends confirm
    /// and retry. `max_age` is borrowed from RFC 9470.
    StepUpRequired {
        /// Maximum confirmation age the action accepts, in seconds.
        max_age: u32,
    },
    /// The handle breaks the syntax rules.
    HandleInvalid,
    /// The handle is reserved, or looks like a reserved name.
    HandleReserved,
    /// Another account holds the handle.
    HandleTaken,
}

/// An active passkey of an account, without its cryptographic contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    // Fields stay in the settings API's original order, for byte-for-byte replies.
    /// The label its owner chose.
    pub friendly_name: String,
    /// Passkey ID, used to rename or remove it.
    pub id: PasskeyId,
}

/// A social identity linked to an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// The identity's provider.
    pub provider: Provider,
    /// The email the provider reported when it was linked, if any.
    pub linked_email: Option<String>,
}
