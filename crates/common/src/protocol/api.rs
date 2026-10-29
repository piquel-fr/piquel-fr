//! Bodies of auth's first-party JSON API, the account API, for the signed-in
//! user, which the admin dashboard's views share.
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
use chrono::{DateTime, Utc};
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
    /// The session was confirmed with a passkey, and this sign-in would lower its
    /// assurance: frontends sign out first, then sign in again.
    PasskeyRequired,
    /// The recovery link is unknown, expired, used or cancelled, or its account
    /// was disabled.
    InvalidLink,
    /// The account has no recovery that can be undone, or not the one named.
    NothingToUndo,
    /// Undoing the recovery needs a passkey other than its own: the asserting
    /// one was the recovery's, or the account has no other, and only support can
    /// undo it.
    OlderPasskeyRequired,
    /// The passkey belongs to a recovery in probation, which signs in but never
    /// confirms a session until the recovery settles.
    RecoveryProbation {
        /// When the probation ends.
        settles_at: DateTime<Utc>,
    },
    /// A recovery of the account can still be undone, so no passkey but the
    /// recovery's own is removed until it settles or is undone.
    RecoveryInProgress,
    /// An application page cannot sign the user in itself, because the browser or
    /// the authorization request needs auth's own pages. It sends the user through
    /// the redirect flow instead: with the same request when the sign-in's start
    /// refused it, which leaves it unclaimed, or with a fresh one when its finish
    /// did, since its start claimed it.
    InteractionRequired,
}

/// An active passkey of an account, without its cryptographic contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    // Fields stay in the settings API's original order, for byte-for-byte replies.
    /// The label its owner chose.
    pub friendly_name: String,
    /// Passkey ID, used to rename or remove it.
    pub id: PasskeyId,
    /// When it was enrolled. A label can be renamed, so pages tell passkeys apart
    /// by this and their ID.
    pub created_at: DateTime<Utc>,
}

/// A social identity linked to an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// The identity's provider.
    pub provider: Provider,
    /// The email the provider reported when it was linked, if any.
    pub linked_email: Option<String>,
}
