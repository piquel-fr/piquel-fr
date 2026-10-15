//! Validated admin inputs and the admin API's request and response bodies.

use super::AdminError;
use crate::passkey::PasskeyView;
use chrono::{DateTime, Duration, Utc};
use piquel_auth_protocol::{TokenId, UserId, oauth::ClientAuthMethod};
use piquel_repository::{
    AuditAction, StoredAuditEntry, StoredConsent, StoredEmail, StoredExternalIdentity,
    StoredOidcClient, StoredSession, StoredUser,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

/// Largest accepted invitation lifetime number; the suffix chooses hours or days.
const MAX_INVITE_EXPIRY: i64 = 365;
/// Invitation lifetime when none is given.
const DEFAULT_INVITE_EXPIRY_DAYS: i64 = 7;
/// Shared explanation for invalid invitation lifetimes.
const INVITE_EXPIRY_HELP: &str = "expiry must be 1 to 365 followed by h or d, e.g. 24h or 7d";
/// Maximum Unicode characters in an administrator's reason.
const MAX_REASON_CHARS: usize = 500;

/// An invitation lifetime of 1 to 365 hours or days, written like `24h` or `7d`.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct InviteExpiry(Duration);

/// Why an invitation lifetime was rejected.
#[derive(Debug, Error)]
pub enum InvalidInviteExpiry {
    /// The unit, value or bounds violate the supported hours/days syntax.
    #[error("{INVITE_EXPIRY_HELP}")]
    Format,
    /// The numeric portion could not be parsed.
    #[error("{INVITE_EXPIRY_HELP}")]
    Number(#[from] std::num::ParseIntError),
}

impl InviteExpiry {
    /// The lifetime as a duration.
    pub(super) const fn duration(self) -> Duration {
        self.0
    }
}

impl Default for InviteExpiry {
    /// Seven days.
    fn default() -> Self {
        Self(Duration::days(DEFAULT_INVITE_EXPIRY_DAYS))
    }
}

impl FromStr for InviteExpiry {
    type Err = InvalidInviteExpiry;
    /// Parses a bounded hours/days lifetime while retaining numeric syntax errors.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (number, unit) = value
            .char_indices()
            .last()
            .map(|(index, _)| value.split_at(index))
            .ok_or(InvalidInviteExpiry::Format)?;
        let number = number.parse::<i64>()?;
        if !(1..=MAX_INVITE_EXPIRY).contains(&number) {
            return Err(InvalidInviteExpiry::Format);
        }
        match unit {
            "h" => Ok(Self(Duration::hours(number))),
            "d" => Ok(Self(Duration::days(number))),
            _ => Err(InvalidInviteExpiry::Format),
        }
    }
}

impl TryFrom<String> for InviteExpiry {
    type Error = InvalidInviteExpiry;
    /// Parses JSON lifetimes with the same rules as the command line.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Why an administrator acted: 1 to 500 characters, not blank, no control characters.
pub(crate) struct Reason(String);

impl Reason {
    /// Accepts `value` unchanged if it satisfies the rule.
    pub(crate) fn parse(value: String) -> Result<Self, AdminError> {
        if value.trim().is_empty()
            || value.chars().count() > MAX_REASON_CHARS
            || value.chars().any(char::is_control)
        {
            return Err(AdminError::InvalidReason);
        }
        Ok(Self(value))
    }

    /// Borrows the validated text.
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// `POST /admin/users/{id}/disable` body. The reason stays a plain string so an
/// invalid one gets our 400 message, not a JSON rejection.
#[derive(Deserialize)]
pub(super) struct DisableUser {
    /// Why the account is disabled; recorded in the audit log.
    pub(super) reason: String,
}

/// Optional `POST /admin/invitations` body.
#[derive(Default, Deserialize)]
pub(super) struct CreateInvitation {
    /// How long the link stays valid; seven days by default.
    #[serde(default)]
    pub(super) expires_in: InviteExpiry,
}

/// `GET /admin/users` query.
#[derive(Deserialize)]
pub(super) struct UserSearch {
    /// Account ID, or part of a username, display name or email. Empty lists every account.
    #[serde(default)]
    pub(super) q: String,
    /// The previous page's `next`, to continue after it.
    pub(super) cursor: Option<UserId>,
}

/// `GET /admin/audit` query.
#[derive(Deserialize)]
pub(super) struct AuditSearch {
    /// Only entries about this account.
    pub(super) user: Option<UserId>,
    /// Only entries with this action, e.g. `admin.user_disabled`.
    pub(super) action: Option<AuditAction>,
    /// The previous page's `next`, to continue with older entries.
    pub(super) before: Option<TokenId>,
}

/// One page of accounts.
#[derive(Serialize)]
pub(crate) struct UserPage {
    /// Matching accounts, by ID.
    pub(super) users: Vec<StoredUser>,
    /// Cursor of the next page, if there may be one.
    pub(super) next: Option<UserId>,
}

/// Everything an administrator sees about one account.
#[derive(Serialize)]
pub(crate) struct UserDetail {
    /// Profile and status.
    pub(super) user: StoredUser,
    /// Whether the account is an administrator, which the admin API cannot change.
    pub(super) administrator: bool,
    /// Email addresses, primary first.
    pub(super) emails: Vec<StoredEmail>,
    /// Active passkeys, without their cryptographic contents.
    pub(super) passkeys: Vec<PasskeyView>,
    /// Linked social identities.
    pub(super) identities: Vec<StoredExternalIdentity>,
    /// Active sessions, newest first.
    pub(super) sessions: Vec<StoredSession>,
    /// Remembered consents.
    pub(super) consents: Vec<StoredConsent>,
}

/// One page of audit entries.
#[derive(Serialize)]
pub(crate) struct AuditPage {
    /// Matching entries, newest first.
    pub(super) entries: Vec<StoredAuditEntry>,
    /// Cursor of the next, older page, if there may be one.
    pub(super) next: Option<TokenId>,
}

/// An OIDC client as administrators see it: everything but its secret digest.
#[derive(Serialize)]
pub(crate) struct ClientView {
    /// Client identifier.
    id: String,
    /// Name shown on consent screens.
    display_name: String,
    /// Exact allowed authorization redirect URIs.
    redirect_uris: Vec<String>,
    /// Exact allowed post-logout redirect URIs.
    post_logout_uris: Vec<String>,
    /// Scopes the client may request.
    allowed_scopes: Vec<String>,
    /// Audiences the client may request tokens for.
    allowed_audiences: Vec<String>,
    /// Whether the client may receive refresh tokens.
    allow_refresh: bool,
    /// Whether the client is usable.
    enabled: bool,
    /// Whether the client skips the consent screen.
    trusted: bool,
    /// How the client authenticates at the token endpoint (RFC 7591 metadata).
    token_endpoint_auth_method: ClientAuthMethod,
}

impl From<StoredOidcClient> for ClientView {
    /// Replaces the secret digest with the authentication method it implies.
    fn from(client: StoredOidcClient) -> Self {
        Self {
            token_endpoint_auth_method: match client.client_secret_hash {
                Some(_) => ClientAuthMethod::ClientSecretBasic,
                None => ClientAuthMethod::None,
            },
            id: client.id,
            display_name: client.display_name,
            redirect_uris: client.redirect_uris,
            post_logout_uris: client.post_logout_uris,
            allowed_scopes: client.allowed_scopes,
            allowed_audiences: client.allowed_audiences,
            allow_refresh: client.allow_refresh,
            enabled: client.enabled,
            trusted: client.trusted,
        }
    }
}

/// A new invitation. Its link holds the secret and is shown only once.
#[derive(Serialize)]
pub struct CreatedInvitation {
    /// Invitation identifier, for listing and revocation.
    pub id: TokenId,
    /// Single-use signup link.
    pub url: url::Url,
    /// When the link stops working.
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    //! Invitation lifetime parsing and reason bounds.
    use super::*;

    /// Invitation lifetimes accept bounded hours and days and reject malformed input.
    #[test]
    fn invite_expiry_accepts_bounded_hours_and_days() {
        assert_eq!(
            "24h"
                .parse::<InviteExpiry>()
                .map(InviteExpiry::duration)
                .ok(),
            Some(Duration::hours(24))
        );
        assert_eq!(
            "365d"
                .parse::<InviteExpiry>()
                .map(InviteExpiry::duration)
                .ok(),
            Some(Duration::days(365))
        );
        for invalid in ["", "d", "0d", "366d", "-1h", "7w", "7 d", "é"] {
            assert!(invalid.parse::<InviteExpiry>().is_err(), "{invalid}");
        }
    }

    /// Reasons count Unicode characters and reject blank or control input.
    #[test]
    fn reasons_are_bounded_visible_text() {
        for valid in ["Spam".to_owned(), "é".repeat(500)] {
            assert!(Reason::parse(valid).is_ok());
        }
        for invalid in [String::new(), " \t ".into(), "a\nb".into(), "é".repeat(501)] {
            assert!(matches!(
                Reason::parse(invalid),
                Err(AdminError::InvalidReason)
            ));
        }
    }
}
