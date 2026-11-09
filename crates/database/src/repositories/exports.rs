//! The records of an account its data export reads in full, ended ones
//! included, where the other repositories read only what is in use. The export
//! reads the rest through them.

use super::{ExportRepository, JsonArray, RepositoryExecutor};
use crate::{DatabaseError, StoredPasskey};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sourceorigin_common::{
    AnnouncementId, AuthenticationMethod, ClientId, EventId, NotificationId, PasskeyId, Provider,
    SessionId, UserId, events::UserAgentFamily,
};
use std::net::IpAddr;

/// A GitHub or Google identity the account linked, unlinked ones included until
/// cleanup deletes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityRecord {
    /// The provider.
    pub provider: Provider,
    /// The provider's identifier of the person.
    pub subject: String,
    /// The email the provider reported when it was linked, if any.
    pub linked_email: Option<String>,
    /// When it was linked.
    pub linked_at: DateTime<Utc>,
    /// When it last signed in.
    pub last_login_at: DateTime<Utc>,
    /// When it was unlinked; `None` while linked.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A browser session of the account, ended ones included until cleanup deletes
/// them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionRecord {
    /// Session ID.
    pub id: SessionId,
    /// How it authenticated.
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// When it signed in.
    pub authenticated_at: DateTime<Utc>,
    /// The browser and platform it signed in with, if recorded.
    pub device: Option<UserAgentFamily>,
    /// The IP address it signed in from, if recorded.
    pub created_ip: Option<IpAddr>,
    /// When it was last active, refreshed at most every few minutes.
    pub last_seen_at: DateTime<Utc>,
    /// The IP address of its last recorded activity, if recorded.
    pub last_seen_ip: Option<IpAddr>,
    /// When a passkey last confirmed it, if one did.
    pub passkey_confirmed_at: Option<DateTime<Utc>>,
    /// The passkey that signed it in, or last confirmed it, if one did.
    pub passkey_id: Option<PasskeyId>,
    /// When it expires, or expired.
    pub expires_at: DateTime<Utc>,
    /// When it was signed out; `None` unless it was.
    pub revoked_at: Option<DateTime<Utc>>,
    /// The apps it signed in to, first one first.
    pub clients: Vec<ClientId>,
}

/// A notification of the account's inbox as stored, whatever its kind: one a
/// newer release wrote is exported too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationRecord {
    /// Notification ID.
    pub id: NotificationId,
    /// When it was written.
    pub created_at: DateTime<Utc>,
    /// When its owner last read it, unless they marked it unread since.
    pub read_at: Option<DateTime<Utc>>,
    /// The event it comes from, if any.
    pub event_id: Option<EventId>,
    /// What it says, as stored: `{"kind": …, …}`.
    #[serde(flatten)]
    pub payload: Value,
}

/// An announcement the account received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AnnouncementRecord {
    /// Announcement ID.
    pub id: AnnouncementId,
    /// Its subject.
    pub subject: String,
    /// Its text.
    pub body: String,
    /// Whether it went to every account, rather than to chosen ones.
    pub everyone: bool,
    /// When it was sent.
    pub sent_at: DateTime<Utc>,
}

impl ExportRepository<'_> {
    /// Every passkey the account holds or held, revoked ones included, oldest
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn passkeys(&mut self, user_id: UserId) -> Result<Vec<StoredPasskey>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredPasskey,
                r#"SELECT
                    id AS "id: PasskeyId", credential_id, user_id AS "user_id: UserId", credential,
                    friendly_name, created_at, last_used_at, revoked_at
                FROM passkey_credentials
                WHERE user_id = $1
                ORDER BY created_at, id"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Every identity the account linked, unlinked ones included, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn identities(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<IdentityRecord>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                IdentityRecord,
                r#"SELECT
                    provider_name AS "provider: Provider", subject, linked_email, linked_at,
                    last_login_at, revoked_at
                FROM external_login_identities
                WHERE user_id = $1
                ORDER BY linked_at, id"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Every session of the account, ended ones included, most recently active
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn sessions(&mut self, user_id: UserId) -> Result<Vec<SessionRecord>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                SessionRecord,
                r#"SELECT
                    s.id AS "id: SessionId",
                    s.authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    s.authenticated_at, s.user_agent_family AS "device: UserAgentFamily",
                    s.created_ip AS "created_ip: IpAddr", s.last_seen_at,
                    s.last_seen_ip AS "last_seen_ip: IpAddr", s.passkey_confirmed_at,
                    s.passkey_id AS "passkey_id: PasskeyId", s.expires_at, s.revoked_at,
                    (
                        SELECT COALESCE(jsonb_agg(c.client_id ORDER BY c.first_issued_at), '[]')
                        FROM oidc_session_clients c
                        WHERE c.session_id = s.id
                    ) AS "clients!: JsonArray<ClientId>"
                FROM sessions s
                WHERE s.user_id = $1
                ORDER BY s.last_seen_at DESC, s.id DESC"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Every notification of the account's inbox, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn notifications(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<NotificationRecord>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                NotificationRecord,
                r#"SELECT
                    id AS "id: NotificationId", created_at, read_at,
                    event_id AS "event_id: EventId", payload
                FROM notifications
                WHERE user_id = $1
                ORDER BY created_at DESC, id DESC"#,
                user_id.as_uuid(),
            )
        )
    }

    /// The announcements the account received, until cleanup deletes its
    /// recipient row, newest first. Drafts are the administrators' until sent.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn announcements(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<AnnouncementRecord>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                AnnouncementRecord,
                r#"SELECT
                    a.id AS "id: AnnouncementId", a.subject, a.body, a.everyone,
                    a.sent_at AS "sent_at!"
                FROM announcements a
                JOIN announcement_recipients r ON r.announcement_id = a.id
                WHERE r.user_id = $1 AND a.sent_at IS NOT NULL
                ORDER BY a.sent_at DESC, a.id DESC"#,
                user_id.as_uuid(),
            )
        )
    }

    /// When the account became an administrator, if it is one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn administrator_since(
        &mut self,
        user_id: UserId,
    ) -> Result<Option<DateTime<Utc>>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT granted_at FROM administrators WHERE user_id = $1",
                user_id.as_uuid(),
            )
        )
    }
}
