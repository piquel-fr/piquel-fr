//! Append-only security history with typed actions, outcomes, actors and metadata.

use super::{AuditEventRepository, RepositoryExecutor};
use crate::{DatabaseError, StoredSession};
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{Provider, SessionId, TokenId, UserId};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

piquel_common::str_enum! {
    /// Actions recorded in the permanent security audit log.
    pub enum AuditAction {
        /// A new account was created.
        AccountCreate = "account.create",
        /// A passkey authenticated the account.
        PasskeyLogin = "passkey.login",
        /// A passkey opened the settings management window.
        SettingsUnlock = "settings.unlock",
        /// A passkey was enrolled.
        PasskeyAdd = "passkey.add",
        /// A passkey was renamed.
        PasskeyRename = "passkey.rename",
        /// A passkey was revoked.
        PasskeyRemove = "passkey.remove",
        /// An external provider authenticated the account.
        FederationLogin = "federation.login",
        /// An external identity was linked.
        FederationLink = "federation.link",
        /// An external identity was unlinked.
        FederationUnlink = "federation.unlink",
        /// A refresh token was replayed.
        RefreshReplay = "refresh.replay",
        /// Refresh token policy rejected rotation.
        RefreshPolicyRejected = "refresh.policy_rejected",
        /// A redeemed authorization code was redeemed again.
        AuthorizationCodeReplay = "authorization_code.replay",
        /// A passkey's signature counter did not increase, so it may have been copied.
        PasskeyCounterRegression = "passkey.counter_regression",
        /// An operator granted the account administrator rights.
        AdminGrant = "admin.granted",
        /// An operator revoked the account's administrator rights.
        AdminRevoke = "admin.revoked",
        /// An administrator viewed the account's details, which include personal data.
        AdminUserView = "admin.user_viewed",
        /// An administrator disabled the account and ended its sessions.
        AdminUserDisable = "admin.user_disabled",
        /// An administrator reactivated the account.
        AdminUserEnable = "admin.user_enabled",
        /// An administrator ended every session and refresh grant of the account.
        AdminSessionsRevoke = "admin.sessions_revoked",
        /// An administrator ended one session of the account and its refresh grants.
        AdminSessionRevoke = "admin.session_revoked",
        /// An administrator created a signup invitation.
        AdminInvitationCreate = "admin.invitation_created",
        /// An administrator revoked a signup invitation.
        AdminInvitationRevoke = "admin.invitation_revoked",
    }
}
piquel_common::str_enum! {
    /// SQL-compatible outcome of an audited operation.
    pub enum AuditOutcome {
        /// The operation completed.
        Success = "success",
        /// The operation failed.
        Failure = "failure",
        /// Policy rejected the operation.
        Rejected = "rejected",
    }
}
/// Who performed an administrative operation, stored with its audit entry,
/// invitation or administrator grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Actor {
    /// An administrator using the admin API.
    Admin {
        /// The administrator's account.
        user_id: UserId,
        /// The browser session the administrator used.
        session_id: SessionId,
    },
    /// An operator running the `auth-service` CLI.
    Cli {
        /// Operating-system user that ran the command.
        os_user: String,
        /// Host the command ran on.
        host: String,
    },
}

impl Actor {
    /// The administrator signed in with `session`.
    #[must_use]
    pub const fn admin(session: &StoredSession) -> Self {
        Self::Admin {
            user_id: session.user_id,
            session_id: session.id,
        }
    }
}

impl std::fmt::Display for Actor {
    /// Formats the actor for operators, e.g. `root@host` or `admin <id> (session <id>)`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin {
                user_id,
                session_id,
            } => write!(f, "admin {user_id} (session {session_id})"),
            Self::Cli { os_user, host } => write!(f, "{os_user}@{host}"),
        }
    }
}

/// Non-sensitive context stored in the audit JSON column. Every field is optional,
/// so entries written before a field existed still decode.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMetadata {
    /// Provider involved in the operation, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// Who performed an administrative operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    /// Why the actor performed it, when they had to say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One security audit log entry.
#[derive(Clone, Debug, Serialize)]
pub struct StoredAuditEntry {
    /// Entry identifier; entries sort by it in creation order.
    pub id: TokenId,
    /// Account the entry concerns, if any.
    pub user_id: Option<UserId>,
    /// What happened.
    pub action: AuditAction,
    /// How it ended.
    pub outcome: AuditOutcome,
    /// Provider, actor and reason, when recorded.
    pub metadata: AuditMetadata,
    /// When it was recorded.
    pub created_at: DateTime<Utc>,
}

/// Selects a page of [`StoredAuditEntry`] values, newest first.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuditFilter {
    /// Only entries about this account.
    pub user_id: Option<UserId>,
    /// Only entries with this action.
    pub action: Option<AuditAction>,
    /// Only entries older than this entry, to continue a previous page.
    pub before: Option<TokenId>,
}

impl AuditEventRepository<'_> {
    /// Records a successful account operation with optional provider context.
    ///
    /// # Errors
    /// Preserves database failures from the append operation.
    pub async fn record(
        &mut self,
        user_id: UserId,
        action: AuditAction,
        provider: Option<Provider>,
    ) -> Result<(), DatabaseError> {
        self.record_outcome(
            Some(user_id),
            action,
            AuditOutcome::Success,
            AuditMetadata {
                provider,
                ..AuditMetadata::default()
            },
        )
        .await
    }

    /// Records a successful administrative operation by `actor`, about `user_id`
    /// when it concerns an account, with the actor's `reason` when one was given.
    ///
    /// # Errors
    /// Preserves database failures from the append operation.
    pub async fn record_by(
        &mut self,
        actor: &Actor,
        user_id: Option<UserId>,
        action: AuditAction,
        reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        self.record_outcome(
            user_id,
            action,
            AuditOutcome::Success,
            AuditMetadata {
                provider: None,
                actor: Some(actor.clone()),
                reason: reason.map(Into::into),
            },
        )
        .await
    }

    /// Records an account operation that policy rejected.
    ///
    /// # Errors
    /// Preserves database failures from the append operation.
    pub async fn record_rejection(
        &mut self,
        user_id: UserId,
        action: AuditAction,
    ) -> Result<(), DatabaseError> {
        self.record_outcome(
            Some(user_id),
            action,
            AuditOutcome::Rejected,
            AuditMetadata::default(),
        )
        .await
    }

    /// Appends a new entry for an account operation. Audit history is retained
    /// indefinitely; actions and outcomes are validated by their types.
    async fn record_outcome(
        &mut self,
        user_id: Option<UserId>,
        action: AuditAction,
        outcome: AuditOutcome,
        request_metadata: AuditMetadata,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO security_audit_log (id, user_id, action, outcome, request_metadata)
                VALUES ($1, $2, $3, $4, $5)",
                TokenId::new().as_uuid(),
                user_id.map(UserId::as_uuid),
                action.as_str(),
                outcome.as_str(),
                Json(&request_metadata) as _,
            )
        )?;
        Ok(())
    }

    /// Lists up to `limit` entries matching `filter`, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored value is outside its vocabulary.
    pub async fn list(
        &mut self,
        filter: AuditFilter,
        limit: u16,
    ) -> Result<Vec<StoredAuditEntry>, DatabaseError> {
        Ok(run!(
            self,
            fetch_all,
            sqlx::query!(
                r#"SELECT
                    id AS "id: TokenId", user_id AS "user_id: UserId",
                    action AS "action: AuditAction", outcome AS "outcome: AuditOutcome",
                    request_metadata AS "metadata: Json<AuditMetadata>", created_at
                FROM security_audit_log
                WHERE ($1::uuid IS NULL OR user_id = $1)
                AND ($2::text IS NULL OR action = $2)
                AND ($3::uuid IS NULL OR id < $3)
                ORDER BY id DESC
                LIMIT $4"#,
                filter.user_id.map(UserId::as_uuid),
                filter.action.map(AuditAction::as_str),
                filter.before.map(TokenId::as_uuid),
                i64::from(limit),
            )
        )?
        .into_iter()
        .map(|row| StoredAuditEntry {
            id: row.id,
            user_id: row.user_id,
            action: row.action,
            outcome: row.outcome,
            metadata: row.metadata.0,
            created_at: row.created_at,
        })
        .collect())
    }

    /// Lists an account's audit actions and outcomes, newest first, so other crates'
    /// tests can observe what the service recorded.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a stored value is outside its vocabulary.
    #[cfg(feature = "test-support")]
    pub async fn list_for_user(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<(AuditAction, AuditOutcome)>, DatabaseError> {
        Ok(run!(
            self,
            fetch_all,
            sqlx::query!(
                r#"SELECT action AS "action: AuditAction", outcome AS "outcome: AuditOutcome"
                FROM security_audit_log
                WHERE user_id = $1
                ORDER BY created_at DESC, id DESC"#,
                user_id.as_uuid(),
            )
        )?
        .into_iter()
        .map(|row| (row.action, row.outcome))
        .collect())
    }
}
