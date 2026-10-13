//! Append-only security history with typed actions, outcomes and metadata.

use super::{AuditEventRepository, RepositoryExecutor};
use crate::DatabaseError;
use piquel_auth_protocol::{Provider, TokenId, UserId};
use serde::Serialize;

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
/// Non-sensitive context stored in the audit JSON column.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AuditMetadata {
    /// Provider involved in the operation, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
}

/// A security audit entry. Audit history is retained indefinitely.
#[derive(Clone, Debug)]
pub struct AppendAuditEvent {
    /// Entry identifier.
    pub id: TokenId,
    /// Affected account, when one is known.
    pub user_id: Option<UserId>,
    /// Operation that occurred.
    pub action: AuditAction,
    /// Whether the operation succeeded, failed or was rejected by policy.
    pub outcome: AuditOutcome,
    /// Non-sensitive request context as a JSON object.
    pub request_metadata: AuditMetadata,
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
        self.append(&AppendAuditEvent {
            id: TokenId::new(),
            user_id: Some(user_id),
            action,
            outcome: AuditOutcome::Success,
            request_metadata: AuditMetadata { provider },
        })
        .await
    }

    /// Appends an audit entry.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails. Outcomes are validated by their type.
    pub async fn append(&mut self, input: &AppendAuditEvent) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query(
                "INSERT INTO security_audit_log (id, user_id, action, outcome, request_metadata)
                VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(input.id.as_uuid())
            .bind(input.user_id.map(UserId::as_uuid))
            .bind(input.action.as_str())
            .bind(input.outcome.as_str())
            .bind(sqlx::types::Json(&input.request_metadata))
        )?;
        Ok(())
    }
}
