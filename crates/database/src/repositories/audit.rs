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
        /// A passkey confirmed an existing session for protected actions.
        SessionPasskeyConfirmed = "session.passkey_confirmed",
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
pub(crate) struct AuditMetadata {
    /// Provider involved in the operation, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<Provider>,
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
            user_id,
            action,
            AuditOutcome::Success,
            AuditMetadata { provider },
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
            user_id,
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
        user_id: UserId,
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
                user_id.as_uuid(),
                action.as_str(),
                outcome.as_str(),
                sqlx::types::Json(&request_metadata) as _,
            )
        )?;
        Ok(())
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
