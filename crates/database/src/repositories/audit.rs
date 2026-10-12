use super::{AuditEventRepository, RepositoryExecutor};
use crate::DatabaseError;
use piquel_auth_protocol::{TokenId, UserId};
use serde_json::Value;

/// A security audit entry. Audit history is retained indefinitely.
#[derive(Clone, Debug)]
pub struct AppendAuditEvent {
    /// Entry identifier.
    pub id: TokenId,
    /// Affected account, when one is known.
    pub user_id: Option<UserId>,
    /// What happened, e.g. `logout`.
    pub action: String,
    /// One of `success`, `failure` or `rejected`.
    pub outcome: String,
    /// Non-sensitive request context as a JSON object.
    pub request_metadata: Value,
}

impl AuditEventRepository<'_> {
    /// Appends an audit entry.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown outcome.
    pub async fn append(&mut self, input: &AppendAuditEvent) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO security_audit_log (id,user_id,action,outcome,request_metadata) VALUES ($1,$2,$3,$4,$5)").bind(input.id.as_uuid()).bind(input.user_id.map(UserId::as_uuid)).bind(&input.action).bind(&input.outcome).bind(&input.request_metadata))?;
        Ok(())
    }
}
