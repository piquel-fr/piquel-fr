use super::*;
use crate::PendingFederation;

impl FederationRepository<'_> {
    pub async fn insert_transaction(
        &mut self,
        input: &InsertFederationTransaction,
    ) -> Result<(), DatabaseError> {
        execute!(self,sqlx::query("INSERT INTO federation_transactions(id,provider_name,state_digest,browser_digest,nonce,pkce_verifier,return_to,expires_at,link_user_id,link_session_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(input.id.as_uuid()).bind(&input.provider).bind(&input.state_digest).bind(&input.browser_digest).bind(&input.nonce).bind(&input.pkce_verifier).bind(&input.return_to).bind(input.expires_at).bind(input.link_user_id.map(UserId::as_uuid)).bind(input.link_session_id.map(SessionId::as_uuid)))?;
        Ok(())
    }
    pub async fn consume_transaction(
        &mut self,
        provider: &str,
        state_digest: &[u8],
        browser_digest: &[u8],
    ) -> Result<ConsumedFederationTransaction, DatabaseError> {
        let row=fetch_optional!(self,sqlx::query("UPDATE federation_transactions SET consumed_at=now() WHERE provider_name=$1 AND state_digest=$2 AND browser_digest=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING nonce,pkce_verifier,return_to,link_user_id,link_session_id").bind(provider).bind(state_digest).bind(browser_digest))?.ok_or(DatabaseError::NotFound)?;
        Ok(ConsumedFederationTransaction {
            link_user_id: row
                .try_get::<Option<uuid::Uuid>, _>("link_user_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?
                .map(UserId::from_uuid)
                .transpose()
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            link_session_id: row
                .try_get::<Option<uuid::Uuid>, _>("link_session_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?
                .map(SessionId::from_uuid)
                .transpose()
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            nonce: row
                .try_get("nonce")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            pkce_verifier: row
                .try_get("pkce_verifier")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
            return_to: row
                .try_get("return_to")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        })
    }
    pub async fn find_active(
        &mut self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<StoredExternalIdentity>, DatabaseError> {
        fetch_optional!(self,sqlx::query("SELECT id,user_id,provider_name,issuer,subject,linked_email FROM external_login_identities WHERE issuer=$1 AND subject=$2 AND revoked_at IS NULL").bind(issuer).bind(subject))?.map(|row|stored_external_identity(&row)).transpose()
    }
    pub async fn insert_identity(
        &mut self,
        input: &InsertExternalIdentity,
    ) -> Result<StoredExternalIdentity, DatabaseError> {
        let row=fetch_one!(self,sqlx::query("INSERT INTO external_login_identities(id,user_id,provider_name,issuer,subject,linked_email) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,user_id,provider_name,issuer,subject,linked_email").bind(input.id.as_uuid()).bind(input.user_id.as_uuid()).bind(&input.provider).bind(&input.issuer).bind(&input.subject).bind(&input.linked_email))?;
        stored_external_identity(&row)
    }
    pub async fn record_login(&mut self, id: TokenId) -> Result<(), DatabaseError> {
        execute!(self,sqlx::query("UPDATE external_login_identities SET last_login_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(id.as_uuid()))?;
        Ok(())
    }
    pub async fn list_active(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<StoredExternalIdentity>, DatabaseError> {
        let rows=match &mut self.executor{RepositoryExecutor::Pool(pool)=>sqlx::query("SELECT id,user_id,provider_name,issuer,subject,linked_email FROM external_login_identities WHERE user_id=$1 AND revoked_at IS NULL ORDER BY linked_at").bind(user_id.as_uuid()).fetch_all(*pool).await,RepositoryExecutor::Connection(connection)=>sqlx::query("SELECT id,user_id,provider_name,issuer,subject,linked_email FROM external_login_identities WHERE user_id=$1 AND revoked_at IS NULL ORDER BY linked_at").bind(user_id.as_uuid()).fetch_all(&mut **connection).await}.map_err(Into::<DatabaseError>::into)?;
        rows.iter().map(stored_external_identity).collect()
    }
}
fn stored_external_identity(
    row: &sqlx::postgres::PgRow,
) -> Result<StoredExternalIdentity, DatabaseError> {
    Ok(StoredExternalIdentity {
        id: TokenId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        user_id: UserId::from_uuid(
            row.try_get("user_id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        provider: row
            .try_get("provider_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        issuer: row
            .try_get("issuer")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        subject: row
            .try_get("subject")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        linked_email: row
            .try_get("linked_email")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}

impl FederationRepository<'_> {
    pub async fn insert_pending(&mut self, input: &PendingFederation) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO pending_federation(id,browser_digest,provider_name,issuer,subject,email,display_name,return_to,link_user_id,link_session_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(input.id.as_uuid()).bind(&input.browser_digest).bind(&input.provider).bind(&input.issuer).bind(&input.subject).bind(&input.email).bind(&input.display_name).bind(&input.return_to).bind(input.link_user_id.map(UserId::as_uuid)).bind(input.link_session_id.map(SessionId::as_uuid)).bind(input.expires_at))?;
        Ok(())
    }
    pub async fn pending(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<PendingFederation>, DatabaseError> {
        fetch_optional!(self, sqlx::query("SELECT * FROM pending_federation WHERE browser_digest=$1 AND consumed_at IS NULL AND expires_at>now()").bind(digest))?.map(|row| stored_pending(&row)).transpose()
    }
    /// Consumption participates in the caller's identity/account transaction.
    pub async fn consume_pending(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<PendingFederation, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("UPDATE pending_federation SET consumed_at=now() WHERE id=$1 AND browser_digest=$2 AND consumed_at IS NULL AND expires_at>now() RETURNING *").bind(id.as_uuid()).bind(digest))?.ok_or(DatabaseError::NotFound)?;
        stored_pending(&row)
    }
    pub async fn cancel_pending(&mut self, digest: &[u8]) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("UPDATE pending_federation SET consumed_at=now() WHERE browser_digest=$1 AND consumed_at IS NULL").bind(digest))?;
        Ok(())
    }
    pub async fn unlink(&mut self, user_id: UserId, provider: &str) -> Result<bool, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE external_login_identities SET revoked_at=now() WHERE user_id=$1 AND provider_name=$2 AND revoked_at IS NULL").bind(user_id.as_uuid()).bind(provider))?.rows_affected()==1)
    }
    /// Preserve the first verified local email forever; never import conflicting
    /// provider observations into another account's email ownership.
    pub async fn set_first_email(
        &mut self,
        user_id: UserId,
        email: &str,
    ) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO user_emails(id,user_id,normalized_email,verified_at,is_primary) SELECT $1,$2,$3,now(),true WHERE NOT EXISTS(SELECT 1 FROM user_emails WHERE user_id=$2 AND verified_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM active_verified_email_ownership WHERE normalized_email=$3 AND user_id<>$2)").bind(TokenId::new().as_uuid()).bind(user_id.as_uuid()).bind(email))?;
        Ok(())
    }
}
fn stored_pending(row: &sqlx::postgres::PgRow) -> Result<PendingFederation, DatabaseError> {
    Ok(PendingFederation {
        id: TokenId::from_uuid(
            row.try_get("id")
                .map_err(|_| DatabaseError::InvalidStoredData)?,
        )
        .map_err(|_| DatabaseError::InvalidStoredData)?,
        browser_digest: row
            .try_get("browser_digest")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        provider: row
            .try_get("provider_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        issuer: row
            .try_get("issuer")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        subject: row
            .try_get("subject")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        email: row
            .try_get("email")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        return_to: row
            .try_get("return_to")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        link_user_id: row
            .try_get::<Option<uuid::Uuid>, _>("link_user_id")
            .map_err(|_| DatabaseError::InvalidStoredData)?
            .map(UserId::from_uuid)
            .transpose()
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        link_session_id: row
            .try_get::<Option<uuid::Uuid>, _>("link_session_id")
            .map_err(|_| DatabaseError::InvalidStoredData)?
            .map(SessionId::from_uuid)
            .transpose()
            .map_err(|_| DatabaseError::InvalidStoredData)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| DatabaseError::InvalidStoredData)?,
    })
}
