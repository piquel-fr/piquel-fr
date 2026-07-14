use crate::{DatabaseError, repositories::*};
use sqlx::{Postgres, Transaction};

/// A private-SQLx transaction with the same typed repository families as `Database`.
pub struct DatabaseTransaction<'a> {
    inner: Transaction<'a, Postgres>,
}
impl<'a> DatabaseTransaction<'a> {
    pub(crate) const fn new(inner: Transaction<'a, Postgres>) -> Self {
        Self { inner }
    }
    pub fn users(&mut self) -> UserRepository<'_> {
        UserRepository::new()
    }
    pub fn emails(&mut self) -> EmailRepository<'_> {
        EmailRepository::new()
    }
    pub fn sessions(&mut self) -> SessionRepository<'_> {
        SessionRepository::new()
    }
    pub fn audit_events(&mut self) -> AuditEventRepository<'_> {
        AuditEventRepository::new()
    }
    pub fn internal_events(&mut self) -> InternalEventRepository<'_> {
        InternalEventRepository::new()
    }
    pub fn passkeys(&mut self) -> PasskeyRepository<'_> {
        PasskeyRepository::new()
    }
    pub fn oidc(&mut self) -> OidcRepository<'_> {
        OidcRepository::new()
    }
    pub fn tokens(&mut self) -> TokenRepository<'_> {
        TokenRepository::new()
    }
    pub fn federation(&mut self) -> FederationRepository<'_> {
        FederationRepository::new()
    }
    pub fn service_identities(&mut self) -> ServiceIdentityRepository<'_> {
        ServiceIdentityRepository::new()
    }
    pub async fn commit(self) -> Result<(), DatabaseError> {
        self.inner.commit().await.map_err(crate::error::map_error)
    }
    pub async fn rollback(self) -> Result<(), DatabaseError> {
        self.inner.rollback().await.map_err(crate::error::map_error)
    }
}
