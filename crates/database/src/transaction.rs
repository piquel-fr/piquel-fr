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
        UserRepository::from_connection(&mut self.inner)
    }
    pub fn emails(&mut self) -> EmailRepository<'_> {
        EmailRepository::from_connection(&mut self.inner)
    }
    pub fn sessions(&mut self) -> SessionRepository<'_> {
        SessionRepository::from_connection(&mut self.inner)
    }
    pub fn audit_events(&mut self) -> AuditEventRepository<'_> {
        AuditEventRepository::from_connection(&mut self.inner)
    }
    pub fn passkeys(&mut self) -> PasskeyRepository<'_> {
        PasskeyRepository::from_connection(&mut self.inner)
    }
    pub fn oidc(&mut self) -> OidcRepository<'_> {
        OidcRepository::from_connection(&mut self.inner)
    }
    pub fn tokens(&mut self) -> TokenRepository<'_> {
        TokenRepository::from_connection(&mut self.inner)
    }
    pub fn federation(&mut self) -> FederationRepository<'_> {
        FederationRepository::from_connection(&mut self.inner)
    }
    pub fn security(&mut self) -> SecurityRepository<'_> {
        SecurityRepository::from_connection(&mut self.inner)
    }
    pub async fn commit(self) -> Result<(), DatabaseError> {
        self.inner.commit().await.map_err(Into::into)
    }
    pub async fn rollback(self) -> Result<(), DatabaseError> {
        self.inner.rollback().await.map_err(Into::into)
    }
}
