//! Browser-bound provider transactions, pending signups and identity links.

use super::{FederationRepository, RepositoryExecutor, StoredRow};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{Provider, SessionId, TokenId, UserId};
use sqlx::postgres::PgRow;

/// An in-flight redirect to a social login provider, bound to the initiating
/// browser.
#[derive(Clone, Debug)]
pub struct InsertFederationTransaction {
    /// Transaction identifier.
    pub id: TokenId,
    /// External authentication provider.
    pub provider: Provider,
    /// 32-byte digest of the OAuth `state` parameter.
    pub state_digest: Vec<u8>,
    /// 32-byte digest of the initiating browser's secret.
    pub browser_digest: Vec<u8>,
    /// OIDC nonce expected in the provider's ID token.
    pub nonce: String,
    /// PKCE code verifier for the provider's token request.
    pub pkce_verifier: String,
    /// Validated address the browser returns to afterwards.
    pub return_to: String,
    /// Account to link the identity to; set together with `link_session_id`.
    pub link_user_id: Option<UserId>,
    /// Session that started the link; set together with `link_user_id`.
    pub link_session_id: Option<SessionId>,
    /// When the provider callback stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// A transaction taken by [`FederationRepository::consume_transaction`].
#[derive(Clone, Debug)]
pub struct ConsumedFederationTransaction {
    /// OIDC nonce expected in the provider's ID token.
    pub nonce: String,
    /// PKCE code verifier for the provider's token request.
    pub pkce_verifier: String,
    /// Validated address the browser returns to afterwards.
    pub return_to: String,
    /// Account to link the identity to, for link flows.
    pub link_user_id: Option<UserId>,
    /// Session that started the link, for link flows.
    pub link_session_id: Option<SessionId>,
}

/// A new link between an account and a provider subject.
#[derive(Clone, Debug)]
pub struct InsertExternalIdentity {
    /// Link identifier.
    pub id: TokenId,
    /// Linked account.
    pub user_id: UserId,
    /// External authentication provider.
    pub provider: Provider,
    /// Provider issuer identifier.
    pub issuer: String,
    /// Provider subject; 1 to 255 characters.
    pub subject: String,
    /// Email the provider reported when linking, if any.
    pub linked_email: Option<String>,
}

/// An active link between an account and a provider subject. Each subject and
/// each provider per account has at most one active link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredExternalIdentity {
    /// Link identifier.
    pub id: TokenId,
    /// Linked account.
    pub user_id: UserId,
    /// Provider name.
    pub provider: Provider,
    /// Provider issuer identifier.
    pub issuer: String,
    /// Provider subject.
    pub subject: String,
    /// Email the provider reported when linking, if any.
    pub linked_email: Option<String>,
}

impl StoredExternalIdentity {
    /// Decodes a stored row, retaining the column name and cause for invalid data.
    fn from_row(row: &PgRow) -> Result<Self, DatabaseError> {
        Ok(Self {
            id: row.id("id")?,
            user_id: row.id("user_id")?,
            provider: row.vocabulary("provider_name")?,
            issuer: row.column("issuer")?,
            subject: row.column("subject")?,
            linked_email: row.column("linked_email")?,
        })
    }
}

/// Verified provider evidence, usable only by its initiating browser until
/// expiry. No account or session exists for a pending signup until the
/// browser finishes its first passkey.
#[derive(Clone, Debug)]
pub struct PendingFederation {
    /// Pending record identifier.
    pub id: TokenId,
    /// 32-byte digest of the initiating browser's secret; unique.
    pub browser_digest: Vec<u8>,
    /// External authentication provider.
    pub provider: Provider,
    /// Provider issuer identifier.
    pub issuer: String,
    /// Provider subject; 1 to 255 characters.
    pub subject: String,
    /// Email the provider reported, if any.
    pub email: Option<String>,
    /// Display name suggested by the provider.
    pub display_name: String,
    /// Validated address the browser returns to afterwards.
    pub return_to: String,
    /// Account to link the identity to, for link flows.
    pub link_user_id: Option<UserId>,
    /// Session that started the link; requires `link_user_id`.
    pub link_session_id: Option<SessionId>,
    /// When the evidence stops being accepted.
    pub expires_at: DateTime<Utc>,
}

impl PendingFederation {
    /// Decodes a stored row, retaining the column name and cause for invalid data.
    fn from_row(row: &PgRow) -> Result<Self, DatabaseError> {
        Ok(Self {
            id: row.id("id")?,
            browser_digest: row.column("browser_digest")?,
            provider: row.vocabulary("provider_name")?,
            issuer: row.column("issuer")?,
            subject: row.column("subject")?,
            email: row.column("email")?,
            display_name: row.column("display_name")?,
            return_to: row.column("return_to")?,
            link_user_id: row.id("link_user_id")?,
            link_session_id: row.id("link_session_id")?,
            expires_at: row.column("expires_at")?,
        })
    }
}

impl FederationRepository<'_> {
    /// Stores a provider redirect transaction.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for a reused state
    /// digest or a link user without a link session.
    pub async fn insert_transaction(
        &mut self,
        input: &InsertFederationTransaction,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query(
                "INSERT INTO federation_transactions (
                    id, provider_name, state_digest, browser_digest, nonce,
                    pkce_verifier, return_to, expires_at, link_user_id, link_session_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
            )
            .bind(input.id.as_uuid())
            .bind(input.provider.as_str())
            .bind(&input.state_digest)
            .bind(&input.browser_digest)
            .bind(&input.nonce)
            .bind(&input.pkce_verifier)
            .bind(&input.return_to)
            .bind(input.expires_at)
            .bind(input.link_user_id.map(UserId::as_uuid))
            .bind(input.link_session_id.map(SessionId::as_uuid))
        )?;
        Ok(())
    }

    /// Consumes the unexpired transaction matching the provider callback and
    /// the browser that started it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if none matches, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn consume_transaction(
        &mut self,
        provider: Provider,
        state_digest: &[u8],
        browser_digest: &[u8],
    ) -> Result<ConsumedFederationTransaction, DatabaseError> {
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "UPDATE federation_transactions
                SET consumed_at = now()
                WHERE provider_name = $1
                AND state_digest = $2
                AND browser_digest = $3
                AND consumed_at IS NULL
                AND expires_at > now()
                RETURNING nonce, pkce_verifier, return_to, link_user_id, link_session_id"
            )
            .bind(provider.as_str())
            .bind(state_digest)
            .bind(browser_digest)
        )?;
        Ok(ConsumedFederationTransaction {
            nonce: row.column("nonce")?,
            pkce_verifier: row.column("pkce_verifier")?,
            return_to: row.column("return_to")?,
            link_user_id: row.id("link_user_id")?,
            link_session_id: row.id("link_session_id")?,
        })
    }

    /// Finds the active link for a provider subject.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active(
        &mut self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<StoredExternalIdentity>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query(
                "SELECT id, user_id, provider_name, issuer, subject, linked_email
                FROM external_login_identities
                WHERE issuer = $1
                AND subject = $2
                AND revoked_at IS NULL"
            )
            .bind(issuer)
            .bind(subject)
        )?
        .as_ref()
        .map(StoredExternalIdentity::from_row)
        .transpose()
    }

    /// Links a provider subject to an account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the subject is already linked or
    /// the account already links this provider, or another [`DatabaseError`]
    /// if the query fails.
    pub async fn insert_identity(
        &mut self,
        input: &InsertExternalIdentity,
    ) -> Result<StoredExternalIdentity, DatabaseError> {
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "INSERT INTO external_login_identities (
                    id, user_id, provider_name, issuer, subject, linked_email
                ) VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, user_id, provider_name, issuer, subject, linked_email"
            )
            .bind(input.id.as_uuid())
            .bind(input.user_id.as_uuid())
            .bind(input.provider.as_str())
            .bind(&input.issuer)
            .bind(&input.subject)
            .bind(&input.linked_email)
        )?;
        StoredExternalIdentity::from_row(&row)
    }

    /// Records a login through an active link.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn record_login(&mut self, id: TokenId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query(
                "UPDATE external_login_identities
                SET last_login_at = now()
                WHERE id = $1
                AND revoked_at IS NULL"
            )
            .bind(id.as_uuid())
        )?;
        Ok(())
    }

    /// Lists the account's active links, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_active(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<StoredExternalIdentity>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query(
                "SELECT id, user_id, provider_name, issuer, subject, linked_email
                FROM external_login_identities
                WHERE user_id = $1
                AND revoked_at IS NULL
                ORDER BY linked_at"
            )
            .bind(user_id.as_uuid())
        )?
        .iter()
        .map(StoredExternalIdentity::from_row)
        .collect()
    }

    /// Revokes the account's active link for a provider, releasing its
    /// subject. Returns `false` if there was none.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn unlink(
        &mut self,
        user_id: UserId,
        provider: Provider,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query(
                "UPDATE external_login_identities
                SET revoked_at = now()
                WHERE user_id = $1
                AND provider_name = $2
                AND revoked_at IS NULL"
            )
            .bind(user_id.as_uuid())
            .bind(provider.as_str())
        )?
        .rows_affected()
            == 1)
    }

    /// Stores verified provider evidence for a pending signup or link.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. when the browser
    /// already has a pending record.
    pub async fn insert_pending(&mut self, input: &PendingFederation) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query(
                "INSERT INTO pending_federation (
                    id, browser_digest, provider_name, issuer, subject, email,
                    display_name, return_to, link_user_id, link_session_id, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
            )
            .bind(input.id.as_uuid())
            .bind(&input.browser_digest)
            .bind(input.provider.as_str())
            .bind(&input.issuer)
            .bind(&input.subject)
            .bind(&input.email)
            .bind(&input.display_name)
            .bind(&input.return_to)
            .bind(input.link_user_id.map(UserId::as_uuid))
            .bind(input.link_session_id.map(SessionId::as_uuid))
            .bind(input.expires_at)
        )?;
        Ok(())
    }

    /// Finds the browser's unconsumed, unexpired pending record.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn pending(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<PendingFederation>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query(
                "SELECT *
                FROM pending_federation
                WHERE browser_digest = $1
                AND consumed_at IS NULL
                AND expires_at > now()"
            )
            .bind(digest)
        )?
        .as_ref()
        .map(PendingFederation::from_row)
        .transpose()
    }

    /// Consumes the browser's pending record. Run it in the transaction that
    /// commits the resulting identity and account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if no unconsumed, unexpired record
    /// matches, or another [`DatabaseError`] if the query fails.
    pub async fn consume_pending(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<PendingFederation, DatabaseError> {
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "UPDATE pending_federation
                SET consumed_at = now()
                WHERE id = $1
                AND browser_digest = $2
                AND consumed_at IS NULL
                AND expires_at > now()
                RETURNING *"
            )
            .bind(id.as_uuid())
            .bind(digest)
        )?;
        PendingFederation::from_row(&row)
    }

    /// Abandons the browser's pending record, if any.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn cancel_pending(&mut self, digest: &[u8]) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query(
                "UPDATE pending_federation
                SET consumed_at = now()
                WHERE browser_digest = $1
                AND consumed_at IS NULL"
            )
            .bind(digest)
        )?;
        Ok(())
    }

    /// Adds `email` as the verified primary address of an account that has
    /// none. Does nothing if the account already has a verified address or
    /// another active account owns `email`: a provider observation never
    /// replaces the first local address or takes another account's address.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn set_first_email(
        &mut self,
        user_id: UserId,
        email: &str,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query(
                "INSERT INTO user_emails (id, user_id, normalized_email, verified_at, is_primary)
                SELECT $1, $2, $3, now(), true
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM user_emails
                    WHERE user_id = $2
                    AND verified_at IS NOT NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM active_verified_email_ownership
                    WHERE normalized_email = $3
                    AND user_id <> $2
                )"
            )
            .bind(TokenId::new().as_uuid())
            .bind(user_id.as_uuid())
            .bind(email)
        )?;
        Ok(())
    }
}
