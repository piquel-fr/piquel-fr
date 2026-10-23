//! Signing keys, their lifecycle and the lock that serializes changes to them.

use super::{RepositoryExecutor, SigningKeyRepository};
use crate::{DatabaseError, LockKey};
use chrono::{DateTime, Utc};
use piquel_common::protocol::jwt::{Jwk, KeyId};
use sqlx::types::Json;

piquel_common::str_enum! {
    /// Where a signing key is in its lifecycle.
    pub enum SigningKeyState {
        /// Published ahead of use, so verifiers have it before it signs.
        Next = "next",
        /// Signs new tokens; one per key type.
        Active = "active",
        /// No longer signs, but stays published while its tokens may be valid.
        Retiring = "retiring",
        /// Unpublished, its private key erased; verifies only `id_token_hint`s.
        Retired = "retired",
    }
}

piquel_common::str_enum! {
    /// The family of a signing key, which fixes the algorithms it signs with.
    pub enum SigningKeyType {
        /// RSA, signing RS256.
        Rsa = "rsa",
    }
}

/// A stored signing key.
#[derive(Clone, Debug)]
pub struct StoredSigningKey {
    /// The key's `kid`.
    pub id: KeyId,
    /// Its family.
    pub key_type: SigningKeyType,
    /// Where it is in its lifecycle.
    pub state: SigningKeyState,
    /// Its public key, as JWKS publishes it.
    pub public_jwk: Jwk,
    /// Its sealed PKCS#8 private key; `None` once retired.
    pub sealed_private_key: Option<Vec<u8>>,
    /// When it was generated or imported.
    pub created_at: DateTime<Utc>,
    /// When it started signing.
    pub activated_at: Option<DateTime<Utc>>,
    /// When it stopped signing.
    pub deactivated_at: Option<DateTime<Utc>>,
    /// When it left the key set.
    pub retired_at: Option<DateTime<Utc>>,
}

/// A new signing key, published as `next` or signing at once as `active`.
#[derive(Clone, Debug)]
pub struct InsertSigningKey {
    /// The key's `kid`.
    pub id: KeyId,
    /// Its family.
    pub key_type: SigningKeyType,
    /// `next` or `active`; the table refuses other states for a new key.
    pub state: SigningKeyState,
    /// Its public key, as JWKS publishes it.
    pub public_jwk: Jwk,
    /// Its sealed PKCS#8 private key.
    pub sealed_private_key: Vec<u8>,
    /// When it is created, and activated if `active`.
    pub at: DateTime<Utc>,
}

impl SigningKeyRepository<'_> {
    /// Waits for the lock that serializes signing key changes, held until the
    /// transaction ends.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails, or this repository is not
    /// bound to a transaction, where the lock would end at once.
    pub async fn lock(&mut self) -> Result<(), DatabaseError> {
        Self::require_transaction(&self.executor)?;
        run!(
            self,
            execute,
            sqlx::query!(
                "SELECT pg_advisory_xact_lock($1)",
                LockKey::SigningKeys.id()
            )
        )?;
        Ok(())
    }

    /// Takes the lock of [`Self::lock`] if no other transaction holds it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails, or this repository is not
    /// bound to a transaction.
    pub async fn try_lock(&mut self) -> Result<bool, DatabaseError> {
        Self::require_transaction(&self.executor)?;
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT pg_try_advisory_xact_lock($1) AS "locked!""#,
                LockKey::SigningKeys.id()
            )
        )
    }

    /// Refuses to take a transaction-level lock outside a transaction.
    fn require_transaction(executor: &RepositoryExecutor<'_>) -> Result<(), DatabaseError> {
        match executor {
            RepositoryExecutor::Pool(_) => Err(DatabaseError::Operation(
                "the signing key lock requires a transaction".into(),
            )),
            RepositoryExecutor::Connection(_) => Ok(()),
        }
    }

    /// Lists every key, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list(&mut self) -> Result<Vec<StoredSigningKey>, DatabaseError> {
        let rows = run!(
            self,
            fetch_all,
            sqlx::query!(
                r#"SELECT
                    id AS "id: KeyId", key_type AS "key_type: SigningKeyType",
                    state AS "state: SigningKeyState", public_jwk AS "public_jwk: Json<Jwk>",
                    sealed_private_key, created_at, activated_at, deactivated_at, retired_at
                FROM signing_keys
                ORDER BY created_at, id"#
            )
        )?;
        Ok(rows
            .into_iter()
            .map(|row| StoredSigningKey {
                id: row.id,
                key_type: row.key_type,
                state: row.state,
                public_jwk: row.public_jwk.0,
                sealed_private_key: row.sealed_private_key,
                created_at: row.created_at,
                activated_at: row.activated_at,
                deactivated_at: row.deactivated_at,
                retired_at: row.retired_at,
            })
            .collect())
    }

    /// Stores a new key.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the ID is taken or the key type
    /// already has a key in that state, or another [`DatabaseError`].
    pub async fn insert(&mut self, key: &InsertSigningKey) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO signing_keys (
                    id, key_type, state, public_jwk, sealed_private_key, created_at, activated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6::timestamptz,
                    CASE WHEN $3::text = 'active' THEN $6::timestamptz END
                )",
                key.id.as_str(),
                key.key_type.as_str(),
                key.state.as_str(),
                Json(&key.public_jwk) as _,
                key.sealed_private_key,
                key.at,
            )
        )?;
        Ok(())
    }

    /// Starts signing with a `next` key. The key type's active key must have
    /// stopped first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if `id` is no `next` key, or another
    /// [`DatabaseError`].
    pub async fn activate(&mut self, id: &KeyId, at: DateTime<Utc>) -> Result<(), DatabaseError> {
        Self::found(
            run!(
                self,
                execute,
                sqlx::query!(
                    "UPDATE signing_keys SET state = 'active', activated_at = $2
                    WHERE id = $1 AND state = 'next'",
                    id.as_str(),
                    at,
                )
            )?
            .rows_affected(),
        )
    }

    /// Stops signing with an `active` key; it stays published as `retiring`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if `id` is no `active` key, or another
    /// [`DatabaseError`].
    pub async fn deactivate(&mut self, id: &KeyId, at: DateTime<Utc>) -> Result<(), DatabaseError> {
        Self::found(
            run!(
                self,
                execute,
                sqlx::query!(
                    "UPDATE signing_keys SET state = 'retiring', deactivated_at = $2
                    WHERE id = $1 AND state = 'active'",
                    id.as_str(),
                    at,
                )
            )?
            .rows_affected(),
        )
    }

    /// Unpublishes a `retiring` key and erases its private key.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if `id` is no `retiring` key, or
    /// another [`DatabaseError`].
    pub async fn retire(&mut self, id: &KeyId, at: DateTime<Utc>) -> Result<(), DatabaseError> {
        Self::found(
            run!(
                self,
                execute,
                sqlx::query!(
                    "UPDATE signing_keys
                    SET state = 'retired', retired_at = $2, sealed_private_key = NULL
                    WHERE id = $1 AND state = 'retiring'",
                    id.as_str(),
                    at,
                )
            )?
            .rows_affected(),
        )
    }

    /// Deletes a key in any state.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if no key has this ID, or another
    /// [`DatabaseError`].
    pub async fn delete(&mut self, id: &KeyId) -> Result<(), DatabaseError> {
        Self::found(
            run!(
                self,
                execute,
                sqlx::query!("DELETE FROM signing_keys WHERE id = $1", id.as_str())
            )?
            .rows_affected(),
        )
    }

    /// Reports a change that matched no key as [`DatabaseError::NotFound`].
    const fn found(rows: u64) -> Result<(), DatabaseError> {
        if rows == 1 {
            Ok(())
        } else {
            Err(DatabaseError::NotFound)
        }
    }
}

/// Lifecycle constraints and lock exclusion.
#[cfg(test)]
mod tests;
