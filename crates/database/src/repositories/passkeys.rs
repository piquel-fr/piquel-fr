//! Passkey credentials and single-use `WebAuthn` ceremony persistence.

use super::{PasskeyRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{PasskeyId, SessionId, TokenId, UserId, protocol::api::Passkey};
use serde_json::Value;

piquel_common::str_enum! {
    /// SQL-compatible `WebAuthn` ceremony purpose.
    pub enum CeremonyKind {
        /// First passkey during account creation.
        Registration = "registration",
        /// Account sign-in.
        Authentication = "authentication",
        /// Additional passkey enrollment.
        Enrollment = "enrollment",
        /// Passkey confirmation of an existing session.
        PurposeAuthentication = "purpose_authentication",
    }
}

/// A new passkey credential.
#[derive(Clone, Debug)]
pub struct InsertPasskey {
    /// Row identifier.
    pub id: PasskeyId,
    /// `WebAuthn` credential ID; unique across all accounts.
    pub credential_id: Vec<u8>,
    /// Owning account.
    pub user_id: UserId,
    /// Serialized `WebAuthn` credential, including its public key and counter.
    pub credential: Value,
    /// User-chosen label.
    pub friendly_name: String,
}

/// A passkey credential row.
#[derive(Clone, Debug)]
pub struct StoredPasskey {
    /// Row identifier.
    pub id: PasskeyId,
    /// `WebAuthn` credential ID.
    pub credential_id: Vec<u8>,
    /// Owning account.
    pub user_id: UserId,
    /// Serialized `WebAuthn` credential.
    pub credential: Value,
    /// User-chosen label.
    pub friendly_name: String,
    /// When the credential was registered.
    pub created_at: DateTime<Utc>,
    /// When the credential last authenticated, if it has.
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the credential was revoked; `None` while it is usable.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<StoredPasskey> for Passkey {
    /// Shows the label only, never the credential.
    fn from(passkey: StoredPasskey) -> Self {
        Self {
            id: passkey.id,
            friendly_name: passkey.friendly_name,
        }
    }
}

/// Server-side state for a started `WebAuthn` ceremony. The state contains the
/// challenge and must never be logged.
#[derive(Clone, Debug)]
pub struct InsertCeremony {
    /// Ceremony identifier handed to the browser.
    pub id: TokenId,
    /// Account the ceremony acts for, when known in advance.
    pub user_id: Option<UserId>,
    /// Session the ceremony acts for, when started from one.
    pub session_id: Option<SessionId>,
    /// Ceremony purpose; consumption must name the same kind.
    pub kind: CeremonyKind,
    /// Digest stored alongside the state.
    pub challenge_digest: Vec<u8>,
    /// Serialized ceremony state.
    pub state: Value,
    /// When the ceremony stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// A ceremony taken by [`PasskeyRepository::consume_ceremony`].
#[derive(Clone, Debug)]
pub struct ConsumedCeremony {
    /// Account the ceremony was started for.
    pub user_id: Option<UserId>,
    /// Session the ceremony was started from.
    pub session_id: Option<SessionId>,
    /// Serialized ceremony state.
    pub state: Value,
}

impl PasskeyRepository<'_> {
    /// Stores a new credential.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the credential ID is already
    /// registered, or another [`DatabaseError`] if the query fails.
    pub async fn insert(&mut self, input: &InsertPasskey) -> Result<StoredPasskey, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredPasskey,
                r#"INSERT INTO passkey_credentials (
                    id, credential_id, user_id, credential, friendly_name
                ) VALUES ($1, $2, $3, $4, $5)
                RETURNING
                    id AS "id: PasskeyId", credential_id, user_id AS "user_id: UserId", credential,
                    friendly_name, created_at, last_used_at, revoked_at"#,
                input.id.as_uuid(),
                input.credential_id,
                input.user_id.as_uuid(),
                input.credential,
                input.friendly_name,
            )
        )
    }

    /// Lists the account's unrevoked credentials, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_active(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<StoredPasskey>, DatabaseError> {
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
                AND revoked_at IS NULL
                ORDER BY created_at"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Lists the unrevoked credentials of the account named `username`, oldest
    /// first, if it is active or scheduled for deletion: a passkey can restore the
    /// latter. A missing, disabled or passkey-less account returns none, in the
    /// same single query, so callers cannot tell those cases apart.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_active_by_username(
        &mut self,
        username: &str,
    ) -> Result<Vec<StoredPasskey>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredPasskey,
                r#"SELECT
                    p.id AS "id: PasskeyId", p.credential_id, p.user_id AS "user_id: UserId",
                    p.credential, p.friendly_name, p.created_at, p.last_used_at, p.revoked_at
                FROM passkey_credentials p
                JOIN users u ON u.id = p.user_id
                WHERE u.username = $1
                AND u.status IN ('active', 'deleting')
                AND p.revoked_at IS NULL
                ORDER BY p.created_at"#,
                username,
            )
        )
    }

    /// Finds an unrevoked credential and locks it until the transaction ends,
    /// so authentication rechecks it before updating.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_credential_id_for_update(
        &mut self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredPasskey,
                r#"SELECT
                    id AS "id: PasskeyId", credential_id, user_id AS "user_id: UserId", credential,
                    friendly_name, created_at, last_used_at, revoked_at
                FROM passkey_credentials
                WHERE credential_id = $1
                AND revoked_at IS NULL
                FOR UPDATE"#,
                credential_id,
            )
        )
    }

    /// Stores the credential's post-authentication state, e.g. its counter.
    /// Returns `false` if the credential is unknown or revoked.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn update_after_authentication(
        &mut self,
        credential_id: &[u8],
        credential: &Value,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE passkey_credentials
                SET credential = $1, last_used_at = now()
                WHERE credential_id = $2
                AND revoked_at IS NULL",
                credential,
                credential_id,
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Renames one of the account's unrevoked credentials. Returns `false` if
    /// no such credential exists.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn rename(
        &mut self,
        id: PasskeyId,
        user_id: UserId,
        name: &str,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE passkey_credentials
                SET friendly_name = $1
                WHERE id = $2
                AND user_id = $3
                AND revoked_at IS NULL",
                name,
                id.as_uuid(),
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Revokes a credential only while another active passkey remains.
    /// Returns `false` if it is the last one or does not exist.
    ///
    /// All of the user's credential rows are locked in one statement so two
    /// concurrent removals cannot both pass the last-factor check.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_if_not_last(
        &mut self,
        id: PasskeyId,
        user_id: UserId,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "WITH locked AS MATERIALIZED (
                    SELECT id, revoked_at
                    FROM passkey_credentials
                    WHERE user_id = $2
                    FOR UPDATE
                ),
                eligible AS (
                    SELECT 1
                    FROM locked
                    WHERE id = $1
                    AND revoked_at IS NULL
                    AND (SELECT count(*) FROM locked WHERE revoked_at IS NULL) > 1
                )
                UPDATE passkey_credentials
                SET revoked_at = now()
                FROM eligible
                WHERE passkey_credentials.id = $1
                AND passkey_credentials.user_id = $2
                AND passkey_credentials.revoked_at IS NULL",
                id.as_uuid(),
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Revokes one of the account's credentials unconditionally. Returns
    /// `false` if it was already revoked or does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke(&mut self, id: PasskeyId, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE passkey_credentials
                SET revoked_at = now()
                WHERE id = $1
                AND user_id = $2
                AND revoked_at IS NULL",
                id.as_uuid(),
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Stores the state of a started ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown kind.
    pub async fn insert_ceremony(&mut self, input: &InsertCeremony) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO webauthn_ceremonies (
                    id, user_id, session_id, ceremony_kind, challenge_digest, state, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                input.id.as_uuid(),
                input.user_id.map(UserId::as_uuid),
                input.session_id.map(SessionId::as_uuid),
                input.kind.as_str(),
                input.challenge_digest,
                input.state,
                input.expires_at,
            )
        )?;
        Ok(())
    }

    /// Marks an unexpired ceremony of `kind` consumed and returns its state.
    /// A ceremony is consumed at most once, even if its response is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if no unconsumed, unexpired
    /// ceremony matches, or another [`DatabaseError`] if the query fails.
    pub async fn consume_ceremony(
        &mut self,
        id: TokenId,
        kind: CeremonyKind,
    ) -> Result<ConsumedCeremony, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                ConsumedCeremony,
                r#"UPDATE webauthn_ceremonies
                SET consumed_at = now()
                WHERE id = $1
                AND ceremony_kind = $2
                AND consumed_at IS NULL
                AND expires_at > now()
                RETURNING
                    user_id AS "user_id: UserId", session_id AS "session_id: SessionId", state"#,
                id.as_uuid(),
                kind.as_str(),
            )
        )
    }
}

/// Username lookups against a running database.
#[cfg(test)]
mod tests {
    use super::{InsertPasskey, PasskeyRepository};
    use crate::Database;
    use piquel_common::{PasskeyId, UserId};

    /// A disabled account and an account whose only passkey is revoked list no
    /// credentials, like a username nobody holds.
    #[tokio::test]
    #[ignore = "requires a disposable TEST_DATABASE_URL"]
    async fn username_lookup_hides_disabled_accounts_and_revoked_passkeys() {
        let pool = Database::test_pool().await;
        let mut passkeys = PasskeyRepository::from_pool(&pool);
        for disable in [true, false] {
            let user = UserId::new();
            let username = format!("passkey_{user}");
            sqlx::query("INSERT INTO users(id,username,display_name) VALUES($1,$2,'Passkey test')")
                .bind(user.as_uuid())
                .bind(&username)
                .execute(&pool)
                .await
                .expect("user");
            let key = passkeys
                .insert(&InsertPasskey {
                    id: PasskeyId::new(),
                    credential_id: user.as_uuid().as_bytes().to_vec(),
                    user_id: user,
                    credential: serde_json::json!({}),
                    friendly_name: "Passkey test".into(),
                })
                .await
                .expect("passkey");
            let listed = || async {
                PasskeyRepository::from_pool(&pool)
                    .list_active_by_username(&username)
                    .await
                    .expect("lookup")
                    .len()
            };
            assert_eq!(listed().await, 1);
            if disable {
                sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
                    .bind(user.as_uuid())
                    .execute(&pool)
                    .await
                    .expect("disable");
            } else {
                assert!(passkeys.revoke(key.id, user).await.expect("revoke"));
            }
            assert_eq!(listed().await, 0, "disable: {disable}");
        }
    }
}
