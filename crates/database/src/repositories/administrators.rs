//! Administrator rights, granted and revoked only by the `auth-service` CLI.

use super::{AdministratorRepository, RepositoryExecutor};
use crate::{Actor, DatabaseError};
use chrono::{DateTime, Utc};
use piquel_auth_protocol::UserId;
use serde::Serialize;
use sqlx::types::Json;

/// An administrator account and who granted it.
#[derive(Clone, Debug, Serialize)]
pub struct StoredAdministrator {
    /// The administrator's account.
    pub user_id: UserId,
    /// The account's login name.
    pub username: String,
    /// When the rights were granted.
    pub granted_at: DateTime<Utc>,
    /// The operator who granted them.
    pub granted_by: Actor,
}

impl AdministratorRepository<'_> {
    /// Makes the account an administrator. Returns `false` if it already is one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown account.
    pub async fn grant(
        &mut self,
        user_id: UserId,
        granted_by: &Actor,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO administrators (user_id, granted_by)
                VALUES ($1, $2)
                ON CONFLICT (user_id) DO NOTHING",
                user_id.as_uuid(),
                Json(granted_by) as _,
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Removes the account's administrator rights. Returns `false` if it had none.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "DELETE FROM administrators WHERE user_id = $1",
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Reports whether the account is an administrator.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn contains(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT EXISTS (
                    SELECT FROM administrators WHERE user_id = $1
                ) AS "administrator!""#,
                user_id.as_uuid(),
            )
        )
    }

    /// Reports whether the account is an administrator and, if so, keeps its rights
    /// share-locked until the transaction ends, so revocation waits for it to commit.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn contains_for_share(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT user_id FROM administrators WHERE user_id = $1 FOR SHARE",
                user_id.as_uuid(),
            )
        )?
        .is_some())
    }

    /// Lists every administrator, oldest grant first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list(&mut self) -> Result<Vec<StoredAdministrator>, DatabaseError> {
        Ok(run!(
            self,
            fetch_all,
            sqlx::query!(
                r#"SELECT
                    a.user_id AS "user_id: UserId", u.username, a.granted_at,
                    a.granted_by AS "granted_by: Json<Actor>"
                FROM administrators a
                JOIN users u ON u.id = a.user_id
                ORDER BY a.granted_at, a.user_id"#
            )
        )?
        .into_iter()
        .map(|row| StoredAdministrator {
            user_id: row.user_id,
            username: row.username,
            granted_at: row.granted_at,
            granted_by: row.granted_by.0,
        })
        .collect())
    }
}
