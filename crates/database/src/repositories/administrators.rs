//! Administrator rights. Changes to the list serialize on [`AdministratorRepository::lock`].

use super::{AdministratorRepository, RepositoryExecutor};
use crate::DatabaseError;
use piquel_common::{Handle, UserId, admin::Administrator};

impl AdministratorRepository<'_> {
    /// Serializes changes to the administrator list until the transaction ends:
    /// grants and revocations wait for each other, so a count read after this lock
    /// stays true until commit. Reads and [`Self::contains_for_share`] do not wait.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the lock cannot be taken.
    pub async fn lock(&mut self) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!("LOCK TABLE administrators IN SHARE ROW EXCLUSIVE MODE")
        )?;
        Ok(())
    }

    /// Makes the account an administrator. Returns `false` if it already is one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown account.
    pub async fn grant(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO administrators (user_id) VALUES ($1) ON CONFLICT DO NOTHING",
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Removes the account's administrator rights. Returns `false` if it had none.
    /// Waits for transactions that hold the rights with [`Self::contains_for_share`].
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

    /// Reports whether the account is an administrator and, if so, share-locks its
    /// rights until the transaction ends, so revoking them waits for it to commit.
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

    /// Reports whether an active account other than `user_id` is an administrator,
    /// so removing `user_id` would still leave someone to administer.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn others_active(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT EXISTS (
                    SELECT FROM administrators a
                    JOIN users u ON u.id = a.user_id
                    WHERE a.user_id <> $1
                    AND u.status = 'active'
                ) AS "others!""#,
                user_id.as_uuid(),
            )
        )
    }

    /// Lists every administrator, oldest grant first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list(&mut self) -> Result<Vec<Administrator>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                Administrator,
                r#"SELECT a.user_id AS "user_id: UserId", h.handle AS "handle: Handle", a.granted_at
                FROM administrators a
                JOIN handles h ON h.user_id = a.user_id AND h.released_at IS NULL
                ORDER BY a.granted_at, a.user_id"#
            )
        )
    }
}
