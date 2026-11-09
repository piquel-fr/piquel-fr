//! Administrator rights. Changes to the list serialize on [`AdministratorRepository::lock`].

use super::{AdministratorRepository, RepositoryExecutor};
use crate::DatabaseError;
use piquel_common::{Handle, PictureId, UserId, admin::Administrator};

/// Proof that the transaction took [`AdministratorRepository::lock`], which
/// [`AdministratorRepository::is_last_active`] needs to give an answer that holds
/// until commit. Only `lock` makes one; it proves nothing in another transaction.
#[derive(Debug)]
pub struct AdministratorsLocked(());

impl AdministratorRepository<'_> {
    /// Serializes changes to the administrator list until the transaction ends:
    /// grants, revocations, and disabling or deleting an account, wait for each
    /// other, so [`Self::is_last_active`] stays true until commit. Reads and
    /// [`Self::contains_for_share`] do not wait.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the lock cannot be taken.
    pub async fn lock(&mut self) -> Result<AdministratorsLocked, DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!("LOCK TABLE administrators IN SHARE ROW EXCLUSIVE MODE")
        )?;
        Ok(AdministratorsLocked(()))
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

    /// Reports whether `user_id` is the only active administrator, so revoking its
    /// rights, disabling it or deleting it would leave nobody to administer. Every
    /// such change asks first, under the lock `_locked` proves: two of them cannot
    /// both see the other's administrator still active.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn is_last_active(
        &mut self,
        _locked: &AdministratorsLocked,
        user_id: UserId,
    ) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                // True when every active administrator is `user_id`, and there is
                // one: `bool_and` of no rows is null.
                r#"SELECT COALESCE(bool_and(a.user_id = $1), FALSE) AS "last!"
                FROM administrators a
                JOIN users u ON u.id = a.user_id
                WHERE u.status = 'active'"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Every active administrator, whom an event about the service notifies.
    /// Their rights and accounts stay key-share locked until the transaction
    /// ends, so a purge of one waits for their notifications and emails to be
    /// written, then deletes them with the account. Locking the rights too
    /// holds back a purge that deletes emails before the account, as the
    /// previous release's does, until those emails are written.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn active(&mut self) -> Result<Vec<UserId>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                r#"SELECT a.user_id AS "user_id: UserId"
                FROM administrators a
                JOIN users u ON u.id = a.user_id AND u.status = 'active'
                ORDER BY a.user_id
                FOR KEY SHARE OF a, u"#
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
                r#"SELECT
                    a.user_id AS "user_id: UserId", h.handle AS "handle: Handle",
                    p.id AS "picture?: PictureId", a.granted_at
                FROM administrators a
                JOIN handles h ON h.user_id = a.user_id AND h.released_at IS NULL
                JOIN users u ON u.id = a.user_id
                LEFT JOIN profile_pictures p ON p.user_id = u.id AND u.status = 'active'
                ORDER BY a.granted_at, a.user_id"#
            )
        )
    }
}
