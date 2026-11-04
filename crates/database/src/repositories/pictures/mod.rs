//! Profile pictures: one per account at most, stored as the JPEG auth encoded.
//! Setting or removing one bumps the account's profile version, in the same
//! statement, so relying parties refresh their `picture` claim.

use super::{PictureRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{PictureId, UserId};

/// An account's current picture, without its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredPicture {
    /// Names it in its URL.
    pub id: PictureId,
    /// When it was uploaded.
    pub created_at: DateTime<Utc>,
}

impl PictureRepository<'_> {
    /// Makes `image`, named `id`, the account's picture, replacing any other, and
    /// bumps the account's profile version. Returns the picture as stored. The
    /// caller holds the account's lock.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if `id` is taken, or another
    /// [`DatabaseError`] if the query fails, such as for an empty image, one over the
    /// column's 128 KiB, or an account that is gone.
    pub async fn set(
        &mut self,
        user_id: UserId,
        id: PictureId,
        image: &[u8],
    ) -> Result<StoredPicture, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredPicture,
                r#"WITH p AS (
                    INSERT INTO profile_pictures (user_id, id, image) VALUES ($1, $2, $3)
                    ON CONFLICT (user_id) DO UPDATE
                    SET id = EXCLUDED.id, image = EXCLUDED.image, created_at = now()
                    RETURNING user_id, id, created_at
                )
                UPDATE users u
                SET profile_version = u.profile_version + 1, updated_at = now()
                FROM p WHERE u.id = p.user_id
                RETURNING p.id AS "id: PictureId", p.created_at"#,
                user_id.as_uuid(),
                id.as_uuid(),
                image,
            )
        )
    }

    /// Removes the account's picture and bumps its profile version. Returns
    /// `false`, changing nothing, if it had none. The caller holds the account's
    /// lock.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn remove(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "WITH p AS (
                    DELETE FROM profile_pictures WHERE user_id = $1 RETURNING user_id
                )
                UPDATE users
                SET profile_version = profile_version + 1, updated_at = now()
                WHERE id IN (SELECT user_id FROM p)",
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// The account's current picture, if it has one, in any status.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find(&mut self, user_id: UserId) -> Result<Option<StoredPicture>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredPicture,
                r#"SELECT id AS "id: PictureId", created_at
                FROM profile_pictures WHERE user_id = $1"#,
                user_id.as_uuid(),
            )
        )
    }

    /// The bytes of the account's current picture, in any status: what its export
    /// carries.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn image_of(&mut self, user_id: UserId) -> Result<Option<Vec<u8>>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT image FROM profile_pictures WHERE user_id = $1",
                user_id.as_uuid(),
            )
        )
    }

    /// The bytes of the picture `id`, if it is still its account's and the account
    /// is active: what its URL serves. A replaced or removed picture, or one of a
    /// disabled account or one awaiting deletion, has none.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn image(&mut self, id: PictureId) -> Result<Option<Vec<u8>>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT p.image FROM profile_pictures p
                JOIN users u ON u.id = p.user_id AND u.status = 'active'
                WHERE p.id = $1",
                id.as_uuid(),
            )
        )
    }
}

#[cfg(test)]
mod tests;
