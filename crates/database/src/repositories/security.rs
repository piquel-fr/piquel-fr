//! Single-use signup invitations and shared per-client request budgets.

use super::{RepositoryExecutor, SecurityRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use sourceorigin_common::{TokenId, admin::Invitation};

/// How [`SecurityRepository::open_invitation`] finds an invitation.
#[derive(Clone, Copy, Debug)]
pub enum InvitationKey<'a> {
    /// By its ID.
    Id(TokenId),
    /// By the SHA-256 digest of its link's token.
    Digest(&'a [u8]),
}
use std::time::Duration;

/// An invitation to store.
pub struct InsertInvitation<'a> {
    /// Its ID, which its link's token is derived from.
    pub id: TokenId,
    /// The 32-byte SHA-256 digest of its link's token.
    pub secret_digest: &'a [u8],
    /// When it stops being accepted.
    pub expires_at: DateTime<Utc>,
    /// The normalized address it is mailed to, if any.
    pub email: Option<&'a str>,
}

/// An invitation that can still be redeemed: unexpired, unrevoked and
/// unredeemed. Redeeming one returns it as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenInvitation {
    /// Its ID.
    pub id: TokenId,
    /// The normalized address it was mailed to, if any.
    pub email: Option<String>,
    /// SHA-256 of its link's token, which tells the key that derived it.
    pub secret_digest: Vec<u8>,
    /// When it stops being accepted.
    pub expires_at: DateTime<Utc>,
}

impl SecurityRepository<'_> {
    /// Stores `invitation`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for a digest of
    /// the wrong length or one that already exists.
    pub async fn create_invitation(
        &mut self,
        invitation: &InsertInvitation<'_>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO invitations(id,secret_digest,expires_at,email) VALUES($1,$2,$3,$4)",
                invitation.id.as_uuid(),
                invitation.secret_digest,
                invitation.expires_at,
                invitation.email,
            )
        )?;
        Ok(())
    }

    /// Lists every invitation not yet purged, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_invitations(&mut self) -> Result<Vec<Invitation>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                Invitation,
                r#"SELECT id AS "id: TokenId", email, created_at, expires_at, redeemed_at, revoked_at
                FROM invitations
                ORDER BY created_at DESC, id DESC"#
            )
        )
    }

    /// Revokes an unredeemed invitation. Returns `false` if it is unknown,
    /// redeemed or already revoked. It also expires now: releases before
    /// `revoked_at` check only the expiry, and cleanup then purges it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_invitation(&mut self, id: TokenId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE invitations
                SET revoked_at = now(), expires_at = LEAST(expires_at, now())
                WHERE id = $1
                AND redeemed_at IS NULL
                AND revoked_at IS NULL",
                id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// The open invitation whose link's token has the SHA-256 `digest`, as a
    /// signup presenting it finds it, or the one with the ID `id`, as the email
    /// sender and a resend find it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn open_invitation(
        &mut self,
        key: InvitationKey<'_>,
    ) -> Result<Option<OpenInvitation>, DatabaseError> {
        let (id, digest) = match key {
            InvitationKey::Id(id) => (Some(id.as_uuid()), None),
            InvitationKey::Digest(digest) => (None, Some(digest)),
        };
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                OpenInvitation,
                r#"SELECT id AS "id: TokenId", email, secret_digest, expires_at
                FROM invitations
                WHERE (id = $1 OR secret_digest = $2)
                AND redeemed_at IS NULL
                AND revoked_at IS NULL
                AND expires_at > now()"#,
                id,
                digest,
            )
        )
    }

    /// Redeems the open invitation whose link's token has the SHA-256 `digest`,
    /// and returns it. `None` if it is unknown, expired, revoked or already
    /// redeemed. Call it inside the account-creation transaction so a rollback
    /// keeps the invitation usable.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn redeem_invitation(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<OpenInvitation>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                OpenInvitation,
                r#"UPDATE invitations
                SET redeemed_at = clock_timestamp()
                WHERE secret_digest = $1
                AND redeemed_at IS NULL
                AND revoked_at IS NULL
                AND expires_at > clock_timestamp()
                RETURNING id AS "id: TokenId", email, secret_digest, expires_at"#,
                digest,
            )
        )
    }

    /// Counts a request in `bucket`'s fixed `window` and reports whether the
    /// window is still within `limit` requests. The counter is shared by all
    /// service processes. Each bucket must always use the same window.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn allow_request(
        &mut self,
        bucket: &[u8],
        limit: i32,
        window: Duration,
    ) -> Result<bool, DatabaseError> {
        let requests = run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "INSERT INTO request_limits (bucket, requests, expires_at)
                VALUES ($1, 1, now() + $2)
                ON CONFLICT (bucket) DO UPDATE
                SET requests = CASE
                        WHEN request_limits.expires_at <= now() THEN 1
                        ELSE request_limits.requests + 1
                    END,
                    expires_at = CASE
                        WHEN request_limits.expires_at <= now() THEN now() + $2
                        ELSE request_limits.expires_at
                    END
                RETURNING requests",
                bucket,
                window as _,
            )
        )?;
        Ok(requests <= limit)
    }
}
