//! Account recoveries and their links. Every change to an account's recoveries
//! happens under that account's lock, so they serialize without row locks.

use super::{RecoveryRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Duration, Utc};
use piquel_common::{PasskeyId, RecoveryId, UserId};

/// A new recovery, whose link works until `expires_at`.
pub struct InsertRecovery<'a> {
    /// Recovery identifier, which the link's token is derived from.
    pub id: RecoveryId,
    /// The account recovered.
    pub user_id: UserId,
    /// SHA-256 of the link's token.
    pub secret_digest: &'a [u8],
    /// When the link stops working.
    pub expires_at: DateTime<Utc>,
}

/// A recovery as stored, with the database's clock when it was read, which its
/// [`state`](Self::state) is computed against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecovery {
    /// Recovery identifier.
    pub id: RecoveryId,
    /// The account recovered.
    pub user_id: UserId,
    /// When it started.
    pub started_at: DateTime<Utc>,
    /// When its link stops working, if it is not used first.
    pub expires_at: DateTime<Utc>,
    /// When its link enrolled a passkey, if it did.
    pub completed_at: Option<DateTime<Utc>>,
    /// The passkey its link enrolled, if it did.
    pub passkey_id: Option<PasskeyId>,
    /// When its probation ends, once its link was used.
    pub settles_at: Option<DateTime<Utc>>,
    /// When it was cancelled before its link was used.
    pub cancelled_at: Option<DateTime<Utc>>,
    /// When it was undone after its link was used.
    pub undone_at: Option<DateTime<Utc>>,
    /// The database's clock when the row was read.
    pub read_at: DateTime<Utc>,
}

/// Where a recovery stands. [`StoredRecovery::state`] is the only place auth
/// computes it; the migration's `undoable_recovery` is the one SQL copy, which
/// the database's backstops use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryState {
    /// Its link works: not used, cancelled or undone, and not expired.
    Open,
    /// Its link was used and its probation has not ended: its passkey signs in
    /// but never confirms a session, and a passkey from before it can undo it.
    Probation {
        /// When the probation ends.
        settles_at: DateTime<Utc>,
    },
    /// Its probation ended: its passkey is an ordinary passkey.
    Settled,
    /// It expired unused, or was cancelled or undone.
    Ended,
}

impl RecoveryState {
    /// Whether the recovery can still be undone: its link works, or it is in
    /// probation.
    #[must_use]
    pub const fn undoable(self) -> bool {
        matches!(self, Self::Open | Self::Probation { .. })
    }
}

impl StoredRecovery {
    /// Where the recovery stood when it was read.
    #[must_use]
    pub fn state(&self) -> RecoveryState {
        if self.cancelled_at.is_some() || self.undone_at.is_some() {
            return RecoveryState::Ended;
        }
        match self.settles_at {
            Some(settles_at) if settles_at > self.read_at => {
                RecoveryState::Probation { settles_at }
            }
            Some(_) => RecoveryState::Settled,
            None if self.expires_at > self.read_at => RecoveryState::Open,
            None => RecoveryState::Ended,
        }
    }
}

/// A recent recovery of an account, as support reviews it before starting
/// another: where it stands, and the passkey its link enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentRecovery {
    /// The recovery.
    pub id: RecoveryId,
    /// When it started.
    pub started_at: DateTime<Utc>,
    /// When its link stops, or stopped, working unused.
    pub expires_at: DateTime<Utc>,
    /// When its link enrolled a passkey, if it did.
    pub completed_at: Option<DateTime<Utc>>,
    /// When it was cancelled before its link was used.
    pub cancelled_at: Option<DateTime<Utc>>,
    /// When it was undone, by its owner or by support.
    pub undone_at: Option<DateTime<Utc>>,
    /// Where it stands now.
    pub state: RecoveryState,
    /// The passkey its link enrolled, if it did.
    pub passkey: Option<RecoveryPasskey>,
}

/// The passkey a recovery's link enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPasskey {
    /// The passkey.
    pub id: PasskeyId,
    /// Its label, while its row exists.
    pub friendly_name: Option<String>,
    /// Whether it is still active.
    pub active: bool,
}

/// A [`RecentRecovery`] as one row: the recovery, and its passkey's columns.
struct RecentRow {
    /// The recovery.
    recovery: StoredRecovery,
    /// See [`RecoveryPasskey::friendly_name`].
    passkey_name: Option<String>,
    /// See [`RecoveryPasskey::active`].
    passkey_active: bool,
}

impl From<RecentRow> for RecentRecovery {
    /// Computes its state, and gathers the enrolled passkey's columns.
    fn from(row: RecentRow) -> Self {
        let RecentRow {
            recovery,
            passkey_name,
            passkey_active,
        } = row;
        Self {
            state: recovery.state(),
            id: recovery.id,
            started_at: recovery.started_at,
            expires_at: recovery.expires_at,
            completed_at: recovery.completed_at,
            cancelled_at: recovery.cancelled_at,
            undone_at: recovery.undone_at,
            passkey: recovery.passkey_id.map(|id| RecoveryPasskey {
                id,
                friendly_name: passkey_name,
                active: passkey_active,
            }),
        }
    }
}

impl RecoveryRepository<'_> {
    /// Stores a new recovery.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails.
    pub async fn insert(&mut self, recovery: &InsertRecovery<'_>) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO account_recoveries (id, user_id, secret_digest, expires_at)
                VALUES ($1, $2, $3, $4)",
                recovery.id.as_uuid(),
                recovery.user_id.as_uuid(),
                recovery.secret_digest,
                recovery.expires_at,
            )
        )?;
        Ok(())
    }

    /// Cancels the account's recovery whose link was not used, expired or not, if
    /// any: a newer one replaces it, the account is being disabled, or its owner
    /// undoes it. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn cancel_open(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET cancelled_at = clock_timestamp()
                WHERE user_id = $1
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL",
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// The recovery whose link's token has SHA-256 `digest`, if the link still
    /// works: not used, cancelled or expired.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn find_open_by_digest(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId", started_at,
                    expires_at, completed_at, passkey_id AS "passkey_id: PasskeyId",
                    settles_at, cancelled_at, undone_at, clock_timestamp() AS "read_at!"
                FROM account_recoveries
                WHERE secret_digest = $1
                AND completed_at IS NULL AND cancelled_at IS NULL
                AND expires_at > clock_timestamp()"#,
                digest,
            )
        )
    }

    /// Records that `user_id`'s recovery `id` enrolled `passkey_id` through its
    /// link, once, and starts its probation, which lasts `probation`. Returns
    /// `false` if the link no longer works. Times are the clock's, not the
    /// transaction's start, which may precede a wait for the account lock.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn complete(
        &mut self,
        user_id: UserId,
        id: RecoveryId,
        passkey_id: PasskeyId,
        probation: Duration,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries
                SET completed_at = clock_timestamp(), passkey_id = $3,
                    settles_at = clock_timestamp() + $4::bigint * interval '1 second'
                WHERE user_id = $1 AND id = $2
                AND completed_at IS NULL AND cancelled_at IS NULL
                AND expires_at > clock_timestamp()",
                user_id.as_uuid(),
                id.as_uuid(),
                passkey_id.as_uuid(),
                probation.num_seconds(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// The account's newest recovery that was neither cancelled nor undone. If
    /// the account has a recovery that can still be undone, it is this one: a
    /// start cancels an unused link and is refused during a probation.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn latest(
        &mut self,
        user_id: UserId,
    ) -> Result<Option<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId", started_at,
                    expires_at, completed_at, passkey_id AS "passkey_id: PasskeyId",
                    settles_at, cancelled_at, undone_at, clock_timestamp() AS "read_at!"
                FROM account_recoveries
                WHERE user_id = $1 AND cancelled_at IS NULL AND undone_at IS NULL
                ORDER BY started_at DESC, id DESC
                LIMIT 1"#,
                user_id.as_uuid(),
            )
        )
    }

    /// The recovery whose link enrolled passkey `passkey_id`, if one did.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn of_passkey(
        &mut self,
        passkey_id: PasskeyId,
    ) -> Result<Option<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId", started_at,
                    expires_at, completed_at, passkey_id AS "passkey_id: PasskeyId",
                    settles_at, cancelled_at, undone_at, clock_timestamp() AS "read_at!"
                FROM account_recoveries
                WHERE passkey_id = $1"#,
                passkey_id.as_uuid(),
            )
        )
    }

    /// Recovery `id`, whatever its state.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn find(&mut self, id: RecoveryId) -> Result<Option<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId", started_at,
                    expires_at, completed_at, passkey_id AS "passkey_id: PasskeyId",
                    settles_at, cancelled_at, undone_at, clock_timestamp() AS "read_at!"
                FROM account_recoveries
                WHERE id = $1"#,
                id.as_uuid()
            )
        )
    }

    /// The account's recoveries that started, were used, cancelled or undone
    /// after `since`, newest first, with the passkey each enrolled: one undone
    /// yesterday shows, however long ago it started.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn recent(
        &mut self,
        user_id: UserId,
        since: DateTime<Utc>,
    ) -> Result<Vec<RecentRecovery>, DatabaseError> {
        let rows = run!(
            self,
            fetch_all,
            sqlx::query!(
                r#"SELECT
                    r.id AS "id: RecoveryId", r.user_id AS "user_id: UserId", r.started_at,
                    r.expires_at, r.completed_at, r.passkey_id AS "passkey_id: PasskeyId",
                    r.settles_at, r.cancelled_at, r.undone_at,
                    clock_timestamp() AS "read_at!", p.friendly_name AS "passkey_name?",
                    (p.id IS NOT NULL AND p.revoked_at IS NULL) AS "passkey_active!"
                FROM account_recoveries r
                LEFT JOIN passkey_credentials p ON p.id = r.passkey_id
                WHERE r.user_id = $1
                AND GREATEST(r.started_at, r.completed_at, r.cancelled_at, r.undone_at) > $2
                ORDER BY r.started_at DESC, r.id DESC"#,
                user_id.as_uuid(),
                since,
            )
        )?;
        Ok(rows
            .into_iter()
            .map(|row| {
                RecentRow {
                    recovery: StoredRecovery {
                        id: row.id,
                        user_id: row.user_id,
                        started_at: row.started_at,
                        expires_at: row.expires_at,
                        completed_at: row.completed_at,
                        passkey_id: row.passkey_id,
                        settles_at: row.settles_at,
                        cancelled_at: row.cancelled_at,
                        undone_at: row.undone_at,
                        read_at: row.read_at,
                    },
                    passkey_name: row.passkey_name,
                    passkey_active: row.passkey_active,
                }
                .into()
            })
            .collect())
    }

    /// Records that recovery `id`, whose link was used, was undone, by its owner
    /// or by support.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn undo(&mut self, id: RecoveryId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET undone_at = clock_timestamp()
                WHERE id = $1 AND completed_at IS NOT NULL AND undone_at IS NULL",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Makes recovery `id`'s unused link expire now: a fixture for expiry.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    #[cfg(feature = "test-support")]
    pub async fn expire(&mut self, id: RecoveryId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET expires_at = clock_timestamp() WHERE id = $1",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Moves recovery `id`'s use and probation `by` into the past, as if its link
    /// had been used that long ago: a fixture for the probation's end.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    #[cfg(feature = "test-support")]
    pub async fn backdate_completion(
        &mut self,
        id: RecoveryId,
        by: Duration,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries
                SET completed_at = completed_at - $2::bigint * interval '1 millisecond',
                    settles_at = settles_at - $2::bigint * interval '1 millisecond'
                WHERE id = $1",
                id.as_uuid(),
                by.num_milliseconds(),
            )
        )?;
        Ok(())
    }
}
