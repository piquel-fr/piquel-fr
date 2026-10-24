//! Account recoveries, their links, and what undoing one takes back. Every change
//! to an account's recoveries happens under that account's lock, so they
//! serialize without row locks.

use super::{RecoveryRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{ClientId, EmailId, PasskeyId, Provider, RecoveryId, UserId};
use serde::Serialize;

/// A new recovery, whose link works until `expires_at`.
pub struct InsertRecovery<'a> {
    /// Recovery identifier, which the link's token is derived from.
    pub id: RecoveryId,
    /// The account recovered.
    pub user_id: UserId,
    /// SHA-256 of the link's token.
    pub secret_digest: &'a [u8],
    /// The account's primary address, which undoing the recovery restores.
    pub primary_email_id: Option<EmailId>,
    /// When the link stops working.
    pub expires_at: DateTime<Utc>,
}

/// A recovery as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecovery {
    /// Recovery identifier.
    pub id: RecoveryId,
    /// The account recovered.
    pub user_id: UserId,
    /// The account's primary address when it started.
    pub primary_email_id: Option<EmailId>,
    /// When it started.
    pub started_at: DateTime<Utc>,
    /// When its link stops working.
    pub expires_at: DateTime<Utc>,
    /// When its link enrolled a passkey, if it did.
    pub completed_at: Option<DateTime<Utc>>,
}

/// What undoing a recovery takes back: every way to sign in and every address
/// the account gained since it started, and the primary address it had then. The
/// undo page lists it, and undoing applies exactly it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Rollback {
    /// Active passkeys enrolled since, the recovery's own included.
    pub passkeys: Vec<AddedPasskey>,
    /// Identities linked since.
    pub identities: Vec<AddedIdentity>,
    /// Addresses added or verified since.
    pub emails: Vec<AddedEmail>,
    /// Consents given or extended since.
    pub consents: Vec<AddedConsent>,
    /// The address made primary again, if the primary changes: the one the
    /// recovery started with, or, if it is gone, the oldest address verified
    /// before it.
    pub primary: Option<RestoredPrimary>,
}

/// A passkey enrolled since a recovery started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AddedPasskey {
    /// The passkey.
    pub id: PasskeyId,
    /// Its label.
    pub friendly_name: String,
    /// When it was enrolled.
    pub enrolled_at: DateTime<Utc>,
}

/// An identity linked since a recovery started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AddedIdentity {
    /// Its provider; an account links one identity per provider.
    pub provider: Provider,
    /// The email the provider reported, if any.
    pub linked_email: Option<String>,
    /// When it was linked.
    pub linked_at: DateTime<Utc>,
}

/// An address added, or verified, since a recovery started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AddedEmail {
    /// The address's ID.
    pub id: EmailId,
    /// The address.
    pub address: String,
    /// When it was added.
    pub added_at: DateTime<Utc>,
    /// When it was verified, if it was.
    pub verified_at: Option<DateTime<Utc>>,
}

/// A consent to a client given, or extended, since a recovery started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AddedConsent {
    /// The client.
    pub client_id: ClientId,
    /// Its display name.
    pub client_name: String,
    /// The audience consented to.
    pub audience: String,
    /// When it was last given.
    pub granted_at: DateTime<Utc>,
}

/// A recent recovery of an account, as support reviews it before starting
/// another: when it started and ended, and the passkey its link enrolled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecentRecovery {
    /// The recovery.
    pub id: RecoveryId,
    /// When it started.
    pub started_at: DateTime<Utc>,
    /// When its link enrolled a passkey, if it did.
    pub completed_at: Option<DateTime<Utc>>,
    /// When a newer recovery or the account's disabling replaced it.
    pub cancelled_at: Option<DateTime<Utc>>,
    /// When its owner undid it.
    pub undone_at: Option<DateTime<Utc>>,
    /// The passkey its link enrolled, if it did.
    pub passkey: Option<RecoveryPasskey>,
}

/// The passkey a recovery's link enrolled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryPasskey {
    /// The passkey.
    pub id: PasskeyId,
    /// Its label, while its row exists.
    pub friendly_name: Option<String>,
    /// Whether it is still active.
    pub active: bool,
}

/// A [`RecentRecovery`] as one row.
struct RecentRow {
    /// See [`RecentRecovery::id`].
    id: RecoveryId,
    /// See [`RecentRecovery::started_at`].
    started_at: DateTime<Utc>,
    /// See [`RecentRecovery::completed_at`].
    completed_at: Option<DateTime<Utc>>,
    /// See [`RecentRecovery::cancelled_at`].
    cancelled_at: Option<DateTime<Utc>>,
    /// See [`RecentRecovery::undone_at`].
    undone_at: Option<DateTime<Utc>>,
    /// See [`RecoveryPasskey::id`].
    passkey_id: Option<PasskeyId>,
    /// See [`RecoveryPasskey::friendly_name`].
    passkey_name: Option<String>,
    /// See [`RecoveryPasskey::active`].
    passkey_active: bool,
}

impl From<RecentRow> for RecentRecovery {
    /// Gathers the enrolled passkey's columns, which exist together.
    fn from(row: RecentRow) -> Self {
        Self {
            id: row.id,
            started_at: row.started_at,
            completed_at: row.completed_at,
            cancelled_at: row.cancelled_at,
            undone_at: row.undone_at,
            passkey: row.passkey_id.map(|id| RecoveryPasskey {
                id,
                friendly_name: row.passkey_name,
                active: row.passkey_active,
            }),
        }
    }
}

/// The address undoing a recovery makes primary again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RestoredPrimary {
    /// The address's ID.
    pub id: EmailId,
    /// The address.
    pub address: String,
    /// Whether it is primary already, so nothing changes.
    #[serde(skip)]
    pub is_primary: bool,
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
                "INSERT INTO account_recoveries
                    (id, user_id, secret_digest, primary_email_id, expires_at)
                VALUES ($1, $2, $3, $4, $5)",
                recovery.id.as_uuid(),
                recovery.user_id.as_uuid(),
                recovery.secret_digest,
                recovery.primary_email_id.map(EmailId::as_uuid),
                recovery.expires_at,
            )
        )?;
        Ok(())
    }

    /// Cancels the account's recovery whose link was not used yet, if any: a
    /// newer one replaces it, or the account is being disabled.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn cancel_open(&mut self, user_id: UserId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET cancelled_at = now()
                WHERE user_id = $1
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL",
                user_id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// The recovery whose link's token has SHA-256 `digest`, if the link still
    /// works: not used, cancelled, undone or expired.
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
                    id AS "id: RecoveryId", user_id AS "user_id: UserId",
                    primary_email_id AS "primary_email_id: EmailId", started_at,
                    expires_at, completed_at
                FROM account_recoveries
                WHERE secret_digest = $1
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL
                AND expires_at > now()"#,
                digest,
            )
        )
    }

    /// Records that `user_id`'s recovery `id` enrolled `passkey_id` through its
    /// link, once. Returns `false` if the link no longer works. Expiry is checked
    /// against the clock, not the transaction's start, which may precede a wait
    /// for the account lock.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn complete(
        &mut self,
        user_id: UserId,
        id: RecoveryId,
        passkey_id: PasskeyId,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET completed_at = now(), passkey_id = $3
                WHERE user_id = $1 AND id = $2
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL
                AND expires_at > clock_timestamp()",
                user_id.as_uuid(),
                id.as_uuid(),
                passkey_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// The account's recoveries that can still be undone, newest first: those
    /// whose link still works, and those it was used for after `settled_before`.
    /// Neither cancelled nor undone.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn undoable(
        &mut self,
        user_id: UserId,
        settled_before: DateTime<Utc>,
    ) -> Result<Vec<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId",
                    primary_email_id AS "primary_email_id: EmailId", started_at,
                    expires_at, completed_at
                FROM account_recoveries
                WHERE user_id = $1
                AND cancelled_at IS NULL AND undone_at IS NULL
                AND CASE WHEN completed_at IS NULL THEN expires_at > now()
                    ELSE completed_at > $2 END
                ORDER BY started_at DESC, id DESC"#,
                user_id.as_uuid(),
                settled_before,
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
                    id AS "id: RecoveryId", user_id AS "user_id: UserId",
                    primary_email_id AS "primary_email_id: EmailId", started_at,
                    expires_at, completed_at
                FROM account_recoveries
                WHERE id = $1"#,
                id.as_uuid(),
            )
        )
    }

    /// The account's recoveries started, or used, after `since`, newest first,
    /// with the passkey each enrolled.
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
            sqlx::query_as!(
                RecentRow,
                r#"SELECT
                    r.id AS "id: RecoveryId", r.started_at, r.completed_at, r.cancelled_at,
                    r.undone_at, r.passkey_id AS "passkey_id: PasskeyId",
                    p.friendly_name AS "passkey_name?",
                    (p.id IS NOT NULL AND p.revoked_at IS NULL) AS "passkey_active!"
                FROM account_recoveries r
                LEFT JOIN passkey_credentials p ON p.id = r.passkey_id
                WHERE r.user_id = $1 AND COALESCE(r.completed_at, r.started_at) > $2
                ORDER BY r.started_at DESC, r.id DESC"#,
                user_id.as_uuid(),
                since,
            )
        )?;
        Ok(rows.into_iter().map(Into::into).collect())
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
                "UPDATE account_recoveries SET expires_at = now() WHERE id = $1",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Moves recovery `id`'s use `by` into the past, as if its link had been
    /// used that long ago: a fixture for the settle window.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    #[cfg(feature = "test-support")]
    pub async fn backdate_completion(
        &mut self,
        id: RecoveryId,
        by: chrono::Duration,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries
                SET completed_at = completed_at - $2::bigint * interval '1 millisecond'
                WHERE id = $1",
                id.as_uuid(),
                by.num_milliseconds(),
            )
        )?;
        Ok(())
    }

    /// Records that the owner undid recovery `id`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn undo(&mut self, id: RecoveryId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET undone_at = now()
                WHERE id = $1 AND cancelled_at IS NULL AND undone_at IS NULL",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// What undoing `recovery` takes back now, as [`Rollback`] says.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails.
    pub async fn rollback(&mut self, recovery: &StoredRecovery) -> Result<Rollback, DatabaseError> {
        let (user, since) = (recovery.user_id.as_uuid(), recovery.started_at);
        let passkeys = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                AddedPasskey,
                r#"SELECT id AS "id: PasskeyId", friendly_name, created_at AS enrolled_at
                FROM passkey_credentials
                WHERE user_id = $1 AND revoked_at IS NULL AND created_at >= $2
                ORDER BY created_at, id"#,
                user,
                since,
            )
        )?;
        let identities = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                AddedIdentity,
                r#"SELECT provider_name AS "provider: Provider", linked_email, linked_at
                FROM external_login_identities
                WHERE user_id = $1 AND revoked_at IS NULL AND linked_at >= $2
                ORDER BY linked_at, id"#,
                user,
                since,
            )
        )?;
        let emails = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                AddedEmail,
                r#"SELECT id AS "id: EmailId", normalized_email AS address,
                    created_at AS added_at, verified_at
                FROM user_emails
                WHERE user_id = $1 AND (created_at >= $2 OR verified_at >= $2)
                ORDER BY created_at, id"#,
                user,
                since,
            )
        )?;
        // Prefers the recorded primary; every candidate predates the recovery, so
        // none is taken back.
        let primary = run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                RestoredPrimary,
                r#"SELECT id AS "id: EmailId", normalized_email AS address, is_primary
                FROM user_emails
                WHERE user_id = $1 AND created_at < $2 AND verified_at < $2
                ORDER BY COALESCE(id = $3, false) DESC, created_at, id
                LIMIT 1"#,
                user,
                since,
                recovery.primary_email_id.map(EmailId::as_uuid),
            )
        )?;
        let consents = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                AddedConsent,
                r#"SELECT
                    c.client_id AS "client_id: ClientId", o.display_name AS client_name,
                    c.audience, c.granted_at
                FROM oidc_consents c
                JOIN oidc_clients o ON o.id = c.client_id
                WHERE c.user_id = $1 AND c.granted_at >= $2
                ORDER BY c.granted_at, c.client_id, c.audience"#,
                user,
                since,
            )
        )?;
        Ok(Rollback {
            passkeys,
            identities,
            emails,
            consents,
            primary: primary.filter(|primary| !primary.is_primary),
        })
    }
}
