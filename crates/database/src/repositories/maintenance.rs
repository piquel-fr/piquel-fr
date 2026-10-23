//! Bounded deletion of expired ephemeral authentication state, event personal data
//! and finished deliveries.

use super::{MaintenanceRepository, RepositoryExecutor};
use crate::DatabaseError;

/// Maximum rows removed from each table in one maintenance batch.
const MAX_PURGE_BATCH: u32 = 1_000;

impl MaintenanceRepository<'_> {
    /// Purges a bounded batch of expired ephemeral authentication state, of event
    /// personal data older than 90 days, and of deliveries that succeeded over 7
    /// days ago or failed or were cancelled over 30 days ago, and returns how many
    /// rows were deleted. Failed ordered deliveries are left to
    /// [`DatabaseTransaction::abandon_stuck_deliveries`](crate::DatabaseTransaction::abandon_stuck_deliveries). `batch_size` is clamped to 1..=1000 rows per table.
    ///
    /// Each batch skips rows that live requests have locked. Outside a transaction,
    /// each table's batch commits on its own, so cleanup never holds locks across
    /// tables; inside one, all of them commit or roll back with it. Deleting a
    /// session or an authorization code can still wait briefly on a locked child row
    /// it cascades to or unlinks.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a delete fails. Outside a transaction, earlier
    /// tables stay purged.
    #[expect(
        clippy::too_many_lines,
        reason = "Each purge statement is inline SQL so that it is checked at compile time."
    )]
    pub async fn purge_expired_auth_state(
        &mut self,
        batch_size: u32,
    ) -> Result<u64, DatabaseError> {
        let limit = i64::from(batch_size.clamp(1, MAX_PURGE_BATCH));
        // Runs each statement in order, each removing at most `$1` expired rows
        // that no live request has locked. A checked query needs a literal, and
        // each has its own type, so the statements cannot share a loop.
        macro_rules! purge {
            ($($statement:literal,)+) => {
                Ok(0 $(+ run!(self, execute, sqlx::query!($statement, limit))?.rows_affected())+)
            };
        }
        purge!(
            "DELETE FROM request_limits
            WHERE ctid IN (
                SELECT ctid
                FROM request_limits
                WHERE expires_at < now()
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            "DELETE FROM invitations
            WHERE ctid IN (
                SELECT ctid
                FROM invitations
                WHERE expires_at < now()
                OR redeemed_at < now() - interval '1 day'
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            "DELETE FROM pending_federation
            WHERE ctid IN (
                SELECT ctid
                FROM pending_federation
                WHERE expires_at < now()
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            "DELETE FROM federation_transactions
            WHERE ctid IN (
                SELECT ctid
                FROM federation_transactions
                WHERE expires_at < now()
                OR consumed_at < now() - interval '1 day'
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            "DELETE FROM webauthn_ceremonies
            WHERE ctid IN (
                SELECT ctid
                FROM webauthn_ceremonies
                WHERE expires_at < now()
                OR consumed_at < now() - interval '1 day'
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            "DELETE FROM authorization_requests
            WHERE ctid IN (
                SELECT ctid
                FROM authorization_requests
                WHERE expires_at < now()
                OR consumed_at < now() - interval '1 day'
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            // A redeemed code stays while a replay could still revoke something: an
            // unrevoked family it produced whose session is live (refresh tokens expire
            // with the session). The first day after redemption is kept regardless, so
            // replays are still recorded even for codes that produced no refresh family.
            // Retained codes are rechecked on every pass, so this scan grows with
            // every redeemed code past its first day, not only with purgeable ones.
            "DELETE FROM authorization_codes c
            WHERE c.ctid IN (
                SELECT code.ctid
                FROM authorization_codes code
                WHERE (code.consumed_at IS NULL AND code.expires_at < now())
                OR (
                    code.consumed_at < now() - interval '1 day'
                    AND NOT EXISTS (
                        SELECT 1
                        FROM refresh_token_families family
                        JOIN sessions session ON session.id = family.session_id
                        WHERE family.authorization_code_id = code.id
                        AND family.revoked_at IS NULL
                        AND session.revoked_at IS NULL
                        AND session.expires_at > now()
                    )
                )
                LIMIT $1
                FOR UPDATE OF code SKIP LOCKED
            )",
            "DELETE FROM refresh_tokens t
            WHERE t.ctid IN (
                SELECT token.ctid
                FROM refresh_tokens token
                JOIN refresh_token_families family ON family.id = token.family_id
                WHERE token.expires_at < now()
                OR family.revoked_at < now() - interval '1 day'
                LIMIT $1
                FOR UPDATE OF token SKIP LOCKED
            )",
            "DELETE FROM refresh_token_families f
            WHERE f.ctid IN (
                SELECT family.ctid
                FROM refresh_token_families family
                WHERE (
                    family.revoked_at < now() - interval '1 day'
                    OR family.created_at < now() - interval '31 days'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM refresh_tokens token
                    WHERE token.family_id = family.id
                )
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            "DELETE FROM browser_session_secrets b
            WHERE b.ctid IN (
                SELECT secret.ctid
                FROM browser_session_secrets secret
                JOIN sessions session ON session.id = secret.session_id
                WHERE session.expires_at < now()
                OR session.revoked_at < now() - interval '1 day'
                LIMIT $1
                FOR UPDATE OF secret SKIP LOCKED
            )",
            // Events are kept indefinitely; the personal data beside them is not.
            // No FOR UPDATE: it needs the UPDATE privilege, which the runtime role
            // lacks here. Requests never update these rows, so none hold their locks.
            "DELETE FROM event_personal_data
            WHERE ctid IN (
                SELECT ctid
                FROM event_personal_data
                WHERE created_at < now() - interval '90 days'
                LIMIT $1
            )",
            // Ordered failures hold back their key, so only
            // `DatabaseTransaction::abandon_stuck_deliveries` removes them.
            "DELETE FROM deliveries d
            WHERE d.ctid IN (
                SELECT delivery.ctid
                FROM deliveries delivery
                WHERE (delivery.status = 'succeeded' AND delivery.finished_at < now() - interval '7 days')
                OR (delivery.status = 'cancelled' AND delivery.finished_at < now() - interval '30 days')
                OR (
                    delivery.status = 'failed'
                    AND delivery.ordering_key IS NULL
                    AND delivery.finished_at < now() - interval '30 days'
                )
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
            "DELETE FROM sessions s
            WHERE s.ctid IN (
                SELECT session.ctid
                FROM sessions session
                WHERE (
                    session.expires_at < now()
                    OR session.revoked_at < now() - interval '1 day'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM refresh_token_families family
                    WHERE family.session_id = session.id
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM authorization_codes code
                    WHERE code.session_id = session.id
                )
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )",
        )
    }
}
