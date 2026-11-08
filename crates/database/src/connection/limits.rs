//! Time limits on database sessions: the defaults every connection starts with,
//! and the longer ones that work which needs them sets for itself.

use sqlx::{Postgres, postgres::PgArguments, query::QueryScalar};
use std::time::Duration;

/// A `PostgreSQL` time limit on a session, with its value. Every connection
/// starts with [`Self::DEFAULTS`]; work that legitimately takes longer sets its own
/// with [`Self::set`], explicitly, rather than raising the default for everyone.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limit {
    /// The setting's name.
    setting: &'static str,
    /// Its value; zero turns it off.
    value: Duration,
}

/// How long a [`Limit::set`] lasts.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Scope {
    /// Until the transaction ends (`SET LOCAL`); outside one, it does nothing.
    Transaction,
    /// Until the connection closes: only for one that never returns to the pool.
    Session,
}

impl Limit {
    /// Longest one statement may run. `PostgreSQL` then cancels it, which fails as
    /// [`DatabaseError::Cancelled`](crate::DatabaseError::Cancelled).
    pub(crate) const STATEMENT: Self = Self::new("statement_timeout", Duration::from_secs(15));
    /// Longest one statement waits for a lock, then fails as
    /// [`DatabaseError::LockUnavailable`](crate::DatabaseError::LockUnavailable).
    /// A statement waiting for a strong lock, such as a migration's DDL, queues
    /// every later one behind it, so the wait must stay short.
    pub(crate) const LOCK: Self = Self::new("lock_timeout", Duration::from_secs(5));
    /// Longest a session may sit idle inside a transaction. `PostgreSQL` then ends
    /// the session, so a forgotten transaction cannot keep its locks and its
    /// connection, or hold back the event consumers and the audit sealer, which
    /// wait for every older transaction to end.
    pub(crate) const IDLE_IN_TRANSACTION: Self = Self::new(
        "idle_in_transaction_session_timeout",
        Duration::from_secs(30),
    );
    /// No limit on a whole transaction, whatever the role set for itself: a seal
    /// batch or a verification may run longer than any one statement.
    const TRANSACTION: Self = Self::new("transaction_timeout", Duration::ZERO);
    /// The limits every connection starts with.
    pub(super) const DEFAULTS: [Self; 4] = [
        Self::STATEMENT,
        Self::LOCK,
        Self::IDLE_IN_TRANSACTION,
        Self::TRANSACTION,
    ];

    /// `setting` at `value`.
    const fn new(setting: &'static str, value: Duration) -> Self {
        Self { setting, value }
    }

    /// This limit at `value` instead; zero turns it off.
    pub(crate) const fn at(self, value: Duration) -> Self {
        Self { value, ..self }
    }

    /// The setting and its value in milliseconds, the unit all four read a bare
    /// number in, as connection options pass them.
    pub(super) fn option(self) -> (&'static str, String) {
        (self.setting, self.value.as_millis().to_string())
    }

    /// The query that sets this limit for `scope`, to run like any other, e.g.
    /// `run!(self, fetch_one, Limit::STATEMENT.at(PURGE).set(Scope::Transaction))`.
    pub(crate) fn set(self, scope: Scope) -> QueryScalar<'static, Postgres, String, PgArguments> {
        let (setting, value) = self.option();
        sqlx::query_scalar!(
            r#"SELECT set_config($1, $2, $3) AS "value!""#,
            setting,
            value,
            matches!(scope, Scope::Transaction),
        )
    }
}
