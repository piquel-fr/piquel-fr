//! What the database reports to telemetry: every committed event, as a log line
//! and in counters, and the pool's connections.

use crate::Database;
use piquel_common::{
    EventId, UserId,
    events::{DomainEvent, HistoryActor, SignInFailure},
};
use piquel_telemetry::{Counter, Gauge, Label};

/// Every committed event, by kind.
static EVENTS: Counter<[Label; 1]> = Counter::new(
    "piquel.auth.events",
    "{event}",
    "Domain events committed, by kind.",
);
/// Sign-ins and rejected authentications, by method and outcome.
static SIGN_INS: Counter<[Label; 2]> = Counter::new(
    "piquel.auth.sign_ins",
    "{sign_in}",
    "Sign-ins by method, and their outcome: success or why they were rejected.",
);
/// New accounts, by how the person proved who they are.
static REGISTRATIONS: Counter<[Label; 1]> = Counter::new(
    "piquel.auth.registrations",
    "{account}",
    "Accounts created, by authentication method.",
);
/// Revoked refresh families, by reason: replays and policy rejections included.
static GRANTS_REVOKED: Counter<[Label; 1]> = Counter::new(
    "piquel.auth.grants.revoked",
    "{grant}",
    "Refresh token families revoked, by reason.",
);
/// The pool's connections, as the database semantic conventions name them.
static CONNECTIONS: Gauge<[Label; 1]> = Gauge::new(
    "db.client.connection.count",
    "{connection}",
    "Connections in the database pool, by state.",
);

/// An event recorded in a transaction, published once the transaction commits.
pub(crate) struct Committed {
    /// The stored event's ID.
    pub(crate) id: EventId,
    /// The kind of actor that caused it; never who.
    pub(crate) actor: HistoryActor,
    /// The account it concerns.
    pub(crate) subject: Option<UserId>,
    /// What happened.
    pub(crate) event: DomainEvent,
}

impl Committed {
    /// Logs the event in the current trace and counts it. It runs only after the
    /// commit, so a rolled-back change is never counted; a commit whose answer is
    /// lost may go uncounted, so the stored history stays the record. The line names the
    /// event, its kind, the kind of actor and the subject's pseudonymous ID: the
    /// rest, personal data included, stays in the database under the event's ID.
    pub(crate) fn publish(&self) {
        let kind = self.event.kind();
        tracing::info!(
            event.id = %self.id,
            event.kind = kind,
            event.actor = self.actor.as_str(),
            event.subject = self.subject.map(tracing::field::display),
            "event recorded"
        );
        EVENTS.add(1, &[("kind", kind)]);
        match &self.event {
            DomainEvent::SignedIn { method, .. } => {
                SIGN_INS.add(1, &[("method", method.as_str()), ("outcome", "success")]);
            }
            DomainEvent::SignInFailed { method, reason } => {
                SIGN_INS.add(
                    1,
                    &[
                        ("method", method.as_str()),
                        ("outcome", SignInFailure::as_str(*reason)),
                    ],
                );
            }
            DomainEvent::AccountCreated { method, .. } => {
                REGISTRATIONS.add(1, &[("method", method.as_str())]);
            }
            DomainEvent::GrantRevoked { reason, .. } => {
                GRANTS_REVOKED.add(1, &[("reason", reason.as_str())]);
            }
            _ => {}
        }
    }
}

impl Database {
    /// Reports the pool's idle and used connections as `db.client.connection.count`
    /// at every metrics collection. Only the first call registers.
    pub fn observe_connections(&self) {
        let pool = self.pool.clone();
        CONNECTIONS.observe(move || {
            let idle = u64::try_from(pool.num_idle()).unwrap_or(u64::MAX);
            let used = u64::from(pool.size()).saturating_sub(idle);
            [
                (idle, [("db.client.connection.state", "idle")]),
                (used, [("db.client.connection.state", "used")]),
            ]
        });
    }
}
