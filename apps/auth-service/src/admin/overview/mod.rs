//! The dashboard's overview: what the service is doing now, against what it
//! usually does, and what needs an administrator's attention.

use super::{AdminError, AdminService, Operator};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    admin::{Event, EventSearch, User},
    alerts::{Alert, StoredAlert},
};
use piquel_repository::{DeliveryBacklog, Email};

/// How many of the newest events the overview shows.
const EVENTS_SHOWN: usize = 8;
/// How many of the newest accounts the overview shows.
const NEWEST_SHOWN: u16 = 6;
/// The hours of the week a rate is averaged over.
const HOURS_PER_WEEK: u64 = 7 * 24;
/// How long a message may wait before its backlog needs attention.
const DELIVERY_PATIENCE: Duration = Duration::minutes(15);

/// The kinds of event the overview counts, by the serde tags
/// [`DomainEvent`](piquel_common::events::DomainEvent) stores them under.
pub(crate) struct Kinds;

impl Kinds {
    /// A rejected passkey or provider authentication.
    pub(crate) const FAILED: &'static str = "sign_in_failed";
    /// A browser signed in.
    const SIGNED_IN: &'static str = "signed_in";
    /// A client exchanged a code for tokens.
    const GRANT: &'static str = "grant_issued";
}

/// How often something happened in the last hour, against an hour's usual
/// count over the last week.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rate {
    /// In the last hour.
    pub last_hour: u64,
    /// Per hour, averaged over the week before, rounded up.
    pub usual: u64,
}

impl Rate {
    /// The rate of `last_hour` against `week`, a week's total that includes the
    /// last hour: the usual hour is the week before it, so a spike never raises
    /// its own baseline.
    const fn new(last_hour: u64, week: u64) -> Self {
        Self {
            last_hour,
            usual: week.saturating_sub(last_hour).div_ceil(HOURS_PER_WEEK - 1),
        }
    }

    /// Whether the last hour is a spike: at least ten, and more than three times
    /// usual, so a quiet service's first failures raise nothing.
    const fn spikes(self) -> bool {
        self.last_hour >= 10 && self.last_hour > self.usual.saturating_mul(3)
    }
}

/// What needs an administrator's attention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// An alert is open: it says `subject`, and was raised at `raised_at`.
    OpenAlert {
        /// What it says, in one line.
        subject: &'static str,
        /// When it was raised.
        raised_at: DateTime<Utc>,
    },
    /// Far more sign-ins failed in the last hour than usually do.
    FailedSignIns(Rate),
    /// Messages wait to be delivered, the oldest for longer than they should.
    DeliveriesWaiting {
        /// How many wait.
        pending: u64,
        /// Since when the oldest waits.
        oldest: DateTime<Utc>,
    },
}

/// What the overview shows.
#[derive(Clone, Debug)]
pub struct Overview {
    /// Rejected passkey and provider authentications.
    pub failed_sign_ins: Rate,
    /// Browsers signing in.
    pub sign_ins: Rate,
    /// Clients exchanging codes for tokens.
    pub app_sign_ins: Rate,
    /// Sessions signed in now.
    pub active_sessions: u64,
    /// Every account.
    pub accounts: u64,
    /// The accounts administering Piquel.
    pub administrators: u64,
    /// The newest events.
    pub events: Vec<Event>,
    /// The newest accounts.
    pub newest: Vec<User>,
    /// The emails waiting to be sent.
    pub email_backlog: DeliveryBacklog,
    /// The open alerts, oldest first.
    pub open_alerts: Vec<StoredAlert>,
    /// When it was read.
    pub now: DateTime<Utc>,
}

impl Overview {
    /// What needs attention, most pressing first.
    #[must_use]
    pub fn problems(&self) -> Vec<Problem> {
        let mut problems: Vec<_> = self
            .open_alerts
            .iter()
            .map(|alert| Problem::OpenAlert {
                subject: alert.alert.as_ref().map_or(Alert::UNKNOWN, Alert::subject),
                raised_at: alert.raised_at,
            })
            .collect();
        if self.failed_sign_ins.spikes() {
            problems.push(Problem::FailedSignIns(self.failed_sign_ins));
        }
        if let Some(oldest) = self.email_backlog.oldest
            && self.now - oldest > DELIVERY_PATIENCE
        {
            problems.push(Problem::DeliveriesWaiting {
                pending: self.email_backlog.pending,
                oldest,
            });
        }
        problems
    }
}

impl AdminService {
    /// Reads the overview: the last hour's rates against the week's, what is
    /// signed in now, the newest events and accounts, the email backlog and the
    /// open alerts.
    ///
    /// # Errors
    /// Fails when the operator may not read, or a query fails.
    pub(crate) async fn overview(&self, operator: &Operator) -> Result<Overview, AdminError> {
        operator.authorize_read(&self.database).await?;
        let now = Utc::now();
        let (hour, week) = (now - Duration::hours(1), now - Duration::days(7));
        let mut events = self.database.events();
        let mut rate = async |kind: &str| -> Result<Rate, AdminError> {
            let kinds = [kind.to_owned()];
            let last_hour = events.count_since(None, &kinds, hour).await?;
            let weekly = events.count_since(None, &kinds, week).await?;
            Ok(Rate::new(last_hour, weekly))
        };
        let failed_sign_ins = rate(Kinds::FAILED).await?;
        let sign_ins = rate(Kinds::SIGNED_IN).await?;
        let app_sign_ins = rate(Kinds::GRANT).await?;
        let mut newest_events = self.events(operator, EventSearch::default()).await?.events;
        newest_events.truncate(EVENTS_SHOWN);
        Ok(Overview {
            failed_sign_ins,
            sign_ins,
            app_sign_ins,
            active_sessions: self.database.sessions().count_active().await?,
            accounts: self.database.users().count().await?,
            administrators: u64::try_from(self.database.administrators().list().await?.len())
                .unwrap_or(u64::MAX),
            events: newest_events,
            newest: self.database.users().newest(NEWEST_SHOWN).await?,
            email_backlog: self.database.deliveries().backlog::<Email>().await?,
            open_alerts: self.database.alerts().open().await?,
            now,
        })
    }
}

#[cfg(test)]
mod tests;
