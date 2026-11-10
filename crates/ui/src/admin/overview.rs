//! The dashboard's overview: what needs attention, the numbers that show a
//! problem at a glance, the newest events and the newest accounts.

use super::{EventRow, UserRow, account_status, event_rows, moment};
use crate::{
    icons::{Icon, icon},
    layout::{AvatarSize, avatar, page_head},
};
use chrono::{DateTime, Utc};
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// Something that needs an administrator's attention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem<'a> {
    /// Alerts are open: nobody posted an update on them yet.
    OpenAlerts {
        /// How many.
        count: u64,
        /// The alerts.
        alerts: &'a str,
    },
    /// Far more sign-ins failed in the last hour than usually do.
    FailedSignIns {
        /// How many failed in the last hour.
        count: u64,
        /// How many usually fail in an hour, over the last week.
        usual: u64,
        /// The events, filtered to the failures.
        events: &'a str,
    },
    /// Messages wait to be delivered, and the oldest has waited a while.
    DeliveriesWaiting {
        /// How many wait.
        pending: u64,
        /// Since when the oldest waits.
        oldest: DateTime<Utc>,
        /// The delivery queue.
        deliveries: &'a str,
    },
}

/// A number the overview shows, with what it usually is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measure {
    /// Sign-ins that failed in the last hour, against an hour's usual count.
    FailedSignIns {
        /// In the last hour.
        count: u64,
        /// Usually, per hour, over the last week.
        usual: u64,
    },
    /// Sign-ins in the last hour, against an hour's usual count.
    SignIns {
        /// In the last hour.
        count: u64,
        /// Usually, per hour, over the last week.
        usual: u64,
    },
    /// Sessions that are signed in now.
    ActiveSessions(u64),
    /// Apps that exchanged a code for tokens in the last hour, against an hour's
    /// usual count.
    AppSignIns {
        /// In the last hour.
        count: u64,
        /// Usually, per hour, over the last week.
        usual: u64,
    },
}

impl Measure {
    /// Its label.
    const fn label(self) -> &'static str {
        match self {
            Self::FailedSignIns { .. } => "Failed sign-ins, last hour",
            Self::SignIns { .. } => "Sign-ins, last hour",
            Self::ActiveSessions(_) => "Active sessions",
            Self::AppSignIns { .. } => "App sign-ins, last hour",
        }
    }

    /// Its value.
    const fn value(self) -> u64 {
        match self {
            Self::FailedSignIns { count, .. }
            | Self::SignIns { count, .. }
            | Self::AppSignIns { count, .. }
            | Self::ActiveSessions(count) => count,
        }
    }

    /// How it compares with usual, if it is a rate.
    fn detail(self) -> String {
        match self {
            Self::ActiveSessions(_) => "now".to_owned(),
            Self::FailedSignIns { count, usual }
            | Self::SignIns { count, usual }
            | Self::AppSignIns { count, usual } => match (count, usual) {
                (_, 0) if count == 0 => "none this week".to_owned(),
                (_, 0) => "none before this hour".to_owned(),
                (count, usual) if count >= usual.saturating_mul(2) => {
                    format!("▲ {}× usual ({usual})", count / usual)
                }
                (count, usual) if count.saturating_mul(2) <= usual => {
                    format!("▼ below usual ({usual})")
                }
                (_, usual) => format!("about usual ({usual})"),
            },
        }
    }

    /// Whether it is what one of `problems` is about.
    fn warning(self, problems: &[Problem<'_>]) -> bool {
        matches!(self, Self::FailedSignIns { .. })
            && problems
                .iter()
                .any(|problem| matches!(problem, Problem::FailedSignIns { .. }))
    }
}

/// What the overview shows.
#[derive(Clone, Copy, Debug)]
pub struct AdminOverview<'a> {
    /// What needs attention, most pressing first.
    pub problems: &'a [Problem<'a>],
    /// The numbers, in the order shown.
    pub measures: &'a [Measure],
    /// How many accounts there are.
    pub accounts: u64,
    /// How many administer Origin Auth.
    pub administrators: u64,
    /// The newest events.
    pub events: &'a [EventRow<'a>],
    /// The newest accounts.
    pub newest: &'a [UserRow<'a>],
    /// Every event.
    pub all_events: &'a str,
    /// Every account.
    pub all_users: &'a str,
}

impl AdminOverview<'_> {
    /// The page's lead: how many accounts there are, and how many of them
    /// administer Origin Auth, each with its noun in the right number.
    fn lead(&self) -> String {
        let accounts = match self.accounts {
            1 => "1 account".to_owned(),
            n => format!("{n} accounts"),
        };
        let administrators = match self.administrators {
            1 => "1 of them an administrator".to_owned(),
            n => format!("{n} of them administrators"),
        };
        format!(
            "{accounts}, {administrators}. What needs attention, and what the service is doing right now."
        )
    }
}

/// The overview page.
#[component]
pub async fn admin_overview<'a>(overview: AdminOverview<'a>) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Overview",
            lead: overview.lead(),
        )
        for problem in overview.problems {
            problem_notice(problem: problem)
        }
        <div class="stats">
            for measure in overview.measures {
                let warning = measure.warning(overview.problems);
                <div class=(class!("stat", "warning" if warning))>
                    <span class="label">(measure.label())</span>
                    <span class="value">(measure.value().to_string())</span>
                    <span class=(class!("detail", "warning" if warning))>(measure.detail())</span>
                </div>
            }
        </div>
        <div class="two side">
            <section class="card" aria-labelledby="events-heading">
                <header>
                    <h2 id="events-heading">"Events " <span class="badge ok"><span class="dot"></span>"newest"</span></h2>
                    <a href=(overview.all_events)>"All events"</a>
                </header>
                event_rows(rows: overview.events)
            </section>
            <section class="card" aria-labelledby="newest-heading">
                <header>
                    <h2 id="newest-heading">"Newest accounts"</h2>
                    <a href=(overview.all_users)>"All users"</a>
                </header>
                if overview.newest.is_empty() {
                    <p class="empty">"No account yet."</p>
                } else {
                    <ul class="list">
                        for row in overview.newest {
                            <li>
                                avatar(who: row.who(), size: AvatarSize::Small)
                                <div class="text">
                                    <a href=(row.href.as_str())><strong>(format!("@{}", row.user.handle))</strong></a>
                                    <small>"joined " moment(at: row.user.created_at)</small>
                                </div>
                                if row.administrator {
                                    <span class="badge admin"><span class="dot"></span>"Admin"</span>
                                } else {
                                    account_status(status: row.user.status)
                                }
                            </li>
                        }
                    </ul>
                }
            </section>
        </div>
    })
}

/// What a `problem` says, and where to look.
#[component]
async fn problem_notice<'a>(problem: &'a Problem<'a>) -> Result<impl View> {
    Ok(view! {
        match problem {
            Problem::OpenAlerts { count, alerts } => {
                <section class="notice warning" role="alert">
                    icon(kind: Icon::Warning)
                    <div class="text">
                        <strong>(if *count == 1 { "1 alert needs attention".to_owned() } else { format!("{count} alerts need attention") })</strong>
                        <small>(if *count == 1 { "Nobody has posted an update on it yet." } else { "Nobody has posted an update on them yet." })</small>
                    </div>
                    <a class="button secondary small" href=(*alerts)>"See the alerts"</a>
                </section>
            },
            Problem::FailedSignIns { count, usual, events } => {
                <section class="notice warning" role="alert">
                    icon(kind: Icon::Warning)
                    <div class="text">
                        <strong>(format!("Failed sign-ins are {}× the hourly average", count / (*usual).max(1)))</strong>
                        <small>(format!("{count} failed in the last hour. About {usual} usually do."))</small>
                    </div>
                    <a class="button secondary small" href=(*events)>"See the failures"</a>
                </section>
            },
            Problem::DeliveriesWaiting { pending, oldest, deliveries } => {
                <section class="notice warning" role="alert">
                    icon(kind: Icon::Warning)
                    <div class="text">
                        <strong>(format!("{pending} message{} waiting to be delivered", if *pending == 1 { " is" } else { "s are" }))</strong>
                        <small>"The oldest has waited since " moment(at: *oldest) ". Check that email can be sent, and whether a failed delivery holds the others back."</small>
                    </div>
                    <a class="button secondary small" href=(*deliveries)>"See the queue"</a>
                </section>
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{AdminOverview, admin_overview};
    use topcoat::{
        context::Cx,
        view::{ViewExt, view},
    };

    /// One account, or one administrator, reads as a singular on the page.
    #[tokio::test]
    async fn the_lead_counts_accounts_in_the_right_number() {
        for (accounts, administrators, counts) in [
            (1, 1, "1 account, 1 of them an administrator."),
            (1, 0, "1 account, 0 of them administrators."),
            (2, 1, "2 accounts, 1 of them an administrator."),
            (2, 3, "2 accounts, 3 of them administrators."),
        ] {
            let overview = AdminOverview {
                problems: &[],
                measures: &[],
                accounts,
                administrators,
                events: &[],
                newest: &[],
                all_events: "",
                all_users: "",
            };
            let cx = Cx::default();
            let page = view! { cx => admin_overview(overview: overview) }
                .single()
                .await
                .expect("the overview")
                .render(&cx);
            assert!(page.contains(counts), "{page}");
        }
    }
}
