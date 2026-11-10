//! Signed-in devices, and the browsers the account knows.

use super::{Part, device_name};
use crate::{
    form::{Precision, change_form, time},
    layout::page_head,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sourceorigin_common::{
    AuthenticationMethod, SessionId,
    admin::{DashboardSession, KnownDevice},
    events::UserAgentFamily,
};
use std::net::IpAddr;
use topcoat::{
    Result,
    view::{View, component, view},
};

/// A change the devices page posts, named by its `action` field. Neither needs a
/// passkey confirmation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DeviceChange {
    /// Signs one other device out.
    SignOut {
        /// Its session.
        id: SessionId,
    },
    /// Signs every other device out.
    SignOutOthers,
}

/// One browser signed in to the account.
#[derive(Clone, Copy, Debug)]
pub struct DeviceRow<'a> {
    /// Its session, to sign it out.
    pub id: SessionId,
    /// Whether it is the browser looking at the page.
    pub current: bool,
    /// The browser and platform it signed in with, if recorded.
    pub device: Option<UserAgentFamily>,
    /// The IP address of its last recorded activity, if recorded.
    pub ip: Option<IpAddr>,
    /// How it authenticated.
    pub methods: &'a [AuthenticationMethod],
    /// When it signed in.
    pub authenticated_at: DateTime<Utc>,
    /// Its last recorded activity.
    pub last_seen_at: DateTime<Utc>,
    /// The admin dashboard's sessions resting on it, newest first.
    pub dashboard: &'a [DashboardSession],
}

impl DeviceRow<'_> {
    /// Its name, or that none was recorded.
    pub(crate) fn name(&self) -> String {
        self.device.as_ref().map_or_else(
            || "An unrecorded device".to_owned(),
            |device| device_name(*device),
        )
    }

    /// How it signed in, from where, and when it was last active, as of `now`.
    pub(crate) fn details(&self, now: DateTime<Utc>) -> String {
        let methods = self
            .methods
            .iter()
            .map(|method| match method {
                AuthenticationMethod::Passkey => "Passkey",
                AuthenticationMethod::Federation => "Social sign-in",
            })
            .collect::<Vec<_>>()
            .join(" and ");
        [
            Some(methods),
            self.ip.map(|ip| ip.to_string()),
            Some(self.activity(now)),
        ]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
    }

    /// When it was last active, as of `now`: now for the browser looking at the
    /// page.
    fn activity(&self, now: DateTime<Utc>) -> String {
        if self.current {
            return "Active now".to_owned();
        }
        Self::active(self.last_seen_at, now)
    }

    /// What a dashboard `session` resting on it says, as of `now`: when it was
    /// last used, since it times out soon after.
    pub(crate) fn dashboard_details(session: &DashboardSession, now: DateTime<Utc>) -> String {
        format!(
            "Admin dashboard · {}",
            Self::active(session.last_used_at, now)
        )
    }

    /// That something was last active at `last`, as of `now`. Activity is recorded
    /// every five minutes at most, so anything closer is now.
    fn active(last: DateTime<Utc>, now: DateTime<Utc>) -> String {
        let ago = now - last;
        if ago < TimeDelta::minutes(5) {
            return "Active now".to_owned();
        }
        let (count, unit) = if ago < TimeDelta::hours(1) {
            (ago.num_minutes(), "minute")
        } else if ago < TimeDelta::days(1) {
            (ago.num_hours(), "hour")
        } else {
            (ago.num_days(), "day")
        };
        let plural = if count == 1 { "" } else { "s" };
        format!("Active {count} {unit}{plural} ago")
    }
}

/// The browsers the account knows, `known`: a sign-in from any other one alerts
/// the owner.
#[component]
pub async fn known_devices<'a>(known: &'a [KnownDevice]) -> Result<impl View> {
    Ok(view! {
        <section class="card" aria-labelledby=(Part::KnownBrowsers.id())>
            <header>
                <h2 id=(Part::KnownBrowsers.id())>"Known browsers " <span class="count">(known.len().to_string())</span></h2>
            </header>
            <p class="help">
                "Browsers that signed in to this account within the last 400 days. A sign-in from any other browser sends a security notification."
            </p>
            <ul class="list">
                for row in known {
                    <li>
                        <div class="text">
                            <strong>(row.device.map_or_else(|| "An unrecorded browser".to_owned(), device_name))</strong>
                            <small>
                                "First signed in "
                                time(at: row.first_seen_at, precision: Precision::Day)
                                ", last "
                                time(at: row.last_seen_at, precision: Precision::Day)
                            </small>
                        </div>
                    </li>
                }
            </ul>
            if known.is_empty() {
                <p class="empty">"No browser has signed in since Origin Auth started keeping track."</p>
            }
        </section>
    })
}

/// The devices page: every browser signed in to the account, as of `now`, then
/// every browser it knows. Signing one out, or every other one, posts to `page`.
#[component]
pub async fn devices<'a>(
    page: &'a str,
    rows: &'a [DeviceRow<'a>],
    known: &'a [KnownDevice],
    now: DateTime<Utc>,
) -> Result<impl View> {
    let others = rows.iter().any(|row| !row.current);
    Ok(view! {
        page_head(
            title: "Devices",
            lead: "Every browser signed in to your account. Signing one out also signs out the apps you use through it. Don’t recognize one? Sign it out, then review your security history.".to_owned(),
            actions: view! {
                if others {
                    change_form(
                        action: page,
                        change: DeviceChange::SignOutOthers,
                        label: "Sign out of all other devices",
                        class: "secondary small",
                    )
                }
            },
        )
        <section class="card" aria-labelledby=(Part::Devices.id())>
            <header>
                <h2 id=(Part::Devices.id())>"Signed-in devices " <span class="count">(rows.len().to_string())</span></h2>
            </header>
            <ul class="list">
                for row in rows {
                    let name = row.name();
                    <li>
                        <div class="text">
                            <strong>(name.as_str())</strong>
                            if row.current {
                                " " <span class="badge ok">"This device"</span>
                            }
                            <small>(row.details(now))</small>
                            for dashboard in row.dashboard {
                                <small>(DeviceRow::dashboard_details(dashboard, now))</small>
                            }
                            <small>
                                "signed in "
                                time(at: row.authenticated_at, precision: Precision::Day)
                            </small>
                        </div>
                        if !row.current {
                            change_form(
                                action: page,
                                change: DeviceChange::SignOut { id: row.id },
                                label: "Sign out",
                                class: "secondary small",
                                aria_label: format!("Sign out {name}"),
                            )
                        }
                    </li>
                }
            </ul>
            if !others {
                <p class="empty">"You’re only signed in on this device."</p>
            }
        </section>
        known_devices(known: known)
    })
}
