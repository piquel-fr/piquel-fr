//! Signed-in devices.

use super::device_name;
use crate::{
    form::{Precision, change_form, time},
    layout::page_head,
};
use chrono::{DateTime, TimeDelta, Utc};
use piquel_common::{AuthenticationMethod, SessionId, events::UserAgentFamily};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use topcoat::{
    Result,
    context::Cx,
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

    /// When it was last active, as of `now`. Activity is recorded every five minutes
    /// at most, so anything closer is now.
    fn activity(&self, now: DateTime<Utc>) -> String {
        let ago = now - self.last_seen_at;
        if self.current || ago < TimeDelta::minutes(5) {
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

/// The devices page: every browser signed in to the account, as of `now`. Signing
/// one out, or every other one, posts to `page`.
#[component]
pub async fn devices<'a>(
    cx: &Cx,
    page: &'a str,
    rows: &'a [DeviceRow<'a>],
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
        <section class="card" aria-labelledby="sessions-heading">
            <header>
                <h2 id="sessions-heading">"Signed-in devices " <span class="count">(rows.len().to_string())</span></h2>
            </header>
            <ul class="list">
                #[key(position)]
                for (position, row) in rows.into_iter().enumerate() {
                    let name = row.name();
                    <li>
                        <div class="text">
                            <strong>(name.as_str())</strong>
                            if row.current {
                                " " <span class="badge ok">"This device"</span>
                            }
                            <small>(row.details(now))</small>
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
    })
}
