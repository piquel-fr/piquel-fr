//! The account at a glance: what is signed in and connected now, what happened
//! lately, and a provider it could still link.

use super::{
    ConnectedAppRow, DeviceRow, HistoryRow, Holdings, ProviderRow, SignInChange,
    timeline::activity_feed,
};
use crate::{
    form::change_form,
    icons::{Icon, icon},
    layout::page_head,
};
use chrono::{DateTime, Utc};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// How many devices the overview lists.
const DEVICES_SHOWN: usize = 4;

/// The pages the overview links.
#[derive(Clone, Copy, Debug)]
pub struct OverviewLinks<'a> {
    /// The sign-in methods, whose form links a provider.
    pub sign_in: &'a str,
    /// The devices.
    pub devices: &'a str,
    /// The security history.
    pub history: &'a str,
}

/// What the overview shows of the account.
#[derive(Clone, Copy, Debug)]
pub struct AccountOverview<'a> {
    /// Every browser and app signed in, most recently active first.
    pub devices: &'a [DeviceRow<'a>],
    /// The apps that keep access to the account.
    pub apps: &'a [ConnectedAppRow<'a>],
    /// How many times apps signed the account in over the last seven days.
    pub app_sign_ins_week: u64,
    /// How many security events the last seven days recorded.
    pub security_events_week: u64,
    /// The newest entries of the security history.
    pub activity: &'a [HistoryRow<'a>],
    /// What the account holds, to name what the entries refer to.
    pub holds: Holdings<'a>,
    /// The social sign-in providers, to offer one not yet linked.
    pub providers: &'a [ProviderRow<'a>],
    /// Now, to say when devices were active.
    pub now: DateTime<Utc>,
}

/// The overview page: the tiles, a provider the account could still link, which
/// the page offers until the browser dismisses it, the newest security activity
/// and the devices signed in, linking the pages in `links`.
#[component]
pub async fn account_overview<'a>(
    overview: AccountOverview<'a>,
    links: OverviewLinks<'a>,
) -> Result<impl View> {
    let devices = overview.devices;
    let (browsers, other) = devices.iter().fold((0, 0), |(browsers, other), device| {
        if device.device.is_some() {
            (browsers + 1, other)
        } else {
            (browsers, other + 1)
        }
    });
    let names: Vec<_> = overview.apps.iter().map(|app| app.name).collect();
    let unlinked: Vec<_> = overview
        .providers
        .iter()
        .filter(|row| row.enabled && row.identity.is_none())
        .collect();
    Ok(view! {
        page_head(title: "Overview", lead: "Your account at a glance.".to_owned())
        <div class="stats">
            <div class="stat">
                <span class="label">"Active sessions"</span>
                <span class="value">(devices.len().to_string())</span>
                <span class="detail">(sessions_detail(browsers, other))</span>
            </div>
            <div class="stat">
                <span class="label">"Connected apps"</span>
                <span class="value">(overview.apps.len().to_string())</span>
                <span class="detail">(if names.is_empty() { "none yet".to_owned() } else { names.join(" · ") })</span>
            </div>
            <div class="stat">
                <span class="label">"App sign-ins, 7 days"</span>
                <span class="value">(overview.app_sign_ins_week.to_string())</span>
                <span class="detail">"through apps you use"</span>
            </div>
            <div class="stat">
                <span class="label">"Security events, 7 days"</span>
                <span class="value">(overview.security_events_week.to_string())</span>
                <span class="detail">"sign-ins and changes"</span>
            </div>
        </div>
        for row in unlinked {
            let key = format!("piquel-link:{}", row.provider.as_str());
            let name = row.provider.name();
            <section class="hint" data-dismiss=(key.as_str()) hidden="">
                icon(kind: Icon::Link)
                <div class="text">
                    <strong>(format!("You can still link {name}"))</strong>
                    <small>(format!("Sign in with a {name} account you already have. Linking never replaces your passkeys."))</small>
                </div>
                change_form(
                    action: links.sign_in,
                    change: SignInChange::Link { provider: row.provider },
                    label: format!("Link {name}"),
                    class: "small",
                )
                <button type="button" class="secondary small" data-dismisses=(key.as_str())>"Not now"</button>
            </section>
        }
        <div class="two side">
            <section class="card" aria-labelledby="activity-heading">
                <header>
                    <h2 id="activity-heading">"Recent security activity"</h2>
                    <a href=(links.history)>"See all history"</a>
                </header>
                if overview.activity.is_empty() {
                    <p class="empty">"Nothing has happened to your account yet."</p>
                } else {
                    activity_feed(rows: overview.activity, holds: &overview.holds)
                }
            </section>
            <section class="card" aria-labelledby="devices-heading">
                <header>
                    <h2 id="devices-heading">"Devices"</h2>
                    <a href=(links.devices)>"Manage"</a>
                </header>
                <ul class="list">
                    for device in devices.iter().take(DEVICES_SHOWN) {
                        <li>
                            <div class="text">
                                <strong>(device.name())</strong>
                                if device.current {
                                    " " <span class="badge ok">"This device"</span>
                                }
                                <small>(device.details(overview.now))</small>
                            </div>
                        </li>
                    }
                </ul>
                if devices.len() > DEVICES_SHOWN {
                    <p class="help">
                        <a href=(links.devices)>(format!("And {} more", devices.len() - DEVICES_SHOWN))</a>
                    </p>
                }
            </section>
        </div>
    })
}

/// How many of the sessions are recorded `browsers`, and how many `other`
/// devices went unrecorded, in words.
fn sessions_detail(browsers: usize, other: usize) -> String {
    let plural =
        |count: usize, word: &str| format!("{count} {word}{}", if count == 1 { "" } else { "s" });
    match (browsers, other) {
        (0, 0) => "none".to_owned(),
        (browsers, 0) => plural(browsers, "browser"),
        (0, other) => plural(other, "unrecorded device"),
        (browsers, other) => format!("{} · {other} unrecorded", plural(browsers, "browser")),
    }
}
