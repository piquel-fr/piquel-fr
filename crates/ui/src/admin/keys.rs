//! The keys signing tokens.

use super::{Action, Change, confirm, dashboard_change, moment};
use crate::{clients::choice, layout::page_head};
use chrono::{DateTime, Utc};
use sourceorigin_common::admin::{SigningKey, SigningKeyState};
use topcoat::{
    Result,
    view::{View, class, component, view},
};

/// A signing key, and the change revoking it.
#[derive(Clone, Debug)]
pub struct SigningKeyRow<'a> {
    /// The key.
    pub key: &'a SigningKey,
    /// Revoking it.
    pub revoke: Action,
}

/// A key's state, as a badge's tone and label.
const fn state_badge(state: SigningKeyState) -> (&'static str, &'static str) {
    match state {
        SigningKeyState::Next => ("", "Waiting"),
        SigningKeyState::Active => ("ok", "Signing"),
        SigningKeyState::Retiring => ("neutral", "Retiring"),
        SigningKeyState::Retired => ("neutral", "Retired"),
    }
}

/// Every signing key, oldest first, `rows`, with the page rotating them at
/// `rotate`.
#[component]
pub async fn signing_key_list<'a>(
    rows: &'a [SigningKeyRow<'a>],
    rotate: &'a str,
) -> Result<impl View> {
    Ok(view! {
        page_head(
            title: "Signing keys",
            lead: "The keys that sign tokens. A new key waits a day before it signs, so verifiers have it first, signs for 90 days, then stays published while its tokens may be valid. Every replica picks up a change within a minute.".to_owned(),
            actions: view! { <a data-confirm-first="" class="button" href=(rotate)>"Rotate"</a> },
        )
        <section class="card">
            if rows.is_empty() {
                <p class="empty">"No signing key yet: auth generates one when it starts."</p>
            } else {
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>"key"</th>
                                <th>"state"</th>
                                <th>"created"</th>
                                <th>"signed from"</th>
                                <th>"signed until"</th>
                                <th>"retired"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            for row in rows {
                                let key = row.key;
                                let (tone, label) = state_badge(key.state);
                                <tr>
                                    <td><code>(key.id.as_str())</code> " " <small class="muted">(key.key_type.as_str())</small></td>
                                    <td><span class=(class!("badge", tone))>(label)</span></td>
                                    <td>moment(at: key.created_at)</td>
                                    <td>when(at: key.activated_at)</td>
                                    <td>when(at: key.deactivated_at)</td>
                                    <td>when(at: key.retired_at)</td>
                                    <td class="right">
                                        confirm(action: &row.revoke, change: Change::RevokeSigningKey, subject: key.id.as_str())
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            }
        </section>
        <p class="help">"Importing the deployment's PEM key, into an empty key set, stays at the terminal: auth-service keys import."</p>
    })
}

/// A moment, or a dash before it happens.
#[component]
async fn when(#[into] at: Option<DateTime<Utc>>) -> Result<impl View> {
    Ok(view! {
        match at {
            Some(at) => moment(at: at),
            None => <span class="muted">"—"</span>,
        }
    })
}

/// The page rotating the signing key, with why the last attempt was `refused`,
/// if it was, and whether it asked for the new key to sign `now`; it goes back
/// to `back`.
#[component]
pub async fn signing_key_rotation<'a>(
    back: &'a str,
    #[into]
    #[default]
    refused: Option<&'a str>,
    now: bool,
) -> Result<impl View> {
    Ok(view! {
        dashboard_change(
            change: Change::RotateSigningKey,
            back: back,
            refusal: refused,
            choice(
                name: "now",
                checked: now,
                label: view! { "Sign with it at once" },
                detail: view! { "Skips the day of waiting: verifiers that cached the key set reject its tokens until they fetch it again, for up to an hour. For when the signing key must stop signing now; to stop trusting it, revoke it." },
            )
        )
    })
}
