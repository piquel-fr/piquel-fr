//! An account's recent recoveries, which the pages starting and undoing one list
//! first, as the CLI does.

use super::moment;
use chrono::{DateTime, Utc};
use piquel_common::PasskeyId;
use topcoat::{
    Result,
    view::{View, component, view},
};

/// Where a recovery stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStanding {
    /// Its link works, and was not used yet.
    Unused,
    /// Its link was used: its passkey signs in, confirms no change, and the
    /// recovery can be undone until `settles_at`.
    Probation {
        /// When the probation ends.
        settles_at: DateTime<Utc>,
    },
    /// Its probation ended.
    Settled,
    /// It was undone, after its link was used.
    Undone(DateTime<Utc>),
    /// It was cancelled before its link was used.
    Cancelled(DateTime<Utc>),
    /// Its link expired unused.
    Expired,
}

/// The passkey a recovery's link enrolled, named by its ID and when it was
/// enrolled, never by its label, which whoever used the link may have changed to
/// pass it off as one of the owner's.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryKey {
    /// The passkey.
    pub id: PasskeyId,
    /// When the link enrolled it.
    pub enrolled_at: DateTime<Utc>,
    /// Whether it is still active.
    pub active: bool,
}

/// One of an account's recent recoveries.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryRow {
    /// When it started.
    pub started_at: DateTime<Utc>,
    /// Where it stands.
    pub standing: RecoveryStanding,
    /// The passkey its link enrolled, if it did.
    pub passkey: Option<RecoveryKey>,
}

/// An account's recoveries of the last 15 days, newest first.
#[component]
pub async fn recovery_list<'a>(rows: &'a [RecoveryRow]) -> Result<impl View> {
    Ok(view! {
        if rows.is_empty() {
            <p class="empty">"No recovery in the last 15 days."</p>
        } else {
            <table>
                <thead>
                    <tr><th>"Started"</th><th>"State"</th><th>"Passkey"</th></tr>
                </thead>
                <tbody>
                    for row in rows {
                        <tr>
                            <td>moment(at: row.started_at)</td>
                            <td>
                                match row.standing {
                                    RecoveryStanding::Unused => "Link sent, not used",
                                    RecoveryStanding::Probation { settles_at } => {
                                        "In probation until " moment(at: settles_at)
                                    },
                                    RecoveryStanding::Settled => "Settled",
                                    RecoveryStanding::Undone(at) => { "Undone " moment(at: at) },
                                    RecoveryStanding::Cancelled(at) => { "Cancelled " moment(at: at) },
                                    RecoveryStanding::Expired => "Link expired",
                                }
                            </td>
                            <td>
                                match row.passkey {
                                    Some(passkey) => {
                                        <code>(passkey.id.to_string())</code>
                                        ", enrolled " moment(at: passkey.enrolled_at)
                                        if !passkey.active { ", removed" }
                                    },
                                    None => "None",
                                }
                            </td>
                        </tr>
                    }
                </tbody>
            </table>
        }
    })
}
