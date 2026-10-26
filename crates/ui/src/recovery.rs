//! Account recovery: the pages a recovery's links open, and what the account's
//! pages ask of a recovery that can still be undone.
//!
//! Both links carry what they name in their fragment, which never reaches a
//! server, so each page starts with a form posting it. No page names the
//! recovery's passkey: whoever used the link can rename it.

use crate::{
    Notice, Title,
    form::{Ceremony, Fields, Precision, fragment_form, new_passkey, passkey_form, time},
    intro,
};
use chrono::{DateTime, Utc};
use piquel_common::{PasskeyId, RecoveryId, SessionId};
use serde::{Deserialize, Serialize};
use topcoat::{
    Result,
    view::{View, component, view},
};

/// Above the title of each recovery page.
const EYEBROW: &str = "Your Piquel account";

/// Why a recovery link's form stays disabled without scripts.
const NEEDS_SCRIPTS: &str = "Opening this link needs scripts allowed.";

/// An account's recovery that can still be undone, as its pages show it. Its
/// passkey has no name: pages name the recovery's passkey by ID and enrollment
/// time only, since whoever used the link can rename it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The recovery, which undoing it names.
    pub id: RecoveryId,
    /// When Piquel support started it.
    pub started_at: DateTime<Utc>,
    /// Where it stands.
    pub stage: RecoveryStage,
    /// Whether a passkey from before it can undo it; otherwise only support can.
    pub undoable: bool,
}

/// Where a recovery that can still be undone stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStage {
    /// Its link works; undoing it cancels the link.
    Open {
        /// When the link stops working.
        expires_at: DateTime<Utc>,
    },
    /// Its link added a passkey, which confirms nothing until it settles.
    Probation {
        /// When the link added the passkey.
        completed_at: DateTime<Utc>,
        /// When the probation ends, and with it the undo.
        settles_at: DateTime<Utc>,
        /// The passkey, while the account still has it.
        passkey: Option<RecoveryPasskey>,
    },
}

/// The passkey a recovery added: its ID and when, never its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPasskey {
    /// The passkey.
    pub id: PasskeyId,
    /// When the link added it.
    pub created_at: DateTime<Utc>,
}

impl RecoveryPasskey {
    /// What the pages call it in place of its name, which whoever used the link
    /// chose, within a sentence.
    pub(crate) const NAME: &str = "the recovery's passkey";
    /// [`Self::NAME`], starting a sentence or a label.
    pub(crate) const TITLE: &str = "The recovery's passkey";
}

impl Recovery {
    /// The key under which the browser keeps that `session` answered "yes" to
    /// what the account's pages ask of the recovery. A session only ever sees one
    /// recovery, since starting one signs every session out. The key names the
    /// stage, so a "yes" while the link is unused still asks again once it is
    /// used, and whether a passkey `confirmed` the session, which a recovery's
    /// passkey never does, so a "yes" from whoever used the link still asks the
    /// owner once their older passkey signs in to that session.
    fn dismiss_key(&self, session: SessionId, confirmed: bool) -> String {
        let stage = match self.stage {
            RecoveryStage::Open { .. } => "open",
            RecoveryStage::Probation { .. } => "probation",
        };
        let by = if confirmed {
            "confirmed"
        } else {
            "unconfirmed"
        };
        format!("piquel-recovery:{session}:{stage}:{by}")
    }

    /// The passkey it added, while in probation and the account still has it.
    pub(crate) const fn passkey(&self) -> Option<PasskeyId> {
        match self.stage {
            RecoveryStage::Probation {
                passkey: Some(passkey),
                ..
            } => Some(passkey.id),
            RecoveryStage::Open { .. } | RecoveryStage::Probation { passkey: None, .. } => None,
        }
    }

    /// Whether it keeps the passkey `id` from being removed: while it can be undone,
    /// every passkey but its own stays, so nobody takes the owner's undo away.
    pub(crate) fn keeps(&self, id: PasskeyId) -> bool {
        self.passkey() != Some(id)
    }

    /// The link to it on the undo page at `page`, which names it in the fragment
    /// as the undo emails do. `page` is a path, so the link stays on auth.
    fn undo_href(&self, page: &str) -> String {
        format!("{page}#recovery={}", self.id)
    }

    /// What the account's pages ask of it.
    fn question(&self) -> String {
        match self.stage {
            RecoveryStage::Open { .. } => format!(
                "Piquel support started a recovery of your account on {}. Was this you?",
                Precision::Day.write(self.started_at)
            ),
            RecoveryStage::Probation { completed_at, .. } => format!(
                "Your account was recovered on {}. Was this you?",
                Precision::Day.write(completed_at)
            ),
        }
    }

    /// The label of the link to undo it, answering [`Self::question`] no.
    const fn refusal(&self) -> &'static str {
        match self.stage {
            RecoveryStage::Open { .. } => "No, cancel it",
            RecoveryStage::Probation { .. } => "No, undo it",
        }
    }
}

/// A change a recovery link's page posts, named by its `action` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RecoverChange {
    /// Opens the link: the page names the account it recovers and asks for a
    /// passkey.
    Open {
        /// The link's token, which the form fills in from the link's fragment.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        token: String,
    },
    /// Shows that the passkey script just added the passkey, which signed the
    /// browser in: this changes nothing.
    Recovered {},
}

/// A change a recovery's undo page posts, named by its `action` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum UndoChange {
    /// Opens the link: the page says what undoing the recovery takes back.
    Open {
        /// The recovery, which the form fills in from the link's fragment; absent
        /// when the fragment names none.
        #[serde(
            default,
            deserialize_with = "Fields::lenient",
            skip_serializing_if = "Option::is_none"
        )]
        recovery: Option<RecoveryId>,
    },
    /// Shows that the passkey script just undid the recovery, cancelling its link
    /// and taking back what the link did, if it was used: this changes nothing.
    Undone {
        /// Whether the undo signed the browser in, as its finish answered, which
        /// the passkey script fills in. An undo on a disabled account signs nobody
        /// in.
        #[serde(default, deserialize_with = "Fields::lenient_or_default")]
        signed_in: bool,
    },
}

/// What a recovery link's page asks of the browser.
#[derive(Clone, Copy, Debug)]
pub enum RecoverStep<'a> {
    /// Opening the link, whose form posts its token.
    Open,
    /// Adding a passkey to the account the link recovers.
    Enroll {
        /// The account's handle.
        username: &'a str,
        /// The account's display name.
        display_name: &'a str,
        /// When the link stops working.
        expires_at: DateTime<Utc>,
        /// The link's token, which the passkey script starts the ceremony with.
        token: &'a str,
        /// How many days the new passkey can't confirm changes, and the recovery
        /// can be undone.
        probation_days: i64,
        /// Whether the browser runs Android, which may save the passkey with Google
        /// Password Manager.
        android: bool,
    },
}

/// A recovery link's page, at `action`, asking the browser for `step`. Its forms
/// post to `action`, and `alert` says why the link's form was refused. Once it
/// asks for a passkey, the page's address goes back to `action`, so reloading it
/// never posts the link's form again.
#[component]
pub async fn recover<'a>(
    action: &'a str,
    step: RecoverStep<'a>,
    #[default] alert: Option<&'a str>,
) -> Result<impl View> {
    let title = match step {
        RecoverStep::Open => Title::Recover.as_str().to_owned(),
        RecoverStep::Enroll {
            username,
            display_name,
            ..
        } => format!("Add a passkey to @{username} ({display_name})"),
    };
    Ok(view! {
        <section class="auth-shell stack">
            intro(eyebrow: EYEBROW, title: title)
            match step {
                RecoverStep::Open => fragment_form(
                    action: action,
                    change: RecoverChange::Open { token: String::new() },
                    fragments: &["token"],
                    label: "Continue",
                    unavailable: NEEDS_SCRIPTS,
                    alert: alert,
                    alert_replaces_missing: true,
                    missing: view! { incomplete() },
                ),
                RecoverStep::Enroll { expires_at, token, probation_days, android, .. } => {
                    <div class="stack" data-replace-url=(action)>
                        <p>"This link works until " time(at: expires_at, precision: Precision::Minute) "."</p>
                        <p class="notice">
                            (format!(
                                "For the next {probation_days} days, this passkey signs you in but can't confirm changes to your security settings, and the recovery can still be undone."
                            ))
                        </p>
                        passkey_form(
                            action: action,
                            ceremony: Ceremony::Recover { token },
                            change: RecoverChange::Recovered {},
                            label: "Create a passkey",
                            class: "full",
                            new_passkey(label: "Passkey name", android: android)
                        )
                    </div>
                }
            }
        </section>
    })
}

/// What a recovery's undo page asks of the browser.
#[derive(Clone, Copy, Debug)]
pub enum UndoStep<'a> {
    /// Opening the link, whose form posts the recovery's ID.
    Open {
        /// The recovery of the account the browser is signed in to, if any, and
        /// the account's handle: the page offers to undo it when the link names no
        /// recovery.
        signed_in: Option<(&'a Recovery, &'a str)>,
    },
    /// Undoing `recovery`, with a passkey from before it.
    Undo {
        /// The recovery.
        recovery: &'a Recovery,
        /// The account's handle, which the page names it by; without one, the page
        /// says "your account".
        handle: Option<&'a str>,
    },
    /// Nothing to undo: the link names no recovery that can still be undone.
    Nothing,
    /// The recovery is undone, and the undo signed nobody in, as on a disabled
    /// account.
    Done,
}

/// A recovery's undo page, at `action`, asking the browser for `step`. Its forms
/// post to `action`, and `alert` says why the link's form was refused.
#[component]
pub async fn undo_recovery<'a>(
    action: &'a str,
    step: UndoStep<'a>,
    #[default] alert: Option<&'a str>,
) -> Result<impl View> {
    Ok(view! {
        <section class="auth-shell stack">
            intro(eyebrow: EYEBROW, title: Title::UndoRecovery.as_str())
            match step {
                UndoStep::Open { signed_in } => fragment_form(
                    action: action,
                    change: UndoChange::Open { recovery: None },
                    fragments: &["recovery"],
                    label: "Continue",
                    unavailable: NEEDS_SCRIPTS,
                    alert: alert,
                    alert_replaces_missing: true,
                    // A link that names a recovery wins over the account's own.
                    missing: view! {
                        match signed_in {
                            Some((recovery, handle)) => undoing(action: action, recovery: recovery, handle: Some(handle)),
                            None => incomplete(),
                        }
                    },
                ),
                UndoStep::Undo { recovery, handle } => {
                    <div class="card stack">
                        undoing(action: action, recovery: recovery, handle: handle)
                    </div>
                }
                UndoStep::Nothing => {
                    <div class="card stack">
                        <h2>"There's nothing to undo"</h2>
                        <p>"The recovery was undone or cancelled, or has settled, or this link is wrong."</p>
                    </div>
                }
                UndoStep::Done => {
                    <div class="card stack">
                        <p role="status">(Notice::RecoveryUndone.message())</p>
                        <p>"Your account is disabled, so you're not signed in. Contact Piquel support to enable it."</p>
                    </div>
                }
            }
        </section>
    })
}

/// Undoing `recovery` of the account `handle` names, or of "your account", by
/// posting to `action` once the passkey script ran its ceremony with a passkey from
/// before it. Without one, only support can.
#[component]
async fn undoing<'a>(
    action: &'a str,
    recovery: &'a Recovery,
    handle: Option<&'a str>,
) -> Result<impl View> {
    let account = handle.map_or_else(|| "your account".to_owned(), |handle| format!("@{handle}"));
    let (title, label) = match recovery.stage {
        RecoveryStage::Open { .. } => ("Cancel this recovery?", "Cancel it with a passkey"),
        RecoveryStage::Probation { .. } => ("Undo this recovery?", "Undo it with a passkey"),
    };
    Ok(view! {
        <h2>(title)</h2>
        match recovery.stage {
            RecoveryStage::Open { expires_at } => {
                <p>
                    (format!("Piquel support started a recovery of {account} on "))
                    time(at: recovery.started_at, precision: Precision::Minute)
                    ". Its link works until "
                    time(at: expires_at, precision: Precision::Minute)
                    "."
                </p>
                <p>
                    "The recovery link stops working. If the link is used before you cancel, cancelling takes back what it did too: its passkey, every device and every app's access."
                </p>
            }
            RecoveryStage::Probation { completed_at, settles_at, passkey } => {
                <p>
                    "On "
                    time(at: completed_at, precision: Precision::Minute)
                    (format!(", a recovery link added a passkey to {account}. It can be undone until "))
                    time(at: settles_at, precision: Precision::Minute)
                    "."
                </p>
                <p>"Undoing it takes back:"</p>
                <ul>
                    if let Some(passkey) = passkey {
                        <li>
                            "The passkey the recovery added on "
                            time(at: passkey.created_at, precision: Precision::Minute)
                            (format!(", ID {}", passkey.id))
                        </li>
                    }
                    <li>"Every signed-in device"</li>
                    <li>"Every app's access. Apps ask for it again."</li>
                </ul>
            }
        }
        if recovery.undoable {
            passkey_form(
                action: action,
                ceremony: Ceremony::Undo { recovery: recovery.id },
                // Whatever the stage was, the page says only that it is undone.
                change: UndoChange::Undone { signed_in: false },
                label: label,
                class: "full",
            )
        } else {
            <p class="notice">"You have no passkey from before this recovery, so only Piquel support can undo it."</p>
        }
    })
}

/// What a recovery's page shows when its link lacks what it names.
#[component]
async fn incomplete() -> Result<impl View> {
    Ok(view! {
        <h2>"This link is incomplete"</h2>
        <p>"Open it again from the email, or ask Piquel support for a new one."</p>
    })
}

/// What the account's pages ask of its `recovery` that can still be undone, until
/// `session` answers: whether it was the owner's, which the passkey script shows
/// unless this browser already said yes to it at this stage, and since a passkey
/// `confirmed` the session, if one did, with a link to undo it on the undo page,
/// `undo`. In probation, a notice, shown without scripts, says what the recovery
/// holds back meanwhile, and who can undo it.
#[component]
pub async fn recovery_banner<'a>(
    recovery: &'a Recovery,
    session: SessionId,
    confirmed: bool,
    undo: &'a str,
) -> Result<impl View> {
    let key = recovery.dismiss_key(session, confirmed);
    let href = recovery.undo_href(undo);
    Ok(view! {
        <section class="notice stack" data-dismiss=(key.as_str()) hidden="">
            <p>(recovery.question())</p>
            <div class="row">
                <button type="button" class="secondary" data-dismisses=(key.as_str())>"Yes, it was me"</button>
                <a href=(href.as_str())>(recovery.refusal())</a>
            </div>
        </section>
        if let RecoveryStage::Probation { settles_at, .. } = recovery.stage {
            <p class="notice">
                "Until "
                time(at: settles_at, precision: Precision::Day)
                ", the passkey the recovery added signs in but can't confirm changes to your security settings. "
                if recovery.undoable {
                    "To make them now, confirm with a passkey you had before."
                } else {
                    "Only Piquel support can undo the recovery."
                }
            </p>
        }
    })
}

/// What a sign-in asks of the account's `recovery` that can still be undone,
/// before it goes on to an app: whether it was the owner's, going on at
/// `continue_href` if so, or to undo it on the undo page, `undo`. The answer is
/// not kept, so the account's pages still ask.
#[component]
pub async fn recovery_prompt<'a>(
    recovery: &'a Recovery,
    continue_href: &'a str,
    undo: &'a str,
) -> Result<impl View> {
    let href = recovery.undo_href(undo);
    Ok(view! {
        <section class="auth-shell stack">
            intro(eyebrow: EYEBROW, title: recovery.question())
            <a class="button" href=(continue_href)>"Yes, continue"</a>
            <a href=(href.as_str())>(recovery.refusal())</a>
        </section>
    })
}

#[cfg(test)]
mod tests {
    //! The recovery pages' changes.
    use super::*;

    /// The link forms send what the fragment fills in only as its own input, and a
    /// recovery ID the fragment gets wrong reads as absent. An undo's outcome reads
    /// as signing nobody in unless it says otherwise.
    #[test]
    fn link_forms_leave_their_values_to_the_fragment() {
        let fields = |change: Fields| serde_urlencoded::to_string(change).expect("fields");
        assert_eq!(
            fields(
                RecoverChange::Open {
                    token: String::new()
                }
                .into()
            ),
            "action=open"
        );
        assert_eq!(
            fields(UndoChange::Open { recovery: None }.into()),
            "action=open"
        );
        let id = RecoveryId::new();
        for (form, expected) in [
            (format!("action=open&recovery={id}"), Some(id)),
            ("action=open&recovery=".to_owned(), None),
            ("action=open&recovery=nope".to_owned(), None),
            ("action=open".to_owned(), None),
        ] {
            let change: UndoChange = serde_urlencoded::from_str(&form).expect("change");
            assert!(
                matches!(change, UndoChange::Open { recovery } if recovery == expected),
                "{form}"
            );
        }
        let token: RecoverChange = serde_urlencoded::from_str("action=open").expect("change");
        assert!(matches!(token, RecoverChange::Open { token } if token.is_empty()));
        for (form, expected) in [
            ("action=undone&signed_in=true", true),
            ("action=undone&signed_in=false", false),
            ("action=undone&signed_in=nope", false),
            ("action=undone", false),
        ] {
            let change: UndoChange = serde_urlencoded::from_str(form).expect("change");
            assert!(
                matches!(change, UndoChange::Undone { signed_in } if signed_in == expected),
                "{form}"
            );
        }
    }

    /// A "yes" holds for one session at one stage, and only until a passkey first
    /// confirms the session.
    #[test]
    fn answers_hold_per_session_stage_and_confirmation() {
        let at = DateTime::<Utc>::UNIX_EPOCH;
        let open = Recovery {
            id: RecoveryId::new(),
            started_at: at,
            stage: RecoveryStage::Open { expires_at: at },
            undoable: true,
        };
        let probation = Recovery {
            stage: RecoveryStage::Probation {
                completed_at: at,
                settles_at: at,
                passkey: None,
            },
            ..open
        };
        let session = SessionId::new();
        let keys = [
            open.dismiss_key(session, false),
            open.dismiss_key(session, true),
            probation.dismiss_key(session, false),
            probation.dismiss_key(session, true),
            open.dismiss_key(SessionId::new(), false),
        ];
        let distinct: std::collections::BTreeSet<_> = keys.iter().collect();
        assert_eq!(distinct.len(), keys.len(), "{keys:?}");
    }
}
