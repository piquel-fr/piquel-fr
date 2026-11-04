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
