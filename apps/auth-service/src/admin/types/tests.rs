//! Invitation lifetime parsing, reason bounds and announcement drafts.
use super::*;

/// Lifetimes accept a bounded number of minutes, hours or days and reject
/// malformed input, naming their bounds.
#[test]
fn lifetimes_accept_bounded_minutes_hours_and_days() {
    for (value, duration) in [("24h", Duration::hours(24)), ("365d", Duration::days(365))] {
        assert_eq!(
            value
                .parse::<InviteExpiry>()
                .map(InviteExpiry::duration)
                .ok(),
            Some(duration)
        );
    }
    for invalid in ["", "0", "d", "0d", "366d", "-1h", "7w", "7 d", "é"] {
        assert!(invalid.parse::<InviteExpiry>().is_err(), "{invalid}");
    }
    for (value, duration) in [("0", Duration::zero()), ("90m", Duration::minutes(90))] {
        assert_eq!(
            value.parse::<GracePeriod>().map(GracePeriod::duration).ok(),
            Some(duration)
        );
    }
    assert_eq!(
        "31d"
            .parse::<GracePeriod>()
            .expect_err("too long")
            .to_string(),
        "must be a whole number followed by m, h or d, from 0 to 30d, e.g. 24h"
    );
}

/// Each choice of the rotation form is the grace period it is written as.
#[test]
fn rotation_choices_are_the_periods_they_name() {
    for grace in Grace::ALL {
        assert_eq!(
            Ok(GracePeriod::from(grace)),
            grace
                .as_str()
                .parse::<GracePeriod>()
                .map_err(|error| error.to_string()),
            "{grace}"
        );
    }
}

/// A letter's subject is one line, and its text keeps its line breaks as `\n`;
/// both are trimmed and bounded.
#[test]
fn letters_are_bounded_text() {
    let letter = Letter::new(" Incident ", "\r\nFirst.\r\n\r\n\tSecond.\n").expect("a letter");
    assert_eq!(
        (letter.subject.as_str(), letter.body.as_str()),
        ("Incident", "First.\n\n\tSecond.")
    );
    for subject in ["", "  ", "Two\nlines", &"é".repeat(151)] {
        assert!(matches!(
            Letter::new(subject, "Text"),
            Err(AdminError::InvalidSubject)
        ));
    }
    for body in ["", " \n ", "Bell\u{7}", &"é".repeat(20_001)] {
        assert!(matches!(
            Letter::new("Incident", body),
            Err(AdminError::InvalidBody)
        ));
    }
}

/// An announcement goes to everyone, or to 1 to 1,000 chosen accounts.
#[test]
fn announcements_go_to_bounded_accounts() {
    let draft = |count| {
        let letter = Letter::new("Incident", "Text").expect("a letter");
        let recipients =
            AnnouncementRecipients::Accounts(vec![UserRef::Handle("ada".into()); count]);
        AnnouncementDraft::new(letter, recipients, false)
    };
    assert!(draft(1_000).is_ok());
    assert!(matches!(draft(0), Err(AdminError::NoRecipients)));
    assert!(matches!(draft(1_001), Err(AdminError::TooManyRecipients)));
}

/// The form lists one account per line, by handle, `@handle` as the dashboard
/// writes it, verified email or ID.
#[test]
fn the_form_names_one_account_per_line() {
    let id = UserId::new();
    let form = DraftAnnouncement {
        subject: "Incident".into(),
        body: "Text".into(),
        audience: AnnouncementAudience::Accounts,
        accounts: format!("ada\r\n\r\n  grace@example.com \n{id}\n@lin\n"),
        ..DraftAnnouncement::default()
    };
    let draft = AnnouncementDraft::try_from(&form).expect("a draft");
    assert_eq!(
        draft.recipients,
        AnnouncementRecipients::Accounts(vec![
            UserRef::Handle("ada".into()),
            UserRef::Email("grace@example.com".into()),
            UserRef::Id(id),
            UserRef::Handle("lin".into()),
        ])
    );
}

/// Reasons count Unicode characters and reject blank or control input.
#[test]
fn reasons_are_bounded_visible_text() {
    for valid in ["Spam".to_owned(), "é".repeat(500)] {
        assert!(Reason::parse(valid).is_ok());
    }
    for invalid in [String::new(), " \t ".into(), "a\nb".into(), "é".repeat(501)] {
        assert!(matches!(
            Reason::parse(invalid),
            Err(AdminError::InvalidReason)
        ));
    }
}
