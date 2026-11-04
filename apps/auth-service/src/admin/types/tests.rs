//! Invitation lifetime parsing and reason bounds.
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
