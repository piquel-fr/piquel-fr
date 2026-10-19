//! Validated admin inputs.

use super::AdminError;
use chrono::Duration;
use std::str::FromStr;
use thiserror::Error;

/// Largest accepted invitation lifetime number; the suffix chooses hours or days.
const MAX_INVITE_EXPIRY: i64 = 365;
/// Invitation lifetime when none is given.
const DEFAULT_INVITE_EXPIRY_DAYS: i64 = 7;
/// Shared explanation for invalid invitation lifetimes.
const INVITE_EXPIRY_HELP: &str = "expiry must be 1 to 365 followed by h or d, e.g. 24h or 7d";
/// Maximum Unicode characters in an administrator's reason.
const MAX_REASON_CHARS: usize = 500;

/// An invitation lifetime of 1 to 365 hours or days, written like `24h` or `7d`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InviteExpiry(Duration);

/// Why an invitation lifetime was rejected.
#[derive(Debug, Error)]
pub enum InvalidInviteExpiry {
    /// The unit, value or bounds violate the supported hours/days syntax.
    #[error("{INVITE_EXPIRY_HELP}")]
    Format,
    /// The numeric portion could not be parsed.
    #[error("{INVITE_EXPIRY_HELP}")]
    Number(#[from] std::num::ParseIntError),
}

impl InviteExpiry {
    /// The lifetime as a duration.
    pub(super) const fn duration(self) -> Duration {
        self.0
    }
}

impl Default for InviteExpiry {
    /// Seven days.
    fn default() -> Self {
        Self(Duration::days(DEFAULT_INVITE_EXPIRY_DAYS))
    }
}

impl FromStr for InviteExpiry {
    type Err = InvalidInviteExpiry;
    /// Parses a bounded hours/days lifetime while retaining numeric syntax errors.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (number, unit) = value
            .char_indices()
            .last()
            .map(|(index, _)| value.split_at(index))
            .ok_or(InvalidInviteExpiry::Format)?;
        let number = number.parse::<i64>()?;
        if !(1..=MAX_INVITE_EXPIRY).contains(&number) {
            return Err(InvalidInviteExpiry::Format);
        }
        match unit {
            "h" => Ok(Self(Duration::hours(number))),
            "d" => Ok(Self(Duration::days(number))),
            _ => Err(InvalidInviteExpiry::Format),
        }
    }
}

/// Why an administrator acted: 1 to 500 characters, not blank, no control characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason(String);

impl Reason {
    /// Accepts `value` unchanged if it satisfies the rule.
    ///
    /// # Errors
    /// [`AdminError::InvalidReason`] when it does not.
    pub fn parse(value: String) -> Result<Self, AdminError> {
        if value.trim().is_empty()
            || value.chars().count() > MAX_REASON_CHARS
            || value.chars().any(char::is_control)
        {
            return Err(AdminError::InvalidReason);
        }
        Ok(Self(value))
    }

    /// Unwraps the validated text.
    pub(super) fn into_inner(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    //! Invitation lifetime parsing and reason bounds.
    use super::*;

    /// Invitation lifetimes accept bounded hours and days and reject malformed input.
    #[test]
    fn invite_expiry_accepts_bounded_hours_and_days() {
        assert_eq!(
            "24h"
                .parse::<InviteExpiry>()
                .map(InviteExpiry::duration)
                .ok(),
            Some(Duration::hours(24))
        );
        assert_eq!(
            "365d"
                .parse::<InviteExpiry>()
                .map(InviteExpiry::duration)
                .ok(),
            Some(Duration::days(365))
        );
        for invalid in ["", "d", "0d", "366d", "-1h", "7w", "7 d", "é"] {
            assert!(invalid.parse::<InviteExpiry>().is_err(), "{invalid}");
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
}
