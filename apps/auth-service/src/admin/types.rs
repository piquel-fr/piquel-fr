//! Validated admin inputs.

use super::AdminError;
use chrono::Duration;
use piquel_common::{Handle, HandleError, UserId};
use serde::Deserialize;
use std::{fmt, str::FromStr};
use thiserror::Error;

/// An account whose current handle the handle rules refuse, as `handle check`
/// lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleProblem {
    /// The account.
    pub user_id: UserId,
    /// Its current handle.
    pub handle: Handle,
    /// Why the rules refuse it.
    pub error: HandleError,
}

/// Maximum Unicode characters in an administrator's reason.
const MAX_REASON_CHARS: usize = 500;

/// Minutes in an hour, for lifetimes.
const MINUTES_PER_HOUR: i64 = 60;
/// Minutes in a day, for lifetimes.
const MINUTES_PER_DAY: i64 = 24 * MINUTES_PER_HOUR;
/// Invitation lifetime when none is given: seven days.
const DEFAULT_INVITE_EXPIRY: i64 = 7 * MINUTES_PER_DAY;
/// Grace period of a rotation when none is given: a day.
const DEFAULT_GRACE_PERIOD: i64 = MINUTES_PER_DAY;

/// A whole number of minutes, written in its largest whole unit, e.g. `365d`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Minutes(i64);

impl fmt::Display for Minutes {
    /// Writes `0`, or the number of days, hours or minutes with its unit.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => formatter.write_str("0"),
            minutes if minutes % MINUTES_PER_DAY == 0 => {
                write!(formatter, "{}d", minutes / MINUTES_PER_DAY)
            }
            minutes if minutes % MINUTES_PER_HOUR == 0 => {
                write!(formatter, "{}h", minutes / MINUTES_PER_HOUR)
            }
            minutes => write!(formatter, "{minutes}m"),
        }
    }
}

/// A lifetime written as a whole number of minutes, hours or days, such as `30m`,
/// `24h` or `7d`, or `0`. It lies between `MIN` and `MAX` minutes. JSON bodies
/// write it the same way, as a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Lifetime<const MIN: i64, const MAX: i64>(Minutes);

/// How long a signup link stays valid: 1 hour to 365 days.
pub type InviteExpiry = Lifetime<MINUTES_PER_HOUR, { 365 * MINUTES_PER_DAY }>;
/// How long a client's earlier secrets keep working after a rotation: up to 30 days.
pub type GracePeriod = Lifetime<0, { 30 * MINUTES_PER_DAY }>;

/// A lifetime that is malformed or out of bounds.
#[derive(Debug, Error)]
#[error("must be a whole number followed by m, h or d, from {min} to {max}, e.g. 24h")]
pub struct InvalidLifetime {
    /// The shortest lifetime allowed.
    min: Minutes,
    /// The longest lifetime allowed.
    max: Minutes,
    /// Why the number did not parse, when it did not.
    #[source]
    source: Option<std::num::ParseIntError>,
}

impl<const MIN: i64, const MAX: i64> Lifetime<MIN, MAX> {
    /// The lifetime as a duration.
    #[must_use]
    pub const fn duration(self) -> Duration {
        Duration::minutes(self.0.0)
    }
}

impl Default for InviteExpiry {
    /// Seven days.
    fn default() -> Self {
        Self(Minutes(DEFAULT_INVITE_EXPIRY))
    }
}

impl Default for GracePeriod {
    /// A day.
    fn default() -> Self {
        Self(Minutes(DEFAULT_GRACE_PERIOD))
    }
}

impl<const MIN: i64, const MAX: i64> TryFrom<String> for Lifetime<MIN, MAX> {
    type Error = InvalidLifetime;
    /// Parses owned text, as serde reads it.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl<const MIN: i64, const MAX: i64> FromStr for Lifetime<MIN, MAX> {
    type Err = InvalidLifetime;
    /// Parses `0` or a number and unit, keeping the number's parse error.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = |source| InvalidLifetime {
            min: Minutes(MIN),
            max: Minutes(MAX),
            source,
        };
        let minutes = if value == "0" {
            0
        } else {
            let (number, unit) = value
                .char_indices()
                .last()
                .map(|(index, _)| value.split_at(index))
                .ok_or_else(|| invalid(None))?;
            let number = number
                .parse::<i64>()
                .map_err(|error| invalid(Some(error)))?;
            let scale = match unit {
                "m" => 1,
                "h" => MINUTES_PER_HOUR,
                "d" => MINUTES_PER_DAY,
                _ => return Err(invalid(None)),
            };
            number.checked_mul(scale).ok_or_else(|| invalid(None))?
        };
        if !(MIN..=MAX).contains(&minutes) {
            return Err(invalid(None));
        }
        Ok(Self(Minutes(minutes)))
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
