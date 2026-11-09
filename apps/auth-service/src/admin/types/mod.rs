//! Validated admin inputs.

use super::AdminError;
use chrono::Duration;
use serde::Deserialize;
use sourceorigin_common::{
    Handle, HandleError, UserId,
    admin::{AnnouncementAudience, DraftAnnouncement},
};
use sourceorigin_ui::Grace;
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

impl From<Grace> for GracePeriod {
    /// The period the rotation form's choice names.
    fn from(grace: Grace) -> Self {
        Self(Minutes(match grace {
            Grace::Now => 0,
            Grace::Hour => MINUTES_PER_HOUR,
            Grace::Day => MINUTES_PER_DAY,
            Grace::Week => 7 * MINUTES_PER_DAY,
            Grace::Month => 30 * MINUTES_PER_DAY,
        }))
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
    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl FromStr for Reason {
    type Err = AdminError;
    /// Parses a reason given on the command line.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value.to_owned())
    }
}

/// Maximum Unicode characters in an announcement's subject.
const MAX_SUBJECT_CHARS: usize = 150;
/// Maximum Unicode characters in an announcement's text.
const MAX_BODY_CHARS: usize = 20_000;
/// Maximum accounts an announcement is chosen for; more go to everyone.
pub(super) const MAX_CHOSEN_ACCOUNTS: usize = 1_000;

/// An announcement's draft, as an operator writes it: its subject and text, and
/// whom it goes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnouncementDraft {
    /// The email's subject: one line of 1 to 150 characters, trimmed.
    pub(super) subject: String,
    /// Its text: 1 to 20,000 characters, trimmed, with `\n` line breaks and no
    /// other control characters but tabs.
    pub(super) body: String,
    /// Whom it goes to.
    pub(super) recipients: AnnouncementRecipients,
    /// Whether it is emailed to every recipient, whatever their preference.
    pub(super) essential: bool,
}

/// Whom an announcement goes to, as an operator names them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnnouncementRecipients {
    /// Every account, as of its sending.
    Everyone,
    /// The accounts named, at least one and at most 1,000.
    Accounts(Vec<UserRef>),
}

impl AnnouncementDraft {
    /// Checks `subject` and `body`, trimmed, and normalizes the text's line
    /// breaks, which forms post as `\r\n`, to `\n`. An `essential` one is emailed
    /// to every recipient, whatever their preference.
    ///
    /// # Errors
    /// [`AdminError::InvalidSubject`] or [`AdminError::InvalidBody`] when either
    /// breaks its rule, and [`AdminError::NoRecipients`] or
    /// [`AdminError::TooManyRecipients`] for too few or many chosen accounts.
    pub fn new(
        subject: &str,
        body: &str,
        recipients: AnnouncementRecipients,
        essential: bool,
    ) -> Result<Self, AdminError> {
        let subject = subject.trim();
        if subject.is_empty()
            || subject.chars().count() > MAX_SUBJECT_CHARS
            || subject.chars().any(char::is_control)
        {
            return Err(AdminError::InvalidSubject);
        }
        let body = body.replace("\r\n", "\n");
        let body = body.trim();
        if body.is_empty()
            || body.chars().count() > MAX_BODY_CHARS
            || body
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        {
            return Err(AdminError::InvalidBody);
        }
        if let AnnouncementRecipients::Accounts(accounts) = &recipients {
            if accounts.is_empty() {
                return Err(AdminError::NoRecipients);
            }
            if accounts.len() > MAX_CHOSEN_ACCOUNTS {
                return Err(AdminError::TooManyRecipients);
            }
        }
        Ok(Self {
            subject: subject.to_owned(),
            body: body.to_owned(),
            recipients,
            essential,
        })
    }
}

impl TryFrom<&DraftAnnouncement> for AnnouncementDraft {
    type Error = AdminError;
    /// Reads the dashboard's form: one account per line of its list, blank lines
    /// skipped.
    fn try_from(form: &DraftAnnouncement) -> Result<Self, Self::Error> {
        let recipients = match form.audience {
            AnnouncementAudience::Everyone => AnnouncementRecipients::Everyone,
            AnnouncementAudience::Accounts => AnnouncementRecipients::Accounts(
                form.accounts
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(|line| match line.parse() {
                        Ok(user) => user,
                        Err(never) => match never {},
                    })
                    .collect(),
            ),
        };
        Self::new(&form.subject, &form.body, recipients, form.essential.0)
    }
}

/// An account as an operator names it: its ID, a verified email of an active
/// account (a value with an `@` other than the leading one of `@handle`), or its
/// current handle, with or without that `@`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserRef {
    /// The account's ID.
    Id(UserId),
    /// A verified address an active account owns.
    Email(String),
    /// The account's current handle, in any status.
    Handle(String),
}

impl FromStr for UserRef {
    type Err = std::convert::Infallible;
    /// Reads a UUID as an ID, a handle written `@handle`, as the dashboard writes
    /// them, as that handle, any other value with an `@` as an email, and anything
    /// else as a handle.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(if let Ok(id) = value.parse() {
            Self::Id(id)
        } else if let Some(handle) = value.strip_prefix('@').filter(|rest| !rest.contains('@')) {
            Self::Handle(handle.to_owned())
        } else if value.contains('@') {
            Self::Email(value.to_owned())
        } else {
            Self::Handle(value.to_owned())
        })
    }
}

impl fmt::Display for UserRef {
    /// Writes the reference as the operator gave it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => id.fmt(formatter),
            Self::Email(value) | Self::Handle(value) => formatter.write_str(value),
        }
    }
}

#[cfg(test)]
mod tests;
