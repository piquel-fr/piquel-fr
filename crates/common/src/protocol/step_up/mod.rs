//! Step-up requirements: what a protected operation needs from the user's
//! authentication (RFC 9470). Auth's own account APIs and bearer-protected
//! resources check the same type, so both enforce one rule; each only reports an
//! unmet requirement in its own format.

use super::claims::Acr;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

/// Longest time, in seconds, since the passkey confirmation auth's protected
/// actions accept: sensitive account changes and admin dashboard changes. The
/// confirmation happens just before the action, so it can be short.
pub const CONFIRMATION_MAX_AGE: u32 = 300;

/// What a protected operation needs from the user's authentication: an `acr` to
/// meet, a maximum age of `auth_time`, or both. The default needs nothing.
///
/// It serializes as the parameters that ask for it, `acr_values` and `max_age`, as in
/// a step-up challenge (RFC 9470 §3).
///
/// ```
/// use chrono::{TimeDelta, Utc};
/// use sourceorigin_common::protocol::{claims::Acr, step_up::StepUpRequirement};
///
/// let recent_passkey = StepUpRequirement::passkey_within(300);
/// let now = Utc::now();
/// let a_minute_ago = Some(now - TimeDelta::minutes(1));
///
/// assert!(recent_passkey.check(Some(&Acr::PhishingResistant), a_minute_ago, now).is_ok());
/// // A social sign-in is too weak, however recent.
/// assert!(recent_passkey.check(Some(&Acr::Social), a_minute_ago, now).is_err());
///
/// // A client asks for it again with these parameters.
/// let params: Vec<_> = recent_passkey.authorize_params().collect();
/// assert_eq!(params, [("acr_values", "phr".into()), ("max_age", "300".into())]);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(optional_fields))]
pub struct StepUpRequirement {
    /// The class the authentication must meet ([`Acr::satisfies`]).
    #[serde(
        default,
        rename = "acr_values",
        skip_serializing_if = "Option::is_none"
    )]
    pub acr: Option<Acr>,
    /// The longest time since `auth_time`, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u32>,
}

impl StepUpRequirement {
    /// A passkey confirmation at most `max_age` seconds old, as auth's sensitive
    /// account changes need.
    #[must_use]
    pub const fn passkey_within(max_age: u32) -> Self {
        Self {
            acr: Some(Acr::PhishingResistant),
            max_age: Some(max_age),
        }
    }

    /// Checks an authentication, reported as `acr` and `auth_time`, at `now`. A
    /// missing claim fails any requirement on it. Resource servers that allow for
    /// clock skew pass `now` minus their leeway.
    ///
    /// # Errors
    /// Returns this requirement when the authentication falls short, for the caller
    /// to report as a challenge.
    pub fn check(
        &self,
        acr: Option<&Acr>,
        auth_time: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<(), Self> {
        let strong = self
            .acr
            .is_none_or(|required| acr.is_some_and(|acr| acr.satisfies(required)));
        let recent = self.max_age.is_none_or(|max_age| {
            auth_time.is_some_and(|auth_time| {
                now.signed_duration_since(auth_time) <= TimeDelta::seconds(max_age.into())
            })
        });
        if strong && recent { Ok(()) } else { Err(*self) }
    }

    /// The authorization request parameters (OIDC Core §3.1.2.1) that ask auth for
    /// this authentication: `acr_values` and `max_age`. A client answering a step-up
    /// challenge adds them to its next authorization request.
    pub fn authorize_params(&self) -> impl Iterator<Item = (&'static str, String)> {
        let acr = self.acr.map(|acr| ("acr_values", acr.to_string()));
        let max_age = self.max_age.map(|age| ("max_age", age.to_string()));
        acr.into_iter().chain(max_age)
    }
}

#[cfg(test)]
mod tests;
