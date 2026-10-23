//! Handles: an account's public identifier, which is also its login name.
//!
//! ```
//! use piquel_common::{Handle, HandleError};
//!
//! let handle = Handle::parse(" Alice-B ")?;
//! assert_eq!(handle.as_str(), "alice-b");
//! assert_eq!(Handle::parse("a_b"), Err(HandleError::Charset));
//! // Confusables of a reserved name are reserved too.
//! assert_eq!(
//!     Handle::parse("adm1n")?.ensure_unreserved(),
//!     Err(HandleError::Reserved("admin".into()))
//! );
//! # Ok::<(), HandleError>(())
//! ```

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// Shortest handle, in characters.
pub const MIN_LENGTH: usize = 3;
/// Longest handle, in characters.
pub const MAX_LENGTH: usize = 32;

/// Names signup and self-service renames refuse, along with every handle sharing
/// one's [skeleton](Handle::skeleton). Operators may still assign them.
const RESERVED: &[&str] = &[
    // Infrastructure labels: a handle may become a subdomain of piquel.fr.
    "auth",
    "admin",
    "www",
    "api",
    "staging",
    "dev",
    "mail",
    "smtp",
    "imap",
    "ldap",
    "status",
    "cdn",
    "static",
    // RFC 2142 mailboxes.
    "abuse",
    "postmaster",
    "hostmaster",
    "webmaster",
    "security",
    "noc",
    "support",
    // piquel.fr routes.
    "settings",
    "developers",
    "login",
    "logout",
    "about",
    "help",
    "privacy",
    "terms",
    // The brand.
    "piquel",
    "piquelfr",
    // Other
    "admin",
    "system",
    "origin",
];

/// A lowercase DNS label: [`MIN_LENGTH`] to [`MAX_LENGTH`] characters of `[a-z0-9-]`,
/// without a leading, trailing or double hyphen. That also excludes punycode's
/// `xn--`, so every handle is a valid DNS label, AT Protocol handle segment and
/// `acct:` local part.
///
/// [`Self::parse`] normalizes user input. Deserializing and [`FromStr`] accept only
/// the canonical form, so a stored handle that breaks the rules fails to decode.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Handle(String);

/// Why a handle is refused, worded as what to do instead.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HandleError {
    /// Too short or too long.
    #[error("use {MIN_LENGTH}–{MAX_LENGTH} characters")]
    Length,
    /// A character outside `[a-z0-9-]`, or a misplaced hyphen.
    #[error("use lowercase letters, digits and single hyphens, not at the start or end")]
    Charset,
    /// The handle is, or looks like, this reserved name.
    #[error("`{0}` and names that look like it are reserved")]
    Reserved(String),
}

impl Handle {
    /// Trims `input`, lowercases its ASCII letters and checks the syntax. Whether
    /// the handle is reserved is [`Self::ensure_unreserved`]'s concern.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::Length`] or [`HandleError::Charset`].
    pub fn parse(input: &str) -> Result<Self, HandleError> {
        let handle = input.trim().to_ascii_lowercase();
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&handle.chars().count()) {
            return Err(HandleError::Length);
        }
        // Empty parts are leading, trailing or consecutive hyphens.
        if !handle.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        }) {
            return Err(HandleError::Charset);
        }
        Ok(Self(handle))
    }

    /// Refuses reserved names and their look-alikes, by comparing skeletons. Signup
    /// and self-service renames call it; operators may skip it.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::Reserved`] with the reserved name it matches.
    pub fn ensure_unreserved(&self) -> Result<(), HandleError> {
        let skeleton = self.skeleton();
        match RESERVED.iter().find(|name| Self::fold(name) == skeleton) {
            Some(name) => Err(HandleError::Reserved((*name).to_owned())),
            None => Ok(()),
        }
    }

    /// The key two handles collide on when they look alike: hyphens dropped, `0`
    /// read as `o`, `1` and `i` as `l`, `5` as `s`, then `rn` as `m` and `vv` as
    /// `w`. Handles are ASCII, so this small table stands in for a UTS #39 skeleton.
    /// No two accounts' handles may share one.
    #[must_use]
    pub fn skeleton(&self) -> String {
        Self::fold(&self.0)
    }

    /// Computes the [skeleton](Self::skeleton) of a valid handle.
    fn fold(handle: &str) -> String {
        handle
            .chars()
            .filter_map(|character| match character {
                '-' => None,
                '0' => Some('o'),
                '1' | 'i' => Some('l'),
                '5' => Some('s'),
                other => Some(other),
            })
            .collect::<String>()
            .replace("rn", "m")
            .replace("vv", "w")
    }

    /// Borrows the handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Handle {
    /// Writes the handle.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Handle {
    type Err = HandleError;
    /// Accepts only a handle already in canonical form, as stored.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let handle = Self::parse(value)?;
        if handle.0 == value {
            Ok(handle)
        } else {
            Err(HandleError::Charset)
        }
    }
}

impl TryFrom<String> for Handle {
    type Error = HandleError;
    /// Accepts only canonical handles, as [`FromStr`] does.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Handle> for String {
    /// Unwraps the handle.
    fn from(value: Handle) -> Self {
        value.0
    }
}

crate::__str_enum_sqlx!(Handle);

/// Syntax, reservation and skeleton vectors.
#[cfg(test)]
mod tests;
