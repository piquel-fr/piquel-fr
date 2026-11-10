//! Look-alike detection, for every name people could mistake for another: handles,
//! client display names and the names reserved from both. Two texts look alike
//! when they share a [`Skeleton`](crate::similarity::Skeleton); a name is compared
//! with a list either whole
//! ([`find_alike`](crate::similarity::Skeleton::find_alike)) or as part of longer
//! text ([`find_contained`](crate::similarity::Skeleton::find_contained)).
//!
//! ```
//! use sourceorigin_common::{Handle, HandleError, similarity::Skeleton};
//!
//! assert_eq!(Skeleton::of("S0urce-Origin"), Skeleton::of("sourceorigin"));
//! assert_eq!(Skeleton::of("Gооgle"), Skeleton::of("google")); // Cyrillic о
//! assert_eq!(
//!     Skeleton::of("My G00gle app").find_contained(["github", "google"]),
//!     Some("google")
//! );
//! // Look-alikes of a reserved handle are reserved too.
//! assert_eq!(
//!     Handle::parse("adm1n")?.ensure_unreserved(),
//!     Err(HandleError::Reserved("admin".into()))
//! );
//! # Ok::<(), HandleError>(())
//! ```

use crate::{
    Handle, HandleError,
    clients::{DisplayName, RESERVED_BRANDS, ReservedDisplayName},
    handle::RESERVED,
};
use unicode_security::skeleton;

/// The key two texts collide on when they look alike. Each character outside
/// ASCII is first read as the characters it looks like, by the UTS #39 confusables
/// table, so a Cyrillic `о` reads as `o` and `é` as `e`. Then only ASCII letters
/// and digits are kept, lowercased, with `0` read as `o`, `1` and `i` as `l`, `5`
/// as `s`, then `rn` as `m` and `vv` as `w`. Whatever has no ASCII look-alike,
/// such as punctuation, spaces, accents and most other scripts, is dropped.
///
/// ASCII text never goes through the confusables table, so handles keep the key
/// the schema's `handle_skeleton` computes, which keeps them and their
/// look-alikes unique; a database test pins the two together.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Skeleton(String);

impl Skeleton {
    /// Computes the skeleton of `text`.
    #[must_use]
    pub fn of(text: &str) -> Self {
        let mut prototypes = String::with_capacity(text.len());
        for character in text.chars() {
            if character.is_ascii() {
                prototypes.push(character);
            } else {
                prototypes.extend(skeleton(character.encode_utf8(&mut [0; 4])));
            }
        }
        let folded: String = prototypes
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|character| match character.to_ascii_lowercase() {
                '0' => 'o',
                '1' | 'i' => 'l',
                '5' => 's',
                other => other,
            })
            .collect();
        Self(folded.replace("rn", "m").replace("vv", "w"))
    }

    /// The first of `names` this text looks like as a whole, as handles are
    /// compared with reserved ones.
    pub fn find_alike<N: AsRef<str>>(&self, names: impl IntoIterator<Item = N>) -> Option<N> {
        names
            .into_iter()
            .find(|name| Self::of(name.as_ref()) == *self)
    }

    /// The first of `names` this text contains a look-alike of, as client display
    /// names are compared with reserved brands.
    pub fn find_contained<N: AsRef<str>>(&self, names: impl IntoIterator<Item = N>) -> Option<N> {
        names
            .into_iter()
            .find(|name| self.0.contains(&Self::of(name.as_ref()).0))
    }

    /// Borrows the skeleton.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Handle {
    /// Refuses names of [`RESERVED`] and their look-alikes. Signup and
    /// self-service renames call it; operators may skip it.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::Reserved`] with the reserved name it matches.
    pub fn ensure_unreserved(&self) -> Result<(), HandleError> {
        match self.skeleton().find_alike(RESERVED) {
            Some(name) => Err(HandleError::Reserved((*name).to_owned())),
            None => Ok(()),
        }
    }

    /// The key two handles collide on when they look alike. No two accounts'
    /// handles may share one; `auth-service handle check` lists those that do.
    #[must_use]
    pub fn skeleton(&self) -> Skeleton {
        Skeleton::of(self.as_str())
    }
}

impl DisplayName {
    /// Refuses a name containing a brand of [`RESERVED_BRANDS`], or a look-alike,
    /// as clients accounts own must. Case, spaces, punctuation and accents are
    /// ignored, so "S0urce0r1gin-Settings", "G00gle" and "Gооgle" (Cyrillic `о`)
    /// are refused too.
    ///
    /// # Errors
    ///
    /// Returns [`ReservedDisplayName`] with the brand the name contains.
    pub fn ensure_unreserved(&self) -> Result<(), ReservedDisplayName> {
        match Skeleton::of(self.as_str()).find_contained(RESERVED_BRANDS) {
            Some(brand) => Err(ReservedDisplayName(brand)),
            None => Ok(()),
        }
    }
}

/// Look-alike vectors, and the reserved names they guard.
#[cfg(test)]
mod tests;
