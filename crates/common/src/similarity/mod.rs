//! Look-alike detection, for every name people could mistake for another: handles,
//! client display names and the names reserved from both. Two texts look alike
//! when they share a [`Skeleton`]; a name is compared with a list either whole
//! ([`Skeleton::find_alike`]) or as part of longer text ([`Skeleton::find_contained`]).
//!
//! ```
//! use sourceorigin_common::similarity::Skeleton;
//!
//! assert_eq!(Skeleton::of("S0urce-Origin"), Skeleton::of("sourceorigin"));
//! assert_eq!(Skeleton::of("adm1n").find_alike(["auth", "admin"]), Some("admin"));
//! assert_eq!(
//!     Skeleton::of("My G00gle app").find_contained(["github", "google"]),
//!     Some("google")
//! );
//! ```

/// The key two texts collide on when they look alike: ASCII letters and digits,
/// lowercased, with `0` read as `o`, `1` and `i` as `l`, `5` as `s`, then `rn` as
/// `m` and `vv` as `w`. Everything else, punctuation, spaces and letters outside
/// ASCII, is dropped. Handles are ASCII, so this small table stands in for a
/// UTS #39 skeleton.
///
/// The schema's `handle_skeleton` computes the same key for handles, to keep them
/// and their look-alikes unique; a database test pins the two together.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Skeleton(String);

impl Skeleton {
    /// Computes the skeleton of `text`.
    #[must_use]
    pub fn of(text: &str) -> Self {
        let folded: String = text
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

/// Look-alike vectors.
#[cfg(test)]
mod tests;
