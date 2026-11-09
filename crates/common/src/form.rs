//! What auth's HTML forms post that does not decode as itself.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::IgnoredAny};

/// A checkbox, or a flag a query sets by its name alone: checked when the form
/// sends its name, whatever the value, since browsers send nothing for an unchecked
/// one. It decodes from text, as a change's fields must, where a `bool` would not.
/// It is checked as `on`, as browsers send it; leave it out of a form or link with
/// `#[serde(default, skip_serializing_if = "Checkbox::is_off")]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Checkbox(pub bool);

impl Checkbox {
    /// Whether it is unchecked, so its form sends nothing.
    #[must_use]
    pub const fn is_off(&self) -> bool {
        !self.0
    }
}

impl Serialize for Checkbox {
    /// Writes `on` when checked, as browsers send it.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.then_some("on").serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Checkbox {
    /// Checked, whatever the value: an unchecked box is not sent at all.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        IgnoredAny::deserialize(deserializer).map(|_| Self(true))
    }
}
