//! Files pages link, embedded in the executable serving them under paths naming
//! their content, so browsers and shared caches keep them forever.

/// A file pages link, such as [`STYLESHEET`], embedded at compile time. Its
/// [`path`](Self::path) names a hash of its content, so a changed file is served
/// at a new path and a cached copy never goes stale.
#[derive(Clone, Copy)]
pub struct Asset {
    /// Its public name before the hash.
    stem: &'static str,
    /// What it is, which names its extension and `Content-Type`.
    kind: Kind,
    /// Its content.
    bytes: &'static [u8],
    /// The 64-bit FNV-1a hash of `bytes`. It only busts caches, so it needs no
    /// cryptographic strength.
    hash: u64,
}

/// What an [`Asset`] is.
#[derive(Clone, Copy)]
enum Kind {
    /// A stylesheet.
    Stylesheet,
    /// A JavaScript module.
    Script,
}

impl Kind {
    /// Its file extension.
    const fn extension(self) -> &'static str {
        match self {
            Self::Stylesheet => "css",
            Self::Script => "js",
        }
    }

    /// Its `Content-Type`.
    const fn content_type(self) -> &'static str {
        match self {
            Self::Stylesheet => "text/css; charset=utf-8",
            Self::Script => "text/javascript; charset=utf-8",
        }
    }
}

impl Asset {
    /// The stylesheet of `bytes`, named `stem`.
    #[must_use]
    pub const fn stylesheet(stem: &'static str, bytes: &'static [u8]) -> Self {
        Self::new(stem, Kind::Stylesheet, bytes)
    }

    /// The JavaScript module of `bytes`, named `stem`.
    #[must_use]
    pub const fn script(stem: &'static str, bytes: &'static [u8]) -> Self {
        Self::new(stem, Kind::Script, bytes)
    }

    /// The `kind` of file of `bytes`, named `stem`. A constant asset is hashed at
    /// compile time, within const evaluation's step budget: a few hundred
    /// kilobytes per file.
    const fn new(stem: &'static str, kind: Kind, bytes: &'static [u8]) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut index = 0;
        while index < bytes.len() {
            hash ^= bytes[index] as u64;
            hash = hash.wrapping_mul(0x0100_0000_01b3);
            index += 1;
        }
        Self {
            stem,
            kind,
            bytes,
            hash,
        }
    }

    /// Where it is served: `/assets/{stem}.{hash}.{extension}`, the hash in 16
    /// hexadecimal digits.
    #[must_use]
    pub fn path(&self) -> String {
        format!(
            "/assets/{}.{:016x}.{}",
            self.stem,
            self.hash,
            self.kind.extension()
        )
    }

    /// Its content.
    #[must_use]
    pub const fn bytes(&self) -> &'static [u8] {
        self.bytes
    }

    /// Its `Content-Type`.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.kind.content_type()
    }
}

/// The stylesheet of piquel.fr's pages: auth's, and the admin dashboard's, which
/// adds its own.
pub const STYLESHEET: Asset = Asset::stylesheet("style", include_bytes!("../assets/style.css"));

#[cfg(test)]
mod tests {
    //! The paths naming assets' content.
    use super::*;

    /// The path names the content's 64-bit FNV-1a hash, here the published one of `a`.
    #[test]
    fn the_path_names_the_content() {
        let asset = Asset::stylesheet("style", b"a");
        assert_eq!(asset.path(), "/assets/style.af63dc4c8601ec8c.css");
    }
}
