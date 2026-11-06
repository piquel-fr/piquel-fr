//! Files pages link, embedded in the executable serving them under paths that
//! never serve other content, so browsers and shared caches keep them forever.

use std::sync::LazyLock;

/// A file pages link, such as [`STYLESHEET`], embedded at compile time. Its
/// [`path`](Self::path) names a hash of its content, so a changed file is served
/// at a new path and a cached copy never goes stale. A font's path names its
/// version instead, since the stylesheet, a static file, links it by name: a
/// new version of a font gets a new name.
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
    /// A WOFF2 font.
    Font,
}

impl Kind {
    /// Its file extension.
    const fn extension(self) -> &'static str {
        match self {
            Self::Stylesheet => "css",
            Self::Script => "js",
            Self::Font => "woff2",
        }
    }

    /// Its `Content-Type`.
    const fn content_type(self) -> &'static str {
        match self {
            Self::Stylesheet => "text/css; charset=utf-8",
            Self::Script => "text/javascript; charset=utf-8",
            Self::Font => "font/woff2",
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

    /// The WOFF2 font of `bytes`, named `stem`, which must name its version.
    #[must_use]
    pub const fn font(stem: &'static str, bytes: &'static [u8]) -> Self {
        Self::new(stem, Kind::Font, bytes)
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
    /// hexadecimal digits, or `/assets/{stem}.{extension}` for a font, whose stem
    /// names its version.
    #[must_use]
    pub fn path(&self) -> String {
        match self.kind {
            Kind::Font => format!("/assets/{}.{}", self.stem, self.kind.extension()),
            Kind::Stylesheet | Kind::Script => format!(
                "/assets/{}.{:016x}.{}",
                self.stem,
                self.hash,
                self.kind.extension()
            ),
        }
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

/// The stylesheet's parts, `assets/style/{part}.css`, joined into one file in
/// the order they cascade, each after the blank line that separates sections.
macro_rules! stylesheet {
    ($first:literal $(, $part:literal)* $(,)?) => {
        concat!(
            include_str!(concat!("../assets/style/", $first, ".css"))
            $(, "\n", include_str!(concat!("../assets/style/", $part, ".css")))*
        )
    };
}

/// The stylesheet of piquel.fr's pages: auth's and the admin dashboard's.
pub const STYLESHEET: Asset = Asset::stylesheet(
    "style",
    stylesheet!(
        "tokens",
        "base",
        "shell",
        "frames",
        "cards",
        "components",
        "narrow",
    )
    .as_bytes(),
);

/// Topcoat's browser runtime, which runs the pages' expressions: their
/// handlers, bindings and signals. It loads after [`EXPRESSIONS`].
pub const RUNTIME: Asset = Asset::script("topcoat", topcoat::runtime::SCRIPT_SOURCE.as_bytes());

/// The functions of every runtime expression in the pages, which the runtime
/// looks up by the data a page carries: pages hold no code, so a policy listing
/// these two scripts runs them, and nothing a page holds. Built once, as the
/// executable's expressions are known only once it runs.
pub static EXPRESSIONS: LazyLock<Asset> = LazyLock::new(|| {
    Asset::script(
        "expressions",
        topcoat::runtime::expressions().source().as_bytes(),
    )
});

/// The typefaces the stylesheet links, by the paths it names: the Latin subsets
/// of DM Sans, a variable weight, and DM Mono at two weights.
pub const FONTS: [Asset; 3] = [
    Asset::font(
        "dm-sans-v17-latin",
        include_bytes!("../assets/fonts/dm-sans-v17-latin.woff2"),
    ),
    Asset::font(
        "dm-mono-v16-latin-400",
        include_bytes!("../assets/fonts/dm-mono-v16-latin-400.woff2"),
    ),
    Asset::font(
        "dm-mono-v16-latin-500",
        include_bytes!("../assets/fonts/dm-mono-v16-latin-500.woff2"),
    ),
];

#[cfg(test)]
mod tests {
    //! The paths naming assets' content.
    use super::*;

    /// The path names the content's 64-bit FNV-1a hash, here the published one of `a`,
    /// except a font's, which names its version.
    #[test]
    fn the_path_names_the_content() {
        let asset = Asset::stylesheet("style", b"a");
        assert_eq!(asset.path(), "/assets/style.af63dc4c8601ec8c.css");
        let font = Asset::font("dm-sans-v17-latin", b"a");
        assert_eq!(font.path(), "/assets/dm-sans-v17-latin.woff2");
    }

    /// The stylesheet links every font at the path it is served on.
    #[test]
    fn the_stylesheet_links_the_fonts() {
        let stylesheet = std::str::from_utf8(STYLESHEET.bytes()).expect("utf-8");
        for font in FONTS {
            assert!(stylesheet.contains(&font.path()), "{}", font.path());
        }
    }
}
