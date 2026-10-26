//! Names the stylesheet and SDK script of auth's pages by their content, copies them
//! into Cargo's build output and generates their `Asset` constants.
use sha2::{Digest, Sha256};
use std::{
    env,
    fmt::Write,
    fs, io,
    path::{Path, PathBuf},
};

/// An I/O result that names the path it is about when it fails.
trait AtPath<T> {
    /// This result, whose error names `path`.
    fn at(self, path: &Path) -> io::Result<T>;
}

impl<T> AtPath<T> for io::Result<T> {
    fn at(self, path: &Path) -> io::Result<T> {
        self.map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))
    }
}

/// A file auth's pages load, embedded under `/assets/` at a path naming its content.
struct PageFile {
    /// The SDK package's file: its stylesheet, or its built script.
    source: PathBuf,
    /// Its public name before the hash.
    stem: &'static str,
    /// Its public name's extension.
    extension: &'static str,
    /// Its `Content-Type`.
    content_type: &'static str,
}

impl PageFile {
    /// Copies the file into `output` at its public path, `/assets/{stem}.{hash}.{extension}`,
    /// so it can be cached forever, and returns its `Asset` as a Rust expression. The copy
    /// keeps the embedded bytes the ones the name was hashed from.
    fn embed(&self, output: &Path) -> io::Result<String> {
        let bytes = fs::read(&self.source).at(&self.source)?;
        let hex = Sha256::digest(&bytes)[..8]
            .iter()
            .fold(String::new(), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            });
        let path = format!("/assets/{}.{hex}.{}", self.stem, self.extension);
        let copy = output.join(path.trim_start_matches('/'));
        let directory = copy
            .parent()
            .ok_or_else(|| io::Error::other("embedded asset has no parent directory"))?;
        fs::create_dir_all(directory).at(directory)?;
        fs::write(&copy, bytes).at(&copy)?;
        let copy = copy
            .to_str()
            .ok_or_else(|| io::Error::other("embedded asset path must be UTF-8"))?;
        // Debug-format strings to emit escaped Rust string literals, including quotes.
        Ok(format!(
            "&Asset {{ path: {path:?}, bytes: include_bytes!({copy:?}), content_type: {:?} }}",
            self.content_type
        ))
    }
}

/// Embeds the stylesheet, and the SDK's script when it was built.
fn main() -> io::Result<()> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(io::Error::other)?);
    let output = PathBuf::from(env::var("OUT_DIR").map_err(io::Error::other)?);
    let sdk = manifest.join("../../packages/auth-sdk");
    let stylesheet = PageFile {
        source: sdk.join("src/style.css"),
        stem: "style",
        extension: "css",
        content_type: "text/css; charset=utf-8",
    };
    let script = PageFile {
        source: sdk.join("build/index.js"),
        stem: "auth-sdk",
        extension: "js",
        content_type: "text/javascript; charset=utf-8",
    };
    for file in [&stylesheet, &script] {
        println!("cargo:rerun-if-changed={}", file.source.display());
    }
    // A missing SDK build is only refused at startup, so Rust checks and tests need no Node.
    let script = if script.source.exists() {
        format!("Some({})", script.embed(&output)?)
    } else {
        "None".to_owned()
    };
    let assets = output.join("assets.rs");
    fs::write(
        &assets,
        format!(
            "impl Asset {{\n\
             /// The stylesheet of auth's pages.\n\
             const STYLESHEET: &Self = {};\n\
             /// The SDK's script, or `None` when the SDK was not built.\n\
             const SCRIPT: Option<&Self> = {script};\n}}\n",
            stylesheet.embed(&output)?
        ),
    )
    .at(&assets)
}
