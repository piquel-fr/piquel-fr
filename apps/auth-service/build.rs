//! Snapshots the completed static auth frontend into Cargo's build output, names the
//! stylesheet and SDK script of auth's server-rendered pages by their content, and
//! generates their lookup with each file's headers.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use std::{fmt::Write, io};

/// Prefix of content-addressed `SvelteKit` bundles.
const IMMUTABLE_PREFIX: &str = "/_app/immutable/";
/// Where the files of auth's server-rendered pages are served, named by their content.
const PAGE_ASSETS_PREFIX: &str = "/assets/";

/// Snapshots frontend files so Cargo embeds a complete, deterministic build.
struct Assets {
    /// Completed `SvelteKit` build to copy.
    source: PathBuf,
    /// Cargo-owned copy, independent of later frontend builds.
    snapshot: PathBuf,
    /// Public paths paired with their copied file paths.
    entries: Vec<(String, PathBuf)>,
    /// The pages' files, by the content-addressed public path each is served at.
    named: Vec<(String, PathBuf)>,
}
impl Assets {
    /// Copies static files recursively and records their browser paths.
    fn collect(&mut self, dir: &Path) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                self.collect(&path)?;
            } else {
                let relative = path.strip_prefix(&self.source).map_err(io::Error::other)?;
                let snapshot = self.snapshot.join(relative);
                fs::create_dir_all(
                    snapshot.parent().ok_or_else(|| {
                        io::Error::other("asset snapshot has no parent directory")
                    })?,
                )?;
                fs::copy(&path, &snapshot)?;
                self.entries
                    .push((format!("/{}", relative.display()), snapshot));
            }
        }
        Ok(())
    }

    /// Copies `file` and names it by its content under [`PAGE_ASSETS_PREFIX`], as
    /// `{stem}.{hash}.{extension}`, so it can be cached forever. Returns that path.
    fn name(&mut self, stem: &str, extension: &str, file: &Path) -> io::Result<String> {
        let bytes = fs::read(file)?;
        let hash = Sha256::digest(&bytes);
        let hex = hash[..8].iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        let path = format!("{PAGE_ASSETS_PREFIX}{stem}.{hex}.{extension}");
        // Copied under its public path, as the frontend's files are.
        let snapshot = self.snapshot.join(path.trim_start_matches('/'));
        fs::create_dir_all(
            snapshot
                .parent()
                .ok_or_else(|| io::Error::other("asset snapshot has no parent directory"))?,
        )?;
        fs::write(&snapshot, bytes)?;
        self.named.push((path.clone(), snapshot));
        Ok(path)
    }

    /// Generates `EmbeddedAssets::find`: a `match` from each path to the file's bytes
    /// and headers. A page also answers at its path without `.html`, the index at `""`.
    /// The pages' named files are content-addressed, so immutable.
    fn lookup(&self, stylesheet: &str, script: Option<&str>) -> io::Result<String> {
        let names: Vec<&str> = self.entries.iter().map(|(name, _)| name.as_str()).collect();
        let mut arms = String::new();
        for (name, path) in self.entries.iter().chain(&self.named) {
            let path = path
                .to_str()
                .ok_or_else(|| io::Error::other("embedded asset path must be UTF-8"))?;
            let mut patterns = vec![name.as_str()];
            if let Some(page) = name.strip_suffix(".html") {
                patterns.push(page);
                if page == "/index" {
                    patterns.push("");
                }
            }
            // A real file at a page's alias keeps its own path.
            patterns.retain(|pattern| *pattern == name || !names.contains(pattern));
            let hash = Sha256::digest(fs::read(path)?);
            let etag = format!("\"{}\"", URL_SAFE_NO_PAD.encode(&hash[..16]));
            let cache =
                if name.starts_with(IMMUTABLE_PREFIX) || name.starts_with(PAGE_ASSETS_PREFIX) {
                    "Immutable"
                } else {
                    "Revalidate"
                };
            // Debug-format strings to emit escaped Rust string literals, including quotes.
            writeln!(
                &mut arms,
                "{patterns} => Some(&Asset {{ bytes: include_bytes!({path:?}), \
                 content_type: {content_type:?}, etag: {etag:?}, cache: CacheClass::{cache} }}),",
                patterns = patterns
                    .iter()
                    .map(|pattern| format!("{pattern:?}"))
                    .collect::<Vec<_>>()
                    .join(" | "),
                content_type = Self::content_type(name),
            )
            .map_err(io::Error::other)?;
        }
        Ok(format!(
            "impl EmbeddedAssets {{\n\
             /// Number of embedded frontend files: zero when the frontend was not built.\n\
             const COUNT: usize = {count};\n\
             /// Path of the stylesheet of auth's own pages.\n\
             pub(crate) const STYLESHEET: &str = {stylesheet:?};\n\
             /// Path of the SDK's script, or `None` when the SDK was not built.\n\
             pub(crate) const SCRIPT: Option<&str> = {script:?};\n\
             /// The embedded file at `path`, or the page at `path` without `.html`.\n\
             fn find(path: &str) -> Option<&'static Asset> {{\n\
             match path {{\n{arms}_ => None,\n}}\n}}\n}}\n",
            count = self.entries.len(),
        ))
    }

    /// The `Content-Type` of a file, by extension.
    fn content_type(name: &str) -> &'static str {
        match name.rsplit('.').next() {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("svg") => "image/svg+xml",
            Some("json") => "application/json",
            Some("png") => "image/png",
            Some("ico") => "image/x-icon",
            Some("woff2") => "font/woff2",
            _ => "application/octet-stream",
        }
    }
}

/// Copies every completed frontend asset, names the pages' stylesheet and the SDK's
/// script by their content, then generates the Rust lookup.
fn main() -> io::Result<()> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(io::Error::other)?);
    let source = manifest.join("../auth-web/build");
    let stylesheet = manifest.join("../../packages/auth-sdk/src/style.css");
    let script = manifest.join("../../packages/auth-sdk/build/index.js");
    let output = PathBuf::from(env::var("OUT_DIR").map_err(io::Error::other)?);
    for input in [&source, &stylesheet, &script] {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    let mut assets = Assets {
        source: source.clone(),
        snapshot: output.join("auth-assets"),
        entries: Vec::new(),
        named: Vec::new(),
    };
    // A missing build embeds nothing; the service then refuses to start.
    if source.exists() {
        assets.collect(&source)?;
    }
    assets.entries.sort();
    let stylesheet = assets.name("style", "css", &stylesheet)?;
    // Like the frontend, a missing SDK build is only refused at startup.
    let script = if script.exists() {
        Some(assets.name("auth-sdk", "js", &script)?)
    } else {
        None
    };
    // Lets code used only by embedded files tolerate builds without them.
    println!("cargo::rustc-check-cfg=cfg(embedded_frontend)");
    if !assets.entries.is_empty() {
        println!("cargo::rustc-cfg=embedded_frontend");
    }
    fs::write(
        output.join("assets.rs"),
        assets.lookup(&stylesheet, script.as_deref())?,
    )
}
