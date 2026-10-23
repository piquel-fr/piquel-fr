//! Snapshots the completed static auth frontend into Cargo's build output, and
//! generates its lookup with each file's headers.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use std::{fmt::Write, io};

/// Prefix of content-addressed `SvelteKit` bundles.
const IMMUTABLE_PREFIX: &str = "/_app/immutable/";

/// Snapshots frontend files so Cargo embeds a complete, deterministic build.
struct Assets {
    /// Completed `SvelteKit` build to copy.
    source: PathBuf,
    /// Cargo-owned copy, independent of later frontend builds.
    snapshot: PathBuf,
    /// Public paths paired with their copied file paths.
    entries: Vec<(String, PathBuf)>,
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

    /// Generates `EmbeddedAssets::find`: a `match` from each path to the file's bytes
    /// and headers. A page also answers at its path without `.html`, the index at `""`.
    fn lookup(&self) -> io::Result<String> {
        let names: Vec<&str> = self.entries.iter().map(|(name, _)| name.as_str()).collect();
        let mut arms = String::new();
        for (name, path) in &self.entries {
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
            let cache = if name.starts_with(IMMUTABLE_PREFIX) {
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
        let (param, body) = if arms.is_empty() {
            ("_path", "None".into())
        } else {
            ("path", format!("match path {{\n{arms}_ => None,\n}}"))
        };
        Ok(format!(
            "impl EmbeddedAssets {{\n\
             /// Number of embedded files: zero when the frontend was not built.\n\
             const COUNT: usize = {count};\n\
             /// The embedded file at `path`, or the page at `path` without `.html`.\n\
             fn find({param}: &str) -> Option<&'static Asset> {{\n{body}\n}}\n}}\n",
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

/// Copies every completed frontend asset, then generates the Rust lookup.
fn main() -> io::Result<()> {
    let source = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(io::Error::other)?)
        .join("../auth-web/build");
    let output = PathBuf::from(env::var("OUT_DIR").map_err(io::Error::other)?);
    println!("cargo:rerun-if-changed={}", source.display());
    let mut assets = Assets {
        source: source.clone(),
        snapshot: output.join("auth-assets"),
        entries: Vec::new(),
    };
    // A missing build embeds nothing; the service then refuses to start.
    if source.exists() {
        assets.collect(&source)?;
    }
    assets.entries.sort();
    // Lets code used only by embedded files tolerate builds without them.
    println!("cargo::rustc-check-cfg=cfg(embedded_frontend)");
    if !assets.entries.is_empty() {
        println!("cargo::rustc-cfg=embedded_frontend");
    }
    fs::write(output.join("assets.rs"), assets.lookup()?)
}
