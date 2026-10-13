//! Snapshots the completed static auth frontend into Cargo's build output.
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use std::{fmt::Write, io};
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
}

/// Copies every completed frontend asset, then generates the Rust lookup table.
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
    let mut entries = String::new();
    for (name, path) in &assets.entries {
        let path = path
            .to_str()
            .ok_or_else(|| io::Error::other("embedded asset path must be UTF-8"))?;
        // Debug-format strings to emit escaped Rust string literals, including quotes.
        writeln!(
            &mut entries,
            "({name:?},include_bytes!({path:?}) as &'static [u8]),"
        )
        .map_err(io::Error::other)?;
    }
    fs::write(
        output.join("assets.rs"),
        format!(
            "/// Public paths and immutable bytes from the completed frontend build.\n\
             pub(crate) static FILES: &[(&str,&[u8])] = &[{entries}];"
        ),
    )?;
    Ok(())
}
