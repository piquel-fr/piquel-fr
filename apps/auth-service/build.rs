//! Snapshots the completed static auth frontend into Cargo's build output.
use std::fmt::Write;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
struct Assets {
    source: PathBuf,
    snapshot: PathBuf,
    entries: Vec<(String, PathBuf)>,
}
impl Assets {
    fn collect(&mut self, dir: &Path) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                self.collect(&path)?;
            } else {
                let relative = path.strip_prefix(&self.source).expect("asset under source");
                let snapshot = self.snapshot.join(relative);
                fs::create_dir_all(snapshot.parent().expect("asset parent"))?;
                fs::copy(&path, &snapshot)?;
                self.entries
                    .push((format!("/{}", relative.display()), snapshot));
            }
        }
        Ok(())
    }
}
fn main() {
    let source =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest")).join("../auth-web/build");
    let output = PathBuf::from(env::var("OUT_DIR").expect("output directory"));
    println!("cargo:rerun-if-changed={}", source.display());
    let mut assets = Assets {
        source: source.clone(),
        snapshot: output.join("auth-assets"),
        entries: Vec::new(),
    };
    if source.exists() {
        assets
            .collect(&source)
            .expect("build the auth frontend completely before compiling Rust");
    }
    assets.entries.sort();
    let mut entries = String::new();
    for (name, path) in &assets.entries {
        let path = path.to_str().expect("UTF-8 asset path");
        // Debug-format strings to emit escaped Rust string literals, including quotes.
        writeln!(
            &mut entries,
            "({name:?},include_bytes!({path:?}) as &'static [u8]),"
        )
        .expect("write generated Rust");
    }
    fs::write(
        output.join("assets.rs"),
        format!("pub(crate) static FILES: &[(&str,&[u8])] = &[{entries}];"),
    )
    .expect("write embedded assets");
}
