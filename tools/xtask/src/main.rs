//! Development tasks for the SourceOrigin workspace, run with `cargo xtask`:
//! publishing the SDKs and releasing a version. See docs/dev/releasing.md.

mod publish;
mod release;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The TypeScript SDK's directory, relative to the workspace root.
const NPM_PACKAGE: &str = "packages/auth";

#[derive(Parser)]
#[command(about = "Development tasks for the SourceOrigin workspace")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Publish the SDKs: the Rust crates to crates.io, in dependency order, then
    /// `@sourceorigin/auth` to npm. Versions already published are skipped.
    Publish {
        /// Package and build everything without uploading, even versions
        /// already published.
        #[arg(long)]
        dry_run: bool,
        /// Publish from a working tree with uncommitted changes.
        #[arg(long)]
        allow_dirty: bool,
    },
    /// Release the workspace version from the latest main: publish the SDKs,
    /// tag the commit, create its GitHub release and close its milestone.
    Release {
        /// Run the checks and the publish dry run, and only print the other
        /// steps and the release notes.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    let workspace = Workspace::current()?;
    match Cli::parse().task {
        Task::Publish {
            dry_run,
            allow_dirty,
        } => publish::Publish {
            workspace: &workspace,
            dry_run,
            allow_dirty,
        }
        .run(),
        Task::Release { dry_run } => release::Release::new(&workspace, dry_run)?.run(),
    }
}

/// The checkout `cargo xtask` runs in, which may be one of several worktrees.
struct Workspace {
    root: PathBuf,
    /// The workspace's crates, as `cargo metadata` describes them.
    packages: Vec<Package>,
}

/// The fields of a crate's `cargo metadata` this reads.
#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    license: Option<String>,
    /// The registries it may be published to: empty for `publish = false`.
    publish: Option<Vec<String>>,
}

/// The TypeScript SDK's `package.json`, as far as this reads it.
#[derive(Deserialize)]
struct NpmPackage {
    name: String,
    version: String,
}

/// The fields of `cargo metadata` this reads.
#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

impl Workspace {
    fn current() -> Result<Self> {
        let root = PathBuf::from(
            Command::new("git")
                .args(["rev-parse", "--show-toplevel"])
                .read()?,
        );
        let metadata = Self::cargo_in(&root)
            .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
            .read()?;
        let Metadata { packages } =
            serde_json::from_str(&metadata).context("parse cargo metadata")?;
        Ok(Self { root, packages })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    /// The crates published to crates.io: every one without `publish = false`.
    fn published(&self) -> impl Iterator<Item = &Package> {
        self.packages.iter().filter(|package| {
            package
                .publish
                .as_ref()
                .is_none_or(|registries| !registries.is_empty())
        })
    }

    /// The version the published crates share, such as `0.1.0`.
    fn version(&self) -> Result<&str> {
        let mut published = self.published();
        let first = published.next().context("no crate is published")?;
        for package in published {
            ensure!(
                package.version == first.version,
                "{} is at {} but {} at {}: the published crates are released together",
                package.name,
                package.version,
                first.name,
                first.version
            );
        }
        Ok(&first.version)
    }

    /// The TypeScript SDK's name and version, which it is published at.
    fn npm_package(&self) -> Result<NpmPackage> {
        let path = self.root.join(NPM_PACKAGE).join("package.json");
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
    }

    /// Cargo, run from the workspace root.
    fn cargo(&self) -> Command {
        Self::cargo_in(&self.root)
    }

    /// Cargo, run from `root` without the package variables `cargo run` gave
    /// this xtask. Build scripts track `CARGO_MANIFEST_DIR`, so passing xtask's
    /// on would make every nested build, and the next ordinary one, recompile.
    fn cargo_in(root: &Path) -> Command {
        let mut command = Command::new("cargo");
        command.current_dir(root);
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(|key| {
                key.starts_with("CARGO_PKG_")
                    || matches!(
                        key,
                        "CARGO_MANIFEST_DIR"
                            | "CARGO_MANIFEST_PATH"
                            | "CARGO_CRATE_NAME"
                            | "CARGO_BIN_NAME"
                            | "CARGO_PRIMARY_PACKAGE"
                    )
            }) {
                command.env_remove(key);
            }
        }
        command
    }

    /// `program`, run from the workspace root.
    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.current_dir(&self.root);
        command
    }

    /// Runs git from the workspace root and returns its trimmed output.
    fn git(&self, args: &[&str]) -> Result<String> {
        self.command("git").args(args).read()
    }
}

/// Runs a command to completion, failing with the command and its status when
/// it fails.
trait Run {
    /// Runs it with the terminal's standard streams.
    fn run(&mut self) -> Result<()>;
    /// Runs it and returns its trimmed standard output; its standard error is
    /// in the failure.
    fn read(&mut self) -> Result<String>;
}

impl Run for Command {
    fn run(&mut self) -> Result<()> {
        let status = self.status().with_context(|| format!("run {self:?}"))?;
        ensure!(status.success(), "{self:?} failed ({status})");
        Ok(())
    }

    fn read(&mut self) -> Result<String> {
        let output = self.output().with_context(|| format!("run {self:?}"))?;
        ensure!(
            output.status.success(),
            "{self:?} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(String::from_utf8(output.stdout)
            .with_context(|| format!("{self:?} printed invalid UTF-8"))?
            .trim()
            .to_owned())
    }
}
