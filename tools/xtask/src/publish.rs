//! `cargo xtask publish`: publishes the SDKs, the Rust crates to crates.io and
//! `@sourceorigin/auth` to npm.

use crate::{NPM_PACKAGE, Package, Run, Workspace};
use anyhow::{Context, Result, ensure};
use std::process::Command;

/// The license every published crate is under. The others are under
/// `PolyForm-Noncommercial-1.0.0`, so none may be published or become a
/// dependency of a published crate.
const LICENSE: &str = "Apache-2.0";

/// A publish of the SDKs at their current versions.
pub struct Publish<'a> {
    pub workspace: &'a Workspace,
    /// Packages and builds everything without uploading, even versions already
    /// published, so it checks the packages whatever the registries hold.
    pub dry_run: bool,
    /// Publishes from a working tree with uncommitted changes.
    pub allow_dirty: bool,
}

impl Publish<'_> {
    /// Checks the crates' licenses and the working tree, then publishes the crates
    /// with `cargo publish --workspace`, which publishes them in dependency order
    /// and builds each from its package, then the npm package with `npm publish`,
    /// whose `prepack` script builds it.
    pub fn run(&self) -> Result<()> {
        self.check()?;
        self.crates()?;
        self.npm()
    }

    /// Fails unless every published crate is under [`LICENSE`], and, without
    /// `allow_dirty`, unless the working tree is clean.
    fn check(&self) -> Result<()> {
        for package in self.workspace.published() {
            ensure!(
                package.license.as_deref() == Some(LICENSE),
                "{} would be published under {}: license it under {LICENSE}, or set `publish = false`",
                package.name,
                package.license.as_deref().unwrap_or("no license")
            );
        }
        if !self.allow_dirty {
            let changes =
                self.workspace
                    .git(&["status", "--porcelain", "--untracked-files=all"])?;
            ensure!(
                changes.is_empty(),
                "the working tree has uncommitted changes; commit them, or pass --allow-dirty:\n{changes}"
            );
        }
        Ok(())
    }

    /// Publishes the crates not yet on crates.io at the workspace version.
    fn crates(&self) -> Result<()> {
        let mut cargo = self.workspace.cargo();
        cargo.args(["publish", "--locked", "--workspace"]);
        if self.dry_run {
            cargo.arg("--dry-run");
        } else {
            let mut pending = 0;
            for package in self.workspace.published() {
                if self.on_crates_io(package)? {
                    println!(
                        "{} {} is already on crates.io",
                        package.name, package.version
                    );
                    cargo.args(["--exclude", &package.name]);
                } else {
                    pending += 1;
                }
            }
            if pending == 0 {
                return Ok(());
            }
        }
        if self.allow_dirty {
            cargo.arg("--allow-dirty");
        }
        cargo.run()
    }

    /// Whether crates.io has `package` at its version.
    fn on_crates_io(&self, package: &Package) -> Result<bool> {
        let found = Self::lookup(
            self.workspace
                .cargo()
                .args(["info", "--registry", "crates-io", "--quiet"])
                .arg(format!("{}@{}", package.name, package.version)),
            "could not find",
        )?;
        Ok(found.is_some())
    }

    /// Publishes the npm package, unless npm has its version already.
    fn npm(&self) -> Result<()> {
        let package = self.workspace.npm_package()?;
        let mut npm = self.workspace.command("npm");
        npm.arg("publish")
            .current_dir(self.workspace.root().join(NPM_PACKAGE));
        if self.dry_run {
            npm.arg("--dry-run");
        } else {
            let found = Self::lookup(
                self.workspace.command("npm").args([
                    "view",
                    &format!("{}@{}", package.name, package.version),
                    "version",
                ]),
                "E404",
            )?;
            // npm prints nothing for a missing version of a package it has.
            if found.is_some_and(|version| !version.is_empty()) {
                println!("{} {} is already on npm", package.name, package.version);
                return Ok(());
            }
        }
        npm.run()
    }

    /// Runs a registry lookup: its standard output when it succeeds, and `None`
    /// when it fails with `missing` in its standard error, as for a version the
    /// registry doesn't have. Any other failure is an error.
    fn lookup(command: &mut Command, missing: &str) -> Result<Option<String>> {
        let output = command
            .output()
            .with_context(|| format!("run {command:?}"))?;
        if output.status.success() {
            return Ok(Some(
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            ));
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            stderr.contains(missing),
            "the registry lookup failed ({}): {}",
            output.status,
            stderr.trim()
        );
        Ok(None)
    }
}
