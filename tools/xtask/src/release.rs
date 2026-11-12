//! `cargo xtask release`: releases the workspace version from the latest
//! `main`. See docs/dev/releasing.md.

use crate::{Run, Workspace, publish::Publish};
use anyhow::{Context, Result, bail, ensure};
use std::{fmt::Write as _, fs};

/// A release of the workspace version, from `HEAD`.
pub struct Release<'a> {
    workspace: &'a Workspace,
    /// The workspace version, such as `0.2.0`.
    version: String,
    /// The latest release tag `HEAD` contains, such as `v0.1.0`; `None` before
    /// the first release.
    previous: Option<String>,
    /// Runs the checks and the publish dry run, and only prints what the other
    /// steps would do.
    dry_run: bool,
}

impl<'a> Release<'a> {
    pub fn new(workspace: &'a Workspace, dry_run: bool) -> Result<Self> {
        let tags = workspace.git(&[
            "tag",
            "--list",
            "v*",
            "--merged",
            "HEAD",
            "--sort=-v:refname",
        ])?;
        Ok(Self {
            workspace,
            version: workspace.version()?.to_owned(),
            previous: tags.lines().next().map(str::to_owned),
            dry_run,
        })
    }

    /// Checks that `HEAD` is the latest `origin/main`, that the version isn't
    /// tagged yet, and that the crates' API changes fit it. Then publishes the
    /// SDKs, tags `HEAD` `v<version>`, pushes the tag, creates its GitHub
    /// release, and closes its minor version's milestone, such as `v0.2`.
    pub fn run(&self) -> Result<()> {
        self.check()?;
        self.semver()?;
        Publish {
            workspace: self.workspace,
            dry_run: self.dry_run,
            allow_dirty: false,
        }
        .run()?;
        let tag = self.tag();
        let title = format!("SourceOrigin {}", self.version);
        let notes = self
            .workspace
            .root()
            .join(format!("target/release-notes-{tag}.md"));
        fs::write(&notes, self.notes()?).with_context(|| format!("write {}", notes.display()))?;
        println!("the release notes are in {}", notes.display());
        let notes = notes.to_string_lossy();
        self.step("git", &["tag", "--annotate", &tag, "--message", &title])?;
        self.step("git", &["push", "origin", &tag])?;
        self.step(
            "gh",
            &[
                "release",
                "create",
                &tag,
                "--verify-tag",
                "--title",
                &title,
                "--notes-file",
                &notes,
            ],
        )?;
        self.close_milestone()
    }

    /// `v<version>`, the release's tag.
    fn tag(&self) -> String {
        format!("v{}", self.version)
    }

    /// Fails unless `HEAD` is the latest `origin/main`, and the version isn't
    /// tagged on `origin` yet.
    fn check(&self) -> Result<()> {
        self.workspace.git(&["fetch", "origin", "main"])?;
        ensure!(
            self.workspace.git(&["rev-parse", "HEAD"])?
                == self.workspace.git(&["rev-parse", "FETCH_HEAD"])?,
            "release from the latest origin/main: run `git switch main && git pull`"
        );
        let tag = self.tag();
        let tagged =
            self.workspace
                .git(&["ls-remote", "--tags", "origin", &format!("refs/tags/{tag}")])?;
        ensure!(
            tagged.is_empty(),
            "{tag} is already released; set a new version in Cargo.toml first"
        );
        Ok(())
    }

    /// Fails when a published crate's API breaks compatibility with the previous
    /// release without a version that allows it, by `cargo semver-checks`.
    fn semver(&self) -> Result<()> {
        let Some(previous) = &self.previous else {
            println!("no earlier release to check the crates' API against");
            return Ok(());
        };
        let mut cargo = self.workspace.cargo();
        cargo.args([
            "semver-checks",
            "--all-features",
            "--baseline-rev",
            previous,
        ]);
        for package in self.workspace.published() {
            cargo.args(["--package", &package.name]);
        }
        cargo.run()
    }

    /// The release notes: what was published, then the pull requests merged
    /// since the previous release, by the titles' Conventional Commits type.
    fn notes(&self) -> Result<String> {
        let npm = self.workspace.npm_package()?;
        let mut notes = String::from("Published:\n\n");
        for package in self.workspace.published() {
            let (name, version) = (&package.name, &package.version);
            writeln!(
                notes,
                "- [`{name}` {version}](https://crates.io/crates/{name}/{version}) on crates.io"
            )?;
        }
        let (name, version) = (&npm.name, &npm.version);
        writeln!(
            notes,
            "- [`{name}` {version}](https://www.npmjs.com/package/{name}/v/{version}) on npm"
        )?;

        let range = self
            .previous
            .as_ref()
            .map_or_else(|| "HEAD".to_owned(), |tag| format!("{tag}..HEAD"));
        let log =
            self.workspace
                .git(&["log", "--first-parent", "--reverse", "--format=%s", &range])?;
        let mut sections = Section::ALL.map(|section| (section, String::new()));
        for subject in log.lines() {
            let (section, line) = Section::of(subject);
            writeln!(sections[section as usize].1, "- {line}")?;
        }
        for (section, lines) in sections.iter().filter(|(_, lines)| !lines.is_empty()) {
            write!(notes, "\n## {}\n\n{lines}", section.title())?;
        }
        Ok(notes)
    }

    /// Closes the open milestone of the release's minor version, if any: a patch
    /// release finds it closed already.
    fn close_milestone(&self) -> Result<()> {
        let mut parts = self.version.split('.');
        let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
            bail!("the version {} has no minor version", self.version);
        };
        let title = format!("v{major}.{minor}");
        let number = self
            .workspace
            .command("gh")
            .args([
                "api",
                "--paginate",
                "repos/{owner}/{repo}/milestones",
                "--jq",
            ])
            .arg(format!(".[] | select(.title == \"{title}\") | .number"))
            .read()?;
        if number.is_empty() {
            println!("no open GitHub milestone named {title} to close");
            return Ok(());
        }
        self.step(
            "gh",
            &[
                "api",
                "--method",
                "PATCH",
                "--silent",
                &format!("repos/{{owner}}/{{repo}}/milestones/{number}"),
                "--field",
                "state=closed",
            ],
        )
    }

    /// Runs `program` with `args` from the workspace root, failing unless it
    /// succeeds, or only prints the command in a dry run. The command is printed
    /// quoted, so it can be run again by hand.
    fn step(&self, program: &str, args: &[&str]) -> Result<()> {
        let mut command = self.workspace.command(program);
        command.args(args);
        if self.dry_run {
            println!("would run: {command:?}");
            return Ok(());
        }
        println!("running: {command:?}");
        command.run()
    }
}

/// A section of the release notes, in their order.
#[derive(Clone, Copy)]
enum Section {
    /// Titles marked breaking, as `feat(sdk)!: …`.
    Breaking,
    /// `feat`.
    Features,
    /// `fix`.
    Fixes,
    /// Every other type, and titles without one.
    Other,
}

impl Section {
    const ALL: [Self; 4] = [Self::Breaking, Self::Features, Self::Fixes, Self::Other];

    fn title(self) -> &'static str {
        match self {
            Self::Breaking => "Breaking changes",
            Self::Features => "Features",
            Self::Fixes => "Fixes",
            Self::Other => "Other changes",
        }
    }

    /// The section a pull request's title goes in, and its line there: the title
    /// without its type, led by its scope in bold, such as
    /// `**sdk:** cookie keys accept hex (#502)`.
    fn of(subject: &str) -> (Self, String) {
        let parsed = subject.split_once(": ").and_then(|(head, description)| {
            let (head, breaking) = head
                .strip_suffix('!')
                .map_or((head, false), |head| (head, true));
            let (kind, scope) = match head.split_once('(') {
                Some((kind, scope)) => (kind, Some(scope.strip_suffix(')')?)),
                None => (head, None),
            };
            if kind.is_empty() || !kind.bytes().all(|byte| byte.is_ascii_lowercase()) {
                return None;
            }
            let section = match kind {
                _ if breaking => Self::Breaking,
                "feat" => Self::Features,
                "fix" => Self::Fixes,
                _ => Self::Other,
            };
            let line = scope.map_or_else(
                || description.to_owned(),
                |scope| format!("**{scope}:** {description}"),
            );
            Some((section, line))
        });
        parsed.unwrap_or_else(|| (Self::Other, subject.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::Section;

    /// Titles go in their type's section without the type, led by their scope.
    #[test]
    fn titles_are_grouped_by_type() {
        let line = |subject| {
            let (section, line) = Section::of(subject);
            (section.title(), line)
        };
        assert_eq!(
            line("feat(sdk): cookie keys accept hex (#502)"),
            (
                "Features",
                "**sdk:** cookie keys accept hex (#502)".to_owned()
            )
        );
        assert_eq!(line("fix: a fix (#1)"), ("Fixes", "a fix (#1)".to_owned()));
        assert_eq!(
            line("refactor(auth)!: drop the v1 routes (#2)"),
            (
                "Breaking changes",
                "**auth:** drop the v1 routes (#2)".to_owned()
            )
        );
        assert_eq!(
            line("add AGENTS.md"),
            ("Other changes", "add AGENTS.md".to_owned())
        );
        assert_eq!(
            line("Merge: things"),
            ("Other changes", "Merge: things".to_owned())
        );
    }
}
