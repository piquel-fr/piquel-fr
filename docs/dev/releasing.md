# Releasing

A release publishes the SDKs: the Rust crates to
[crates.io](https://crates.io/crates/sourceorigin-auth) and the TypeScript SDK to
[npm](https://www.npmjs.com/package/@sourceorigin/auth). It then tags the commit,
creates its GitHub release and closes its milestone. A maintainer runs it from
their machine with `just release`.

## Versions

SourceOrigin follows [semantic versioning](https://semver.org). Before 1.0:

- a minor release, such as 0.2.0, may change the SDKs' API in ways that break
  existing apps. Its release notes say how to upgrade.
- a patch release, such as 0.1.1, never breaks the API: upgrading to it needs no
  changes.

1.0 comes once the claim and challenge types have settled.

The Rust crates share the workspace version, `version` under
`[workspace.package]` in the root `Cargo.toml`, and are released together. Each
published crate requires the others at exactly that version, so an app never
mixes them. Each release is tagged `v<version>` with the workspace version, such
as `v0.2.0`, on a commit of `main`.

`@sourceorigin/auth` has its own version, `version` in `packages/auth/package.json`.
A release publishes it only when that version isn't on npm yet, so a release
that changes only the Rust crates leaves it alone.

The published crates build with Rust 1.88 or newer: `rust-version` under
`[workspace.package]`, which the `msrv` CI job checks. The npm package needs
Node 22 or newer, its `engines`. Raising either is a change users notice, so the
release notes say so.

## What gets published

| Package | Registry | Source |
| --- | --- | --- |
| `sourceorigin-common` | crates.io | `crates/common`: identifiers and the wire types of auth's protocol |
| `sourceorigin-crypto` | crates.io | `crates/crypto`: the cryptography auth and the Rust SDK share |
| `sourceorigin-auth` | crates.io | `crates/auth-sdk`: the Rust SDK |
| `@sourceorigin/auth` | npm | `packages/auth`: the TypeScript SDK |

These are under the [Apache License 2.0](https://github.com/sourceorigin-dev/sourceorigin/blob/main/LICENSE-APACHE),
which each carries: the crates through a link to the root's `LICENSE-APACHE`,
which Cargo packages as a file, and the npm package as a copy, since npm skips
links. Every other crate is under the PolyForm Noncommercial License and sets
`publish = false`, so it can't be published, nor become a dependency of a crate
that is. `just publish` refuses to publish a crate under any other license.

`sourceorigin-common` is published whole: its server-only features, such as
`sqlx` and `events`, are off by default, so an app builds none of them.

docs.rs builds each crate's documentation with every feature, and labels the
items a feature adds. `sourceorigin-auth`'s front page holds a quick start, its
`notes` example.

`just publish`, which runs `cargo xtask publish`
([`tools/xtask`](https://github.com/sourceorigin-dev/sourceorigin/tree/main/tools/xtask)),
publishes the crates with `cargo publish --workspace`, which publishes them in
dependency order and builds each from its package, as an app would. It then
publishes the npm package with `npm publish`, whose `prepack` script builds it.
It skips a crate or package whose version is published already.

The `package` CI job runs `just publish --dry-run` on every pull request that
changes them: it packages each crate and builds it from its package, and packs
the npm package, without uploading anything. Run it yourself after changing a
manifest, `package.json`, or a file a crate reads at compile time:

```console
just publish --dry-run --allow-dirty
```

## Set up publishing

Do this once, on the machine you release from:

1. On [crates.io](https://crates.io), sign in with GitHub, open **Account
   Settings**, then **API Tokens**, and create a token with the `publish-new`
   and `publish-update` scopes, limited to the crates `sourceorigin-*`. Save it
   for Cargo:

   ```console
   cargo login
   ```

2. On [npm](https://www.npmjs.com), create the `sourceorigin` organization if it
   doesn't exist, so the `@sourceorigin` scope is yours, and make sure your
   account is a member. Then sign in:

   ```console
   npm login
   ```

3. Sign the [GitHub CLI](https://cli.github.com) in to the repository with
   `gh auth login`, and install the Cargo tools, `cargo-semver-checks` among
   them, with `just install-tools`.

You also need what [getting started](getting-started.md) installs: the Rust
toolchain of `rust-toolchain.toml`, Node and pnpm.

## Release a version

1. Open a pull request that sets the new versions:
   - in the root `Cargo.toml`, `version` under `[workspace.package]`, and the
     `version` of every local crate under `[workspace.dependencies]`, keeping the
     `=` of `sourceorigin-common` and `sourceorigin-crypto`. Then run
     `cargo update --workspace` to update `Cargo.lock`.
   - in `packages/auth/package.json`, `version`, when the TypeScript SDK changed.
2. Merge it, and check out the merge commit:

   ```console
   git switch main && git pull
   ```

   Wait for its CI run to pass.
3. Check the release without changing anything:

   ```console
   just release --dry-run
   ```

   It runs every check of the next step, and packages and builds the SDKs
   without uploading them. It then prints the commands the other steps would
   run, and writes the release notes to `target/release-notes-v<version>.md`.
4. Release it:

   ```console
   just release
   ```

   It checks that you are on the latest `main` with a clean working tree, and
   that the version isn't released yet. It runs `cargo semver-checks` against
   the previous release: an API change that breaks it fails here, unless the
   new version allows it, which before 1.0 only a minor release does. It then:

   1. publishes the crates, which takes several minutes, then the npm package.
      npm may ask for a one-time password.
   2. tags the commit `v<version>` and pushes the tag.
   3. creates the GitHub release, titled `SourceOrigin <version>`.
   4. closes the GitHub milestone of the minor version, such as `v0.2` for
      0.2.0. A patch release finds it closed already.

5. For a release that breaks existing apps, edit its GitHub release to say how
   to upgrade.

The release notes list what was published, then the pull requests merged since
the previous release, from the titles of their squashed commits on `main`:
breaking changes (a `!` after the type, as in `feat(sdk)!:`), features (`feat`),
fixes (`fix`), and the rest. A title's scope leads its line, in bold.

## Check that it works

The packages' pages on crates.io and npm list the new versions. Add them to a new
project:

```console
cargo new release-check && cd release-check
cargo add sourceorigin-auth --features axum
cargo build
npm install @sourceorigin/auth
```

docs.rs builds the crates' documentation within a few minutes. The GitHub
release lists the merged pull requests, and the `v<version>` milestone is
closed.

## Troubleshooting

- **`cargo semver-checks` finds a breaking change.** Either undo it, or release
  a new minor version instead: change the versions in a new pull request, and
  start again.
- **Publishing fails partway.** What was published stays published, and the tag
  isn't pushed yet. Fix the cause, such as an expired token, and run
  `just release` again: it skips what is published already.
- **Tagging fails.** Everything is published. If the tag was created but not
  pushed, remove it with `git tag --delete v<version>`. Then run `just release`
  again.
- **Creating the GitHub release or closing the milestone fails.** The tag is
  pushed, so `just release` refuses to run again. Run the `gh` command it printed
  for the step that failed, and the ones after it.
- **A published version is broken.** A version can't be replaced. Yank each
  crate with `cargo yank --version <version> <crate>`, deprecate the npm version
  with `npm deprecate @sourceorigin/auth@<version> "<why>"`, and release a fixed
  patch version.
