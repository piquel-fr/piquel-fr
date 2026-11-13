# Contributing

This page covers how a change gets from your branch to `main`. Questions are
welcome at [contact@sourceorigin.dev](mailto:contact@sourceorigin.dev). Report a security
vulnerability privately, as the
[security policy](https://github.com/sourceorigin-dev/sourceorigin/blob/main/SECURITY.md)
describes, never in a public issue.

## Before you start

Open an issue first for anything larger than a fix, so the design is agreed
before the code. SourceOrigin is still in early development: breaking changes are
expected, and there are no real users whose data a change must migrate.

## Every surface gets the feature

A feature reaches every surface it applies to:

- the operator CLI (`apps/auth-service/src/cli`), the most complete surface;
- the user settings, at `auth.sourceorigin.dev/settings`;
- the developer console, at `auth.sourceorigin.dev/developers`;
- the admin dashboard, at `admin.sourceorigin.dev`;
- the Rust and TypeScript SDKs, which share
  [test vectors](testing.md#sdk-test-vectors);
- the documentation, in the [user guide](../user/introduction.md) and this one.

An admin operation may stay CLI-only only with a documented reason next to its
arm in `AdminApplication::page()` (`apps/auth-service/src/web/admin/mod.rs`), as
`PurgeUser` and `PruneAuditChain` have.

## Generated files

Generated files are committed, and CI fails while one is stale. Regenerate them
in the same commit as their source:

| Files | Source | Recipe |
| --- | --- | --- |
| `crates/database/.sqlx/` | SQL queries and migrations | `just db prepare` |
| `tests/sdk-vectors/` | `crates/crypto/tests/sdk_vectors.rs` | `just sdk-vectors` |
| `packages/auth/src/protocol.ts` | the wire types in `crates/common` | `just sdk-types` |
| `docs/dev/operations/variables/`, `docs/dev/operations/cli-commands.md` | the variables' doc comments, and the CLI's clap definitions | `just docs reference` |

List a new generated file in `.gitattributes`, so GitHub collapses it in diffs.

## Pull requests

- Keep a pull request to one change. Stack dependent ones, each on the last.
- Title it as a [Conventional Commit](https://www.conventionalcommits.org) that
  says what changes for whoever uses it, such as
  `feat(auth): every account gets an inbox, so notices about it no longer live only in email`.
  Pull requests are squashed, and the title becomes the commit on `main`.
- Describe what was wrong, what changes, and how you tested it, including what
  you didn't test.
- Run `just validate` first, and the database or browser tests when the change
  can affect them; see [testing](testing.md).
- Update the documentation in the same pull request; see
  [changing the documentation](documentation.md).

`main` merges through a queue, which needs the `ci` check to pass. The queue
tests each pull request on top of the latest `main` before merging it, so two
pull requests that pass alone can't break `main` together. See
[what CI runs](testing.md#what-ci-runs).
