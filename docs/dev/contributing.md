# Contributing

This page covers how a change gets from your branch to `main`. Questions are
welcome at [contact@piquel.fr](mailto:contact@piquel.fr). Report a security
vulnerability privately, as the
[security policy](https://github.com/piquel-fr/piquel-fr/blob/main/SECURITY.md)
describes, never in a public issue.

## Before you start

Open an issue first for anything larger than a fix, so the design is agreed
before the code. piquel.fr is still in early development: breaking changes are
expected, and there are no real users whose data a change must migrate.

## Every surface gets the feature

A feature reaches every surface it applies to, in the same pull request or the
ones right after:

- the operator CLI (`apps/auth-service/src/cli`), the most complete surface;
- the user settings, at `auth.piquel.fr/settings`;
- the developer console, at `auth.piquel.fr/developers`;
- the admin dashboard, at `admin.piquel.fr`;
- the Rust and TypeScript SDKs, with [shared test vectors](testing.md);
- the documentation, in the [user guide](../user/introduction.md) and this one.

An admin operation may stay CLI-only only with a documented reason next to its
arm in `AdminApplication::page()` (`apps/auth-service/src/web/admin/mod.rs`), as
`PurgeUser` and `PruneAuditChain` have.

## Generated files

Generated files are committed, and `just test` fails while one is stale.
Regenerate them in the same commit as their source:

| Files | Source | Recipe |
| --- | --- | --- |
| `crates/database/.sqlx/` | SQL queries and migrations | `just db prepare` |
| `tests/sdk-vectors/` | `crates/common/tests/sdk_vectors.rs` | `just sdk-vectors` |
| `packages/auth/src/protocol.ts` | the wire types in `crates/common` | `just sdk-types` |
| `docs/dev/operations/variables/`, `docs/dev/operations/cli-commands.md` | the variables' doc comments, and the CLI's clap definitions | `just docs reference` |

## Pull requests

- Keep a pull request to one change. Stack dependent ones, each on the last.
- Title it as a [Conventional Commit](https://www.conventionalcommits.org) that
  says what changes for whoever uses it, such as
  `feat(auth): every account gets an inbox, so notices about it no longer live only in email`.
  The title becomes the commit on `main`.
- Describe what was wrong, what changes, and how you tested it, including what
  you didn't test.
- Run `just validate` first, and the database or browser tests when the change
  can affect them; see [testing](testing.md).
- Update the documentation in the same pull request; see
  [changing the documentation](documentation.md).

`main` merges through a queue: it tests each pull request on top of the latest
`main` before merging it, so two pull requests that pass alone can't break
`main` together. The `ci` check is the one to require.
