# sourceorigin

SourceOrigin is the project and its site. Origin Auth is its sign-in service
(sign-in, the account settings, the developer console, the admin dashboard and
the SDKs), and a person's account is an Origin Account. Use these names in
everything people read.

This repository contains everything under the sourceorigin.dev domain:

- `apps/auth-service`: auth.sourceorigin.dev (OIDC, its sign-in pages, the account
  settings and the developer console), the admin dashboard and the operator CLI.
- `apps/web`: sourceorigin.dev's own site.
- `crates/`: `auth-sdk` (the Rust SDK), `common`, `crypto`, `database`,
  `telemetry` and `ui`.
- `packages/auth`: the TypeScript SDK.
- `infra/`: Dockerfiles and piqueld deployments.
- `tools/xtask`: `cargo xtask`, which publishes the SDKs and releases a version
  (`just publish`, `just release`).
- `tests/browser` (Playwright) and `tests/sdk-vectors` (cases every SDK passes).
- `docs/`: the documentation book, a user guide and a contributor guide.
  `docs/plans/` holds plans for work that isn't built yet, outside the book:
  read `docs/plans/platform/README.md` before working on the SourceOrigin
  platform.

This is still very early development. Breaking changes are expected. There are
no real users yet so breaking things doesn't matter.

## Guidelines

When adding a feature, make sure all our surfaces get the feature as
appropriate. This includes the operator CLI (`apps/auth-service/src/cli`), the
developer console, the user settings, the admin panel, the SDKs and the
documentation. All surfaces should support all features. Don't let anything be
left behind. A feature ships with its documentation in the same pull request:
use the `sourceorigin-docs` skill.

The CLI is the most complete surface. An admin operation may stay CLI-only
(`AdminApplication::page()` in `apps/auth-service/src/web/admin/mod.rs` maps
it to `None`) only with a documented reason next to its arm, as `PurgeUser` and
`PruneAuditChain` have.

Generated files are committed; regenerate them with `just db prepare` (SQLx
cache), `just sdk-vectors`, `just sdk-types` and `just docs reference` (the CLI
and configuration references). `just validate` is the local
check, and `just docs` checks the documentation.
