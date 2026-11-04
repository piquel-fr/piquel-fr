# piquel-fr

This repository contains everything under the piquel.fr domain:

- `apps/auth-service`: auth.piquel.fr (OIDC, its sign-in pages, the account
  settings and the developer console), the admin dashboard and the operator CLI.
- `apps/web`: piquel.fr's own site.
- `crates/`: `auth-sdk` (the Rust SDK), `common`, `crypto`, `database`,
  `telemetry` and `ui`.
- `packages/auth`: the TypeScript SDK.
- `infra/`: Dockerfiles and piqueld deployments.
- `tests/browser` (Playwright) and `tests/sdk-vectors` (cases every SDK passes).

This is still very early development. Breaking changes are expected. There are
no real users yet so breaking things doesn't matter.

## Guidelines

When adding a feature, make sure all our surfaces get the feature as
appropriate. This includes the operator CLI (`apps/auth-service/src/cli`), the
developer console, the user settings, the admin panel and the SDKs. All surfaces
should support all features. Don't let anything be left behind.

The CLI is the most complete surface. An admin operation may stay CLI-only
(`App::page()` in `apps/auth-service/src/web/admin/mod.rs` maps it to `None`)
only with a documented reason next to its arm, as `PurgeUser` and
`PruneAuditChain` have.

Generated files are committed; regenerate them with `just db prepare` (SQLx
cache), `just sdk-vectors` and `just sdk-types`. `just validate` is the local
check.
