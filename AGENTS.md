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
- `docs/`: the documentation book, a user guide and a contributor guide.

This is still very early development. Breaking changes are expected. There are
no real users yet so breaking things doesn't matter.

## Guidelines

When adding a feature, make sure all our surfaces get the feature as
appropriate. This includes the operator CLI (`apps/auth-service/src/cli`), the
developer console, the user settings, the admin panel, the SDKs and the
documentation. All surfaces should support all features. Don't let anything be
left behind. A feature ships with its documentation in the same pull request:
use the `piquel-docs` skill.

The CLI is the most complete surface. An admin operation may stay CLI-only
(`AdminApplication::page()` in `apps/auth-service/src/web/admin/mod.rs` maps
it to `None`) only with a documented reason next to its arm, as `PurgeUser` and
`PruneAuditChain` have.

Pages load no JavaScript of their own. What a page does in the browser is Rust,
in its `crates/ui` components, on Topcoat's runtime: signals, `@event` handlers and
`:` bindings. A browser API Topcoat's expressions cannot name, such as WebAuthn or
the clipboard, gets one `raw!` method on `Browser` in `crates/ui/src/browser.rs`,
never a script file. Topcoat is a fork (see `Cargo.toml`) whose pages carry their
expressions as data, so they run under a policy with no `'unsafe-eval'`.

Generated files are committed; regenerate them with `just db prepare` (SQLx
cache), `just sdk-vectors`, `just sdk-types` and `just docs reference` (the CLI
and configuration references). `just validate` is the local
check, and `just docs` checks the documentation.
