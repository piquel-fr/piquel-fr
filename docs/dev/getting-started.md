# Getting started

This page sets up a checkout of sourceorigin so you can build it, test it and run
your changes on a preview.

## Install the tools

- Rust, at the version `rust-toolchain.toml` pins.
- [just](https://just.systems) 1.42 or later. Every task runs through it.
- Node 24 or later and pnpm, for the web tools and the TypeScript SDK. The
  workspace pins pnpm's version.
- The PostgreSQL 18 server binaries (`initdb`, `pg_ctl`), for the database
  tests and `just coverage`.
- For previews, [piquelctl](https://docs.piqueld.dev), piqueld's CLI
  (`cargo install --locked piquelctl`), signed in to the daemon that runs
  SourceOrigin's previews with a token that has `previews:deploy` and
  `previews:delete` on `sourceorigin`. Ask [contact@sourceorigin.dev](mailto:contact@sourceorigin.dev)
  for one.

Then install the rest:

```console
just install         # Prettier, ESLint, tsc, knip and Playwright
just install-tools   # cargo-nextest, cargo-llvm-cov, cargo-deny, cargo-machete, sqlx-cli, mdBook and lychee
```

Recipes are grouped into the `rust`, `web`, `db`, `auth`, `infra` and `docs`
modules under `just/`. `just --list --list-submodules` shows every recipe.

## Build

```console
just build
```

Building needs no database: SQL is checked against the committed query cache in
`crates/database/.sqlx/`. It needs no Node either, because auth builds no
JavaScript.

The executables are `target/release/auth-service` and
`target/release/sourceorigin-web`. Both embed the stylesheet (`crates/ui/assets/style/`,
its parts joined into one file) and its typefaces (`crates/ui/assets/fonts`,
under the SIL Open Font License). Auth also embeds its pages' scripts
(`apps/auth-service/assets/`), and sourceorigin-web the policies
(`apps/web/assets/policies/`). Rebuild after changing them.

## Run your changes

Develop through an HTTPS preview on piqueld:

```console
just preview
```

This snapshots the checkout, uncommitted changes included, builds auth and the
admin dashboard, applies migrations, and prints the preview's URLs. The settings
are at `/settings` on its auth URL, the developer console at `/developers`, and
the documentation on its docs URL.
The preview has its own database and keys, and its URLs work from any device on
the tailnet. Run the same command again after changing code, and
`just preview-delete` to remove it. See [deploying](operations/deploying.md#previews)
for what a preview runs.

Agents use the `preview` and `test-change` skills in `.agents/skills/`, which
follow the same steps.

## Next

- [Contributing](contributing.md): how a change gets to `main`.
- [Testing](testing.md): what to run before you open a pull request.
- [Architecture](architecture/overview.md): how the repository fits together.
