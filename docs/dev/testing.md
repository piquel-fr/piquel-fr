# Testing

`just` runs `validate` by default: the local check before a pull request. The
root `fmt`, `fmt-check`, `lint`, `unused`, `check` and `audit` run the same
recipe in `rust` and `web`. Use individual recipes while iterating:

| Task | Recipe |
| --- | --- |
| Full validation (format, Clippy/ESLint, unused code and dependencies, Rust/TypeScript checks, Rust and SDK unit tests, doc tests, audits) | `just validate` |
| Format Rust and web / check formatting | `just fmt` / `just fmt-check` |
| Rust / TypeScript checks (tsc, the pages' scripts' JSDoc types included) | `just rust check` / `just web check` |
| Clippy and ESLint, warnings denied; `publint` and `attw` on the built TypeScript SDK | `just lint` (`just rust lint` / `just web lint`) |
| Unused Rust dependencies (cargo-machete); unused web files, exports and dependencies (knip, entry points in `knip.json`) | `just unused` (`just rust unused` / `just web unused`) |
| Regenerate the SDK vectors / the TypeScript SDK's wire types / the generated documentation | `just sdk-vectors` / `just sdk-types` / `just docs reference` |
| Unit tests / focused package tests | `just test` / `just test -p auth-service` |
| TypeScript SDK tests with coverage, the shared vectors included / the built SDK in Node, Bun and workerd | `just web test` / `just web smoke` |
| Documentation tests | `just doc-test` |
| Build the book and check its links / serve it while you write | `just docs` / `just docs serve` |
| Database integration tests and query cache check, in a scratch cluster | `just db test` |
| Rust coverage per crate over every test, database tests included, in a scratch cluster; `target/lcov.info` | `just coverage` |
| Query cache check alone, against a migrated `TEST_DATABASE_URL` | `just db prepare-check` |
| Regenerate the query cache after changing SQL or migrations | `just db prepare` |
| Run any command against a scratch cluster | `just db scratch -- psql` |
| Browser tests against running servers | `just web test-browser` |
| Dependency audits | `just audit` (`just rust audit` runs cargo-deny, `just web audit` pnpm) |
| Debug binary / release binary | `just rust build` / `just build` |
| Run with caller-provided auth configuration | `just auth serve`, `just db migrate`, `just auth invite create --expires-in 7d`, `just auth admin list` |

CI runs these recipes on every pull request whose changes they can affect,
including the database and browser tests, and on every push to `main`.
Require its `ci` check: it summarizes the others. CI runs the Rust tests through
`just coverage`, printing coverage per crate and uploading `lcov.info` as the
`rust-coverage` artifact; `just web test` prints the TypeScript SDK's coverage.
Coverage is reported only; nothing fails on it.

Web code is formatted by Prettier and linted by type-aware ESLint (typescript-eslint
`strictTypeChecked`), configured once at the repository root.
Test recipes forward extra arguments to nextest or Playwright, including quoted
filter expressions. `just auth run` forwards arguments to the auth binary.
Cargo embeds the stylesheet, the pages' scripts and migrations during compilation.

Queries in `crates/database` are checked at compile time against
`crates/database/.sqlx/`. Changing a query's text without `just db prepare` fails
the build, so `just validate` catches it without a database. Commit the cache with
the query or migration that changed it.

Database integration tests are explicitly marked ignored for the ordinary test
command. `just db test` runs them in a throwaway PostgreSQL cluster that listens
only on a private Unix socket and is deleted afterwards, then runs
`just db prepare-check` against the migrated
schema, which catches a migration that breaks a cached query and a cached query
the code no longer uses. CI runs that check
after its database tests. To use an existing disposable database
instead, set `TEST_DATABASE_URL`; TCP URLs must include `sslmode=disable` or
`sslmode=verify-full`. It must not target a real account database.
For browser validation against the actual binary, see
[the browser tests' README](https://github.com/piquel-fr/piquel-fr/blob/main/tests/browser/README.md).

Backend tests use signed software-authenticator responses and local GitHub/Google
HTTP fixtures, including real signed Google ID tokens. Browser tests use Chromium's
synced virtual authenticator and real Rust/PostgreSQL endpoints. Actual Apple/Google
device synchronization and live provider credentials require separate validation;
virtual authenticators and provider fixtures do not establish that evidence.
