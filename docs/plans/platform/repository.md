# The repository, CI and deployment

This page covers how this repository is reorganized for the platform, how its
databases and piqueld applications are split, and how CI and testing change.

See [the plan's overview](README.md) for what each status means.

## Layout

**Proposed.** piquel's notes ask for `web` to be renamed. The rest was
suggested and not answered in detail.

```text
apps/auth          # was auth-service
apps/sourceorigin  # was web: the platform's API and workers
apps/web           # the frontend app
crates/database    # shared pool, migrations and fixtures; one module per service
packages/ui        # the shared component library
```

- **Origin stays its own repository.** It has a different license: Apache-2.0,
  against PolyForm Noncommercial here. Keeping it apart also keeps SourceOrigin
  an honest consumer of Origin's API.
- **Where integrations live** follows
  [the integrations rule](platform.md#integrations).
- **Telemetry** covers the whole repository, not one service. That is from the
  notes.

## Databases

**Decided:** rename the crate `sourceorigin-repository`. That name is
confusing in a product about repositories.

**Decided,** with piquel tending to agree:

- One database crate, as the notes ask.
- A role for each service, as the notes ask.
- A database for each service, which goes further than the notes. Origin
  Auth's database holds credentials, and it should not share its failures or
  its leaks with another service.

## piqueld applications

**Decided.** Four applications, where the notes had three:

| Application | What it runs |
| --- | --- |
| `sourceorigin-auth` | Origin Auth and its database |
| `sourceorigin-origin` | The Origin nodes, their volumes and the authority key |
| `sourceorigin` | The platform's API, workers and web UI, and their database |
| `sourceorigin-observability` | The telemetry stack, as today |

The reason for the fourth: deploying auth should never restart a node that
holds an authority key.

## CI by area

**Decided.** Split CI by area of the code, not by language. That is from the
notes.

Today's CI groups jobs by language and kind (`checks`, `web`, `rust`,
`rust-lint`, `e2e`, `docker`, `infra`, `docs`), and a `changes` job decides
from the changed paths which ones a pull request needs.

- Restructure into one job per area. Each is a `just <area> ci` recipe with
  its input paths declared.
- That is the shape of Origin's `checks.toml`, where a check declares its
  inputs, and a result carries over to a new revision when those inputs didn't
  change. Moving to `origin-ci` is then mechanical.
- Generate the Rust part of each area's inputs from `cargo metadata`, and list
  the rest by hand: shared recipes, embedded assets, migrations, Dockerfiles,
  JavaScript packages and deployment files. `cargo metadata` knows none of
  those, and a missing input means a result carried over when it shouldn't
  be. Start with broad inputs and narrow them only with a reason.

Where CI runs is in [CI](origin.md#ci): by hand at first, after review.

## Deployment

**Decided.**

- piqueld builds from an Origin acceptance, without going through the git
  mirror. A webhook tells it of a landing.
- Environments stay in piqueld: `main` builds staging, and production is
  promoted from staging.
- A deploy is recorded as a statement. See [deploys](origin.md#deploys).

## Tests to add

**Decided.**

- The platform's tests run against a real `origin serve`.
- A nightly run against the tip of Origin's `main`, to catch API changes
  early.
- A scheduled restore of the latest backup into a scratch node, which then
  verifies every chain.
- Tests that `kill -9` the node during pushes and landings.

## Agent tooling

**Decided** as part of milestone 1. The skills agents use today assume git and
GitHub: filing a pull request, watching it, and commenting on it. They need
equivalents for the Origin workflow before the first repository moves.
