# The SourceOrigin platform plan

This folder records the plan for the SourceOrigin platform: the service that
hosts [Origin](https://github.com/sourceorigin-dev/origin) repositories. It was
written from a planning discussion on 12 and 13 November 2026, and it keeps
every decision, proposal and open question from that discussion.

It is a plan, not documentation. It says what we intend to build, not how
SourceOrigin works today. Nothing here is listed in `docs/SUMMARY.md`, so none
of it is published in the book.

## The goal

Move all of piquel's development off Git and GitHub onto SourceOrigin, as early
as possible. Using the platform every day is the fastest way to find its
problems and to get ideas for it. That is why the platform starts almost at the
same time as Origin itself.

## The pages

| Page | What it holds |
| --- | --- |
| [Roadmap](roadmap.md) | The milestones, what each one waits for, and where the three repositories stood when this was written |
| [What the platform needs from Origin](origin.md) | Identity, authorization, keys, the git mirror, events, hidden paths, and what running more than one server needs |
| [The platform](platform.md) | What SourceOrigin stores, its services, hosting, notifications, integrations and product ideas |
| [The frontend](frontend.md) | Why Topcoat goes, what replaces it, and the experiment that picks between React and SvelteKit |
| [The repository, CI and deployment](repository.md) | The layout of this repository, the databases, the piqueld applications, CI by area and the tests to add |
| [The original notes](notes.md) | piquel's notes that started the discussion, unchanged |

## How to read a status

Every item carries one of these:

- **Decided**: piquel agreed to it in the discussion.
- **Proposed**: suggested, and not answered yet. Treat it as a default, not a
  decision.
- **Open**: needs more thought before anyone can decide.
- **Deferred**: agreed, but for a later milestone.
- **Dropped**: considered and rejected. The reason is kept so it isn't proposed
  again.

## Decisions at a glance

| Topic | Decision | Status | Page |
| --- | --- | --- | --- |
| Where data lives | Reviews, CI results, deploys and releases are Origin statements. PostgreSQL holds only what can't live in a repository | Decided | [platform](platform.md#data-lives-in-origin) |
| Permissions | No second permission system. The permissions page edits `policy.toml` and lands the change on `policy` | Decided | [platform](platform.md#permissions) |
| Sign-in for Origin | Stock Origin validates tokens from any OpenID Connect issuer. SourceOrigin hosting is stock Origin pointed at Origin Auth | Decided | [origin](origin.md#sign-in-with-openid-connect) |
| Principals | Records hold an opaque, stable ID scoped by issuer, never a name | Decided | [origin](origin.md#principals) |
| Display names | The identity provider is the only source of names. Origin asks it through a lookup | Decided | [origin](origin.md#display-names) |
| Readable policy files | How `policy.toml` stays readable when it holds IDs | Open | [origin](origin.md#readable-policy-files) |
| Authorization in Origin | Origin's defaults are too open for a public host. piquel is designing a proper authorization system | Open | [origin](origin.md#authorization) |
| Hosting | One Origin node with a local volume. No replicas for now | Decided | [origin](origin.md#one-node-first) |
| Authority key | One node key for every hosted repository, mounted as a piqueld secret. Keys per repository come later | Decided | [origin](origin.md#authority-keys) |
| Backups | piqueld's scheduled volume backups. Continuous backup comes with object storage, not from piqueld | Decided | [platform](platform.md#hosting-and-backups) |
| Git mirror | A one-way Origin-to-git mirror, built before the web UI, for Nix, Cargo and backup | Decided | [origin](origin.md#the-git-mirror) |
| CI | No CI engine. `origin-ci` runs on piquel's machine. macOS runs by hand at first | Decided | [repository](repository.md#ci-by-area) |
| Deploys | piqueld builds from Origin directly. Deploys are recorded as statements. `production` as a target waits for a new policy rule | Decided | [origin](origin.md#deploys) |
| Release channels | Nightly and stable map to targets for the CLI and the SDKs. The hosted service uses feature flags on one version | Deferred | [origin](origin.md#releases-and-channels) |
| Frontend framework | Topcoat goes, for auth too. An experiment picks between React with TanStack Start and SvelteKit. Leptos is out | Decided | [frontend](frontend.md) |
| Diff performance | Diffs must be as fast as Pierre's diffshub | Decided | [frontend](frontend.md#what-pierre-provides) |
| Integrations | A worker that needs only Origin's API is an Origin plugin. One that needs accounts, tenancy or billing lives here | Decided | [platform](platform.md#integrations) |
| T3 Code | Origin appears in piquel's T3 Code fork only as a pull request provider. It plays no part in choosing the frontend | Deferred | [platform](platform.md#t3-code) |
| Repository layout | Origin stays its own repository. `apps/web` is renamed, the database crate is renamed, each service gets its own database | Decided in part | [repository](repository.md) |
| piqueld applications | Four: `sourceorigin-auth`, `sourceorigin-origin`, `sourceorigin` and `sourceorigin-observability` | Decided | [repository](repository.md#piqueld-applications) |
| Issues as changes | Not built. No project management system for now | Dropped | [platform](platform.md#dropped) |

## What comes next

The discussion ended with the plan agreed in outline. The next step is to go
into practical depth on each part. Writing milestone 0 as issues in the v0.2
milestone was offered and declined for now.

## Open questions

- How `policy.toml` stays readable once principals are IDs. See
  [readable policy files](origin.md#readable-policy-files).
- What Origin's authorization system looks like. See
  [authorization](origin.md#authorization).
- Which frontend framework wins the experiment. See
  [the experiment](frontend.md#the-experiment).
- Whether v0.2 is exactly milestones 0 and 1. It was proposed and not answered.
  See [the roadmap](roadmap.md#milestones).
- How deeply T3 Code depends on git, which decides how much the fork must
  change. It was not measured.
- Everything in [not discussed yet](platform.md#not-discussed-yet).
