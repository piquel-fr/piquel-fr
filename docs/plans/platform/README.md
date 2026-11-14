# The SourceOrigin platform plan

This folder records the plan for the SourceOrigin platform: the service that
hosts [Origin](https://github.com/sourceorigin-dev/origin) repositories. It was
written from a planning discussion on 12 and 13 November 2026, and it keeps
every decision, proposal and open question from that discussion.

It is a plan, not documentation. It says what we intend to build, not how
SourceOrigin works today. Nothing here is listed in `docs/SUMMARY.md`, so none
of it is published in the book.

## Keeping it current

This is the design document of the whole product while it is being planned.
Update it in the same session whenever something is decided, changed or
dropped, and push the change to its pull request,
[sourceorigin#527](https://github.com/sourceorigin-dev/sourceorigin/pull/527).
A decision that only lives in a conversation is lost.

## The goal

Move all of piquel's development off Git and GitHub onto SourceOrigin, as early
as possible. Using the platform every day is the fastest way to find its
problems and to get ideas for it. That is why the platform starts almost at the
same time as Origin itself.

## The pages

| Page | What it holds |
| --- | --- |
| [Roadmap](roadmap.md) | The milestones, what each one waits for, and where the three repositories stood when this was written |
| [What the platform needs from Origin](origin.md) | Identity, authorization, keys, the registry, the git mirror, hidden paths, and what running more than one server needs |
| [The platform](platform.md) | What SourceOrigin stores, its services, hosting, notifications, integrations and product ideas |
| [The frontend](frontend.md) | Why Topcoat goes, what replaces it, and the experiment that picks between React and SvelteKit |
| [The repository, CI and deployment](repository.md) | The layout of this repository, the databases, the piqueld applications, CI by area and the tests to add |
| [The council review](review.md) | What three reviewers found in this plan, what was decided about each finding, and what is still unanswered |
| [The original notes](notes.md) | piquel's notes that started the discussion, unchanged |

Issues are written with their repository: origin#54 is in
`sourceorigin-dev/origin`, sourceorigin#68 in this repository, and piqueld#340
in `sourceorigin-dev/piqueld`.

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
| Sign-in for Origin | Stock Origin validates tokens from an OpenID Connect issuer. On SourceOrigin, every caller signs in through Origin Auth | Decided | [origin](origin.md#sign-in-with-openid-connect) |
| Principals | Records hold an opaque, stable ID, never a name. One issuer per repository, named in its policy | Decided | [origin](origin.md#principals) |
| Display names | The identity provider is the only source of names. Origin asks it through a lookup | Decided | [origin](origin.md#display-names) |
| Readable policy files | How `policy.toml` stays readable when it holds IDs | Open | [origin](origin.md#readable-policy-files) |
| Authorization in Origin | Origin's defaults are too open for a public host. piquel is designing a proper authorization system | Open | [origin](origin.md#authorization) |
| Hosting | One Origin node with a local volume. No replicas for now. Every environment has its own node and key | Decided | [origin](origin.md#one-node-first) |
| Authority key | One node key for every hosted repository, mounted as a piqueld secret. Rotation and recovery are still to design | Decided in part | [origin](origin.md#authority-keys) |
| Formats | Records carry a time, a repository's identity is in its genesis, content can be redacted, and Origin has ignore files | Decided | [origin](origin.md#ignore-files) |
| Origin's roadmap | Four milestones in `sourceorigin-dev/origin`, with epics as parent issues: v0.1 the prototype merged, v0.2 hostable, v0.3 daily use, v1.0 the rest | Decided | [roadmap](roadmap.md#origins-milestones) |
| The open pull requests | Nothing in the stack has to change for hosting. piquel reviews and merges it from the bottom | Decided | [roadmap](roadmap.md#origin) |
| Finding repositories | The server reads which repositories exist from a registry named in its configuration, one repository at a time, and caches the answer. Creating one is an explicit call | Decided | [origin](origin.md#finding-repositories) |
| Repositories | Private when created, public by the owner's choice, three per account unless an administrator changes it. A public one can be cloned without an account | Decided | [platform](platform.md#projects) |
| Colocated mode | A working copy that is an Origin workspace and a git worktree at once, so git tools can read it. Built in Origin's v0.2 | Decided | [origin](origin.md#colocated-mode) |
| Encrypted remotes | The client has no TLS, which blocks a hosted node. Fixed in v0.2 | Decided | [origin](origin.md#operations) |
| Backups | piqueld's backups with the node stopped, a restore drill, and a restored node that takes back what it signed | Decided | [platform](platform.md#hosting-and-backups) |
| Git mirror | A one-way Origin-to-git mirror, built before the web UI, for Nix, Cargo and as the fallback. It continues the existing git history | Decided | [origin](origin.md#the-git-mirror) |
| CI | No automatic CI at first. Checks are run by hand, after review. A worker in a sandbox comes later | Decided | [origin](origin.md#ci) |
| Deploys | piqueld builds from Origin, told by a webhook. Deploys are recorded as statements. Environments stay in piqueld | Decided | [origin](origin.md#deploys) |
| Hidden paths | Only folders can be hidden, each with a nonce. Built once the mirror is no longer needed | Decided | [origin](origin.md#hidden-paths) |
| Release channels | Nightly and stable map to targets for the CLI and the SDKs. The hosted service uses feature flags on one version | Deferred | [origin](origin.md#releases-and-channels) |
| Frontend framework | Topcoat goes. An experiment picks between React with TanStack Start and SvelteKit. Leptos is out. The product renders on a server | Decided | [frontend](frontend.md) |
| Origin Auth's pages | Sign-in, consent and recovery stay in Origin Auth. The settings, on a hostname of their own, the developer console and the admin dashboard move to the product's frontend, as one admin app for both services | Decided | [review](review.md#the-auth-port-and-the-admin-dashboard) |
| Between services | Calls between the node and SourceOrigin's services use private listeners, linked through piqueld | Decided | [origin](origin.md#between-services) |
| Private changes | A change can be made private by choice, for sensitive fixes | Decided | [origin](origin.md#private-changes) |
| Diff performance | Diffs must be as fast as Pierre's diffshub. Origin gains a diff endpoint | Decided | [frontend](frontend.md#what-pierre-provides) |
| Reviewed marks | Which files a person has reviewed is private state in PostgreSQL, not statements | Decided | [platform](platform.md#marking-files-as-reviewed) |
| Integrations | A worker that needs only Origin's API is an Origin plugin. One that needs accounts, tenancy or billing lives here | Decided | [platform](platform.md#integrations) |
| T3 Code | Origin appears in piquel's T3 Code fork only as a pull request provider. It plays no part in choosing the frontend | Deferred | [platform](platform.md#t3-code) |
| Repository layout | Origin stays its own repository. `apps/web` is renamed, the database crate is renamed, each service gets its own database | Decided in part | [repository](repository.md) |
| piqueld applications | Four: `sourceorigin-auth`, `sourceorigin-origin`, `sourceorigin` and `sourceorigin-observability` | Decided | [repository](repository.md#piqueld-applications) |
| Issues | Issues live in Linear. No project management system is built | Decided | [platform](platform.md#dropped) |
| Issues as changes, `production` as a target, reviewed marks as statements | Not built | Dropped | [platform](platform.md#dropped) |

## What comes next

The focus is on getting Origin ready. Its roadmap is now issues and epics in
`sourceorigin-dev/origin`: see [Origin's milestones](roadmap.md#origins-milestones).
piquel reviews and merges the open stack, and the two known defects went to
the thread that owns the stack.

Writing SourceOrigin's own milestone 0 as issues in its v0.2 milestone was
offered and declined for now.

## Open questions

- Everything under [still to answer](review.md#still-to-answer) in the council
  review.
- How `policy.toml` stays readable once principals are IDs. See
  [readable policy files](origin.md#readable-policy-files).
- What Origin's authorization system looks like. See
  [authorization](origin.md#authorization).
- How authority keys are rotated and recovered. See
  [authority keys](origin.md#authority-keys).
- Which frontend framework wins the experiment. See
  [the experiment](frontend.md#the-experiment).
- Whether v0.2 is exactly milestones 0 and 1. It was proposed and not answered.
  See [the roadmap](roadmap.md#milestones).
- How deeply T3 Code depends on git, which decides how much the fork must
  change. It was not measured.
- Everything in [not discussed yet](platform.md#not-discussed-yet).
