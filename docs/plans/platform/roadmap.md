# Roadmap

This page orders the work. It starts from what GitHub does for piquel's
projects today, because the plan is to replace each of those things, and ends
with the milestones.

See [the plan's overview](README.md) for what each status means.

## What gates leaving GitHub

The web UI is not what gates the move. Four things that only speak git do:

| What GitHub or git provides today | What replaces it | Milestone |
| --- | --- | --- |
| A remote to push to | A hosted Origin node behind Origin Auth | 1 |
| Pull requests and review | Changes and `review` statements, from the CLI first, then the web UI | 1, then 3 |
| The merge queue | Origin's landing queue | 2 |
| GitHub Actions | `origin-ci` running on piquel's machine | 2 |
| Deploys: piqueld builds from a git URL on a webhook | piqueld builds from an Origin acceptance | 2 |
| Cargo git dependencies and Nix flakes | The one-way git mirror | 1 |
| Agent tooling: worktrees, pull request skills, T3 Code | Agent skills for Origin, colocated mode, then a T3 Code provider | 1, then 4 |
| Notifications | The platform's notification system | 4 |

## Where things stood on 13 November 2026

### Origin

- The repository is `sourceorigin-dev/origin`, public, under Apache-2.0.
- `main` has the platform crate, records and on-disk storage, pack files, the
  record index, the change workflow, and statements with promotion.
- Everything a host needs is still an open pull request:

  | Pull request | What it adds |
  | --- | --- |
  | #4 | `OriginService`, the HTTP API and the client SDK |
  | #5 | Clone, push, fetch and remote landing |
  | #6 | Capabilities and scoped tokens |
  | #13 | Targets, policy and the landing queue |
  | #14 | Copy-on-write workspaces |
  | #15 | The operation log, undo and watch |
  | #16 | The `origin-ci` plugin |
  | #17 | The swarm scenario skill |
  | #36 | Deleting objects, and remembering when they were stored |
  | #37 | Dropping statement payloads past their retention |

- So Origin cannot be hosted yet. piquel needs time on Origin before the
  platform work can start properly.
- The design document is `docs/design.md` in that repository. Everything this
  plan says about Origin comes from that document. The unmerged code was not
  read.

### SourceOrigin

- This repository holds Origin Auth and a small site. About 128,000 lines of
  Rust: `apps/auth-service` 70,000, `crates/database` 20,000, `crates/ui`
  14,000, `crates/common` 12,000, `crates/auth-sdk` 9,000.
- `apps/web` is 500 lines: the homepage and the policies.
- Milestones: v0.1 has 17 open issues, v0.2 has 10, v0.3 has 9, v1.0 has 72.
- The v0.2 issues the platform needs already exist:

  | Issue | What it adds | Why the platform needs it |
  | --- | --- | --- |
  | #68 | Device authorization grant | The `origin` CLI has no other way to sign in |
  | #69 | Client credentials grant | Workers and services sign in as themselves |
  | #71 | APIs as resources with their own scopes | Origin's API is such a resource |

- Later issues that touch the plan: #76 personal access tokens, #89 MCP
  clients and #90 scoped grants for agents, all in v1.0. #90 overlaps with
  Origin's own scoped tokens (`origin token issue --scope ... --ttl ...`).

### piqueld

- piqueld builds services from a git URL and syncs its manifest on a GitHub
  webhook. It is piquel's own project, and it will learn to build from Origin.
- The backup features milestone 1 needs are in piqueld's v0.2: #127
  control-plane backups, #332 scheduled environment backups with their
  volumes, #335 volumes as daemon objects, #336 backup repositories, #337
  restoring volumes and environments, #341 volumes, backups and daemon
  settings.
- Restore drills (#340) and btrfs storage pools (#339) are in piqueld's v1.0.

## Milestones

**Decided**, milestone by milestone. piquel agreed to each row.

| Milestone | What ships | Done when |
| --- | --- | --- |
| 0. Groundwork | Repository reorganization, CI by area, device sign-in in Origin Auth, the frontend experiment, the Origin format decisions | The milestones below are unblocked |
| 1. Hosted remote | One stock Origin node behind Origin Auth, backups with a restore drill, the git mirror, agent skills for the Origin workflow | The Origin repository's source of truth is Origin, and GitHub is a read-only mirror |
| 2. Native CI and deploys | `origin-ci` on piquel's machine, piqueld building from an Origin acceptance, the landing queue replacing the merge queue | sourceorigin and piqueld have moved |
| 3. Web UI | Browsing, history, change and stack views, diffs, review | piquel reviews agent changes in the UI |
| 4. Notifications and integrations | Rules over events, Discord, Linear, the T3 Code provider | piquel has stopped checking GitHub notifications |
| 5. Open to others | Projects and organizations, GitHub import, quotas, moderation, billing | The first outside user |

**Proposed:** v0.2 is milestones 0 and 1. This was suggested and not answered.

### Milestone 0: groundwork

Nothing here depends on Origin being ready.

- Reorganize the repository. See [the repository](repository.md).
- Restructure CI into one job per area. See
  [CI by area](repository.md#ci-by-area).
- Add device sign-in to Origin Auth (#68), with #69 and #71.
- Run the frontend experiment. See [the frontend](frontend.md#the-experiment).
- Settle the Origin decisions that are expensive to change later: principals,
  the storage boundary and sign-in. See [origin](origin.md).

### Milestone 1: hosted remote

- **Depends on:** Origin's server, sync and permissions pull requests, and
  piqueld's v0.2 backup features.
- Move the Origin repository first. It is the smallest, and it makes Origin
  host itself.
- Agent tooling belongs here, not later. piquel's development runs through
  agents that assume git worktrees and pull requests. See
  [colocated mode](origin.md#colocated-mode).
- The mirror keeps Nix and Cargo working and is the backup while Origin's
  format is unstable. See [the git mirror](origin.md#the-git-mirror).

### Milestone 2: native CI and deploys

- **Depends on:** Origin's landing, events and `origin-ci` pull requests.
- There is no CI engine with runners. `origin-ci` runs on piquel's machine "as
  if it were in the cloud". That is enough to start.
- piqueld learns to build from Origin directly. It does not go through the
  mirror.
- Then sourceorigin and piqueld move.

### Milestone 3: web UI

- Review is the first screen that matters: piquel reviews agent changes there.
- The framework comes from the experiment. See [the frontend](frontend.md).

### Milestone 4: notifications and integrations

- See [notifications](platform.md#notifications) and
  [integrations](platform.md#integrations).
- The T3 Code provider goes here. See [T3 Code](platform.md#t3-code).

### Milestone 5: open to others

- Projects and organizations, importing from GitHub, quotas, content
  moderation and billing.
- None of this was discussed in depth. See
  [not discussed yet](platform.md#not-discussed-yet).
