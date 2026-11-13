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
- Everything a host needs is still an open pull request. They form one linear
  stack, each based on the one before it, all rebased on `main` on 10 November
  and all mergeable. This is the order they merge in:

  | Order | Pull request | What it adds |
  | --- | --- | --- |
  | 1 | #13 | Targets, policy and the landing queue |
  | 2 | #36 | Deleting objects, and remembering when they were stored |
  | 3 | #37 | Dropping statement payloads past their retention |
  | 4 | #14 | Copy-on-write workspaces |
  | 5 | #15 | The operation log, undo and watch |
  | 6 | #4 | `OriginService`, the HTTP API and the client SDK |
  | 7 | #5 | Clone, push, fetch and remote landing |
  | 8 | #6 | Capabilities and scoped tokens |
  | 9 | #16 | The `origin-ci` plugin |
  | 10 | #17 | The swarm scenario skill |

- CI is green on all of them except #17, whose macOS job fails while #16 below
  it passes. Nobody has looked into why.
- So Origin cannot be hosted yet. piquel needs time on Origin before the
  platform work can start properly.
- **Decided:** nothing in the stack has to change for hosting. Everything a
  hosted node needs is additive, so piquel reviews and merges the stack from
  the bottom. See [what was found in the stack](origin.md#what-the-stack-already-has).
- The stack was read for the places this plan depends on, about 30,000 lines
  in all. It was not reviewed for correctness.
- The design document is `docs/design.md` in that repository.
- The thread that owns the stack was asked to fix its two known defects:
  origin #19, where a CI result can stand for a `checks.toml` other than the
  target's, and origin #39, where superseding a statement isn't serialized.

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

## Origin's milestones

**Decided.** Origin's work is tracked in `sourceorigin-dev/origin` as four
milestones. Each epic is a parent issue, and its issues are sub-issues. The
numbers below are issues in that repository.

| Milestone | Epic | Issues |
| --- | --- | --- |
| **v0.1**, the prototype, merged | #42 the prototype, merged | The ten pull requests above; #19 and #39, the known defects |
| **v0.2**, hostable | #43 identity | #44 principals are stable IDs; #45 OpenID Connect; #46 `origin login`; #47 display name lookup; #48 readable `policy.toml` |
| | #49 authorization | #50 the authorization design; #51 repositories start closed; #34 revocable and per-repository tokens |
| | #52 operating a server | #33 TLS for remotes; #53 the repository registry; #54 health endpoints; #55 telemetry; #56 a repository format version; #20 pack format errors; #57 `origin verify` |
| | No epic | #58 the one-way mirror to git |
| **v0.3**, daily use | No epic | #59 a working copy that git tools can read, which is colocated mode |
| | #60 agents | #61 agent skills for the Origin workflow; #21 a typed library API |
| | #62 deploys | #63 a convention for deploy statements; #64 exporting an acceptance's snapshot for a build |
| **v1.0**, the rest | #65 more than one server | #66 the storage boundary; #67 coordination without `flock`; #68 events that survive a change of server; #28 remotes on plain storage |
| | #69 policy and paths | #70 a target that accepts landings only from another target; #71 hidden paths; #72 an authority key per repository |
| | No epic | Everything else that was open: #22 to #27, #29 to #32 and #35 |

Origin's v0.2 lines up with milestone 1 below, and its v0.3 with milestone 2.

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
