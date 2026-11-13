# Roadmap

This page orders the work. It starts from what GitHub does for piquel's
projects today, because the plan is to replace each of those things, and ends
with the milestones.

See [the plan's overview](README.md) for what each status means.

## What gates leaving GitHub

The web UI is not what gates the move. Things that only speak git do:

| What GitHub or git provides today | What replaces it | Milestone |
| --- | --- | --- |
| A remote to push to | A hosted Origin node behind Origin Auth | 1 |
| Pull requests and review | Changes and `review` statements, from the CLI first, then the web UI | 1, then 3 |
| The merge queue | Origin's landing queue | 2 |
| GitHub Actions | Checks run by hand after review, then an `origin-ci` worker in a sandbox | 2, then later |
| Deploys: piqueld builds from a git URL on a webhook | piqueld builds from an Origin acceptance, told by a webhook | 2 |
| Cargo git dependencies and Nix flakes | The one-way git mirror | 1 |
| Agent tooling: worktrees, pull request skills, T3 Code | Agent skills for Origin, colocated mode, then a T3 Code provider | 1, then 4 |
| Notifications | The platform's notification system | 4 |
| Issues | Linear, which piquel is moving all development to. A Linear integration is planned | Not this plan's |

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
  | 1 | origin#13 | Targets, policy and the landing queue |
  | 2 | origin#36 | Deleting objects, and remembering when they were stored |
  | 3 | origin#37 | Dropping statement payloads past their retention |
  | 4 | origin#14 | Copy-on-write workspaces |
  | 5 | origin#15 | The operation log, undo and watch |
  | 6 | origin#4 | `OriginService`, the HTTP API and the client SDK |
  | 7 | origin#5 | Clone, push, fetch and remote landing |
  | 8 | origin#6 | Capabilities and scoped tokens |
  | 9 | origin#16 | The `origin-ci` plugin |
  | 10 | origin#17 | The swarm scenario skill |

- CI is green on all of them except origin#17, whose macOS job fails while origin#16 below
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
  origin#19, where a CI result can stand for a `checks.toml` other than the
  target's, and origin#39, where superseding a statement isn't serialized.

### SourceOrigin

- This repository holds Origin Auth and a small site. About 128,000 lines of
  Rust: `apps/auth-service` 70,000, `crates/database` 20,000, `crates/ui`
  14,000, `crates/common` 12,000, `crates/auth-sdk` 9,000.
- `apps/web` is 500 lines: the homepage and the policies.
- Milestones: v0.1 has 17 open issues, v0.2 has 10, v0.3 has 9, v1.0 has 72.
- The v0.2 issues the platform needs already exist:

  | Issue | What it adds | Why the platform needs it |
  | --- | --- | --- |
  | sourceorigin#68 | Device authorization grant | The `origin` CLI has no other way to sign in |
  | sourceorigin#69 | Client credentials grant | Workers and services sign in as themselves |
  | sourceorigin#71 | APIs as resources with their own scopes | Origin's API is such a resource |

- Later issues that touch the plan: sourceorigin#76 personal access tokens, sourceorigin#89 MCP
  clients and sourceorigin#90 scoped grants for agents, all in v1.0. sourceorigin#90 overlaps with
  Origin's own scoped tokens (`origin token issue --scope ... --ttl ...`).

### piqueld

- piqueld builds services from a git URL and syncs its manifest on a GitHub
  webhook. It is piquel's own project, and it will learn to build from Origin.
- SourceOrigin is the priority. Features of piqueld and of Origin Auth are
  placed where SourceOrigin needs them, whatever milestone they were in.
- The backup features milestone 1 needs are in piqueld's v0.2: piqueld#127
  control-plane backups, piqueld#332 scheduled environment backups with their
  volumes, piqueld#335 volumes as daemon objects, piqueld#336 backup
  repositories, piqueld#337 restoring volumes and environments, piqueld#341
  volumes, backups and daemon settings.
- Restore drills, piqueld#340, were moved from piqueld's v1.0 to its v0.2,
  because milestone 1 ships one.
- btrfs storage pools, piqueld#339, stay in piqueld's v1.0.

## Origin's milestones

**Decided.** Origin's work is tracked in `sourceorigin-dev/origin` as four
milestones. Each epic is a parent issue, and its issues are sub-issues.

| Milestone | Epic | Issues |
| --- | --- | --- |
| **v0.1**, the prototype, merged | origin#42 the prototype, merged | The ten pull requests above; origin#19 and origin#39, the known defects; origin#76 ignore files; origin#77 times on records |
| **v0.2**, hostable | origin#43 identity | origin#44 principals are stable IDs; origin#45 OpenID Connect; origin#46 `origin login`; origin#47 display name lookup; origin#48 readable `policy.toml` |
| | origin#49 authorization | origin#50 the authorization design; origin#51 repositories start closed; origin#34 revocable and per-repository tokens |
| | origin#52 operating a server | origin#33 TLS for remotes; origin#53 the repository registry; origin#54 health endpoints; origin#55 telemetry; origin#56 a repository format version; origin#20 pack format errors; origin#57 `origin verify`; origin#78 a repository's identity in its genesis; origin#79 rotating and recovering authority keys; origin#80 redacting a record's content; origin#84 creating a repository over a private admin API; origin#85 a restored node takes back what it signed |
| | origin#60 agents | origin#61 agent skills for the Origin workflow. origin#21, a typed library API, is its other sub-issue and stays in v0.3 |
| | No epic | origin#58 the one-way mirror to git; origin#59 colocated mode |
| **v0.3**, daily use | origin#62 deploys | origin#63 a convention for deploy statements; origin#64 exporting an acceptance's snapshot for a build; origin#24 webhooks |
| | No epic | origin#81 the diff between two records |
| **v1.0**, the rest | origin#65 more than one server | origin#66 the storage boundary; origin#67 coordination without `flock`; origin#68 events that survive a change of server; origin#28 remotes on plain storage |
| | origin#69 policy and paths | origin#71 hidden paths; origin#72 an authority key per repository; origin#87 private changes |
| | No epic | origin#82 importing a git repository; origin#83 storage and request budgets; origin#86 a consistent copy of a live repository; everything else that was open: origin#22, origin#23, origin#25, origin#26, origin#27, origin#29, origin#30, origin#31, origin#32 and origin#35 |

Origin's v0.1 and v0.2 are what milestone 1 below needs, and its v0.3 is what
milestones 2 and 3 need. Agent skills and colocated mode moved from v0.3 to
v0.2 after the council's review, because milestone 1 ships them. origin#70, a
target that accepts landings only from another target, is closed: see
[deploys](origin.md#deploys).

## Milestones

**Decided**, milestone by milestone. piquel agreed to each row.

| Milestone | What ships | Done when |
| --- | --- | --- |
| 0. Groundwork | Repository reorganization, CI by area, device sign-in in Origin Auth, the frontend experiment, the Origin format decisions | The milestones below are unblocked |
| 1. Hosted remote | One stock Origin node behind Origin Auth, backups with a restore drill, the git mirror, colocated mode, agent skills for the Origin workflow | The Origin repository's source of truth is Origin, and GitHub is a read-only mirror |
| 2. Landing and deploys | The landing queue replacing the merge queue, checks run by hand after review, piqueld building from an Origin acceptance | sourceorigin and piqueld have moved |
| 3. Web UI | Browsing, history, change and stack views, diffs, review | piquel reviews agent changes in the UI |
| 4. Notifications and integrations | Rules over events, Discord, Linear, the T3 Code provider | piquel has stopped checking GitHub notifications |
| 5. Open to others | Projects and organizations, GitHub import, quotas, moderation, billing | The first outside user |

**Proposed:** v0.2 is milestones 0 and 1. This was suggested and not answered.

**Decided:** milestone 1 is not split. The council suggested a private node
with static tokens first, and sign-in second. piquel works on Origin and
SourceOrigin at the same time, and does device sign-in before that part of
the platform, so one milestone is enough.

### Milestone 0: groundwork

Nothing here depends on Origin being ready.

- Reorganize the repository. See [the repository](repository.md).
- Restructure CI into one job per area. See
  [CI by area](repository.md#ci-by-area).
- Add device sign-in to Origin Auth (sourceorigin#68), with sourceorigin#69
  and sourceorigin#71.
- Run the frontend experiment. See [the frontend](frontend.md#the-experiment).
- Settle the Origin decisions that are expensive to change later, because
  they are written into records: principals, times on records, a repository's
  identity and key rotation. See [origin](origin.md).

### Milestone 1: hosted remote

- **Depends on:** Origin's v0.1 and v0.2, and piqueld's v0.2 backup features.
- Move the Origin repository first. It is the smallest, and it makes Origin
  host itself.
- A repository moves by starting from a snapshot of its git tip. Its earlier
  history stays in git, and the mirror continues it. See
  [the git mirror](origin.md#the-git-mirror).
- Agent tooling belongs here, not later. piquel's development runs through
  agents that assume git worktrees and pull requests. See
  [colocated mode](origin.md#colocated-mode).
- The mirror keeps Nix and Cargo working, and is where a fix goes when the
  node or Origin Auth is broken.
- Until milestone 2, a repository's policy requires no checks, or piquel
  issues them by hand with `origin ci run`.

### Milestone 2: landing and deploys

- **Depends on:** Origin's v0.3.
- CI does not run by itself. piquel runs checks by hand after reviewing a
  change. An automatic worker is deferred. See [CI](origin.md#ci).
- piqueld learns to build from Origin directly, told of a landing by a
  webhook. It does not go through the mirror.
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
