# What the platform needs from Origin

SourceOrigin hosts stock Origin. This page lists what Origin must gain or
change for that to work, and the reasoning behind each item.

What this page says about Origin comes from `docs/design.md` in
`sourceorigin-dev/origin`, and from reading the open stack of pull requests
for the places this plan depends on. Each item names the issue that tracks it
in that repository; [Origin's milestones](roadmap.md#origins-milestones) lists
them all.

See [the plan's overview](README.md) for what each status means.

## What the stack already has

Reading the open stack on 13 November 2026 changed three things this plan had
assumed:

- **Principals need no format change.** A principal name already accepts
  letters, digits, `.`, `_` and `-`, so a UUID fits as it is. Only where the
  value comes from changes. Earlier advice to change principals before merging
  the stack was wrong.
- **Sign-in has its seam.** `auth.rs` has an `Authenticator` trait, and its
  comment names identity providers as other implementations.
- **The storage boundary can wait.** The store's API is already close to "put,
  get and list objects". The file system shows through its directory accessors
  and its locks. With replicas dropped, drawing the boundary is a later
  refactor.

It also showed two gaps:

- **The client has no TLS.** See [operations](#operations).
- **Repositories can't be created over the API.** See
  [finding repositories](#finding-repositories).

## One node first

**Decided.** Hosting starts with one Origin node and a local volume. Replicas
are dropped for now.

piquel's notes assumed Origin servers are stateless. They are not today:

- A repository is a local directory.
- Origin refuses network file systems.
- Storage on something like S3 is listed under "Later" in the design.
- Coordination uses `flock`. That is the Unix call that locks a file for one
  process; the kernel releases the lock when the process dies. It only
  coordinates processes on the same machine. Origin uses it for target chains,
  the queue, pushes, the index, the operation log and the compactor. So two
  servers on different machines cannot share a repository.

What running more than one server would need is kept under
[more than one server](#more-than-one-server).

## Sign-in with OpenID Connect

**Decided.** Stock Origin learns generic OpenID Connect:

- Origin validates tokens from a configured issuer and maps the token's stable
  subject to a principal.
- SourceOrigin hosting is then stock Origin pointed at Origin Auth. Nothing in
  Origin knows about SourceOrigin.
- Someone hosting Origin themselves can use any identity provider.

The `origin` CLI signs in with the device authorization grant, which is Origin
Auth issue #68 in v0.2. Workers need the client credentials grant (#69), and
Origin's API is a resource with its own scopes (#71).

`crates/auth-sdk` is under Apache-2.0, like Origin, so Origin could use it to
validate tokens.

Tracked in origin #45 (the authenticator) and #46 (`origin login`).

## Principals

**Decided.** A principal in a record is an opaque, stable ID, never a name.

The problem: Origin's principals are names today (`user:<name>`), and they are
written into immutable records. Origin Auth handles can change. Once real
history exists this can't be fixed, so it is settled before then.

- For OpenID Connect, the ID is the token's `sub` claim.
- **Open:** whether the issuer is part of the ID, so that IDs from two
  identity providers can't collide when records move between nodes.
- The record format doesn't change. See
  [what the stack already has](#what-the-stack-already-has).
- For solo local use, it is a random ID generated beside the node key. It is
  not `$USER`.
- Deleting an account becomes possible. Purging an Origin Account cuts the
  link between history and the person. A name written into immutable records
  could never be removed, since Origin has no way to erase history.

Tracked in origin #44.

### Display names

**Decided.** The identity provider is the only source of names, and Origin
asks it.

- The Origin server exposes a principal lookup. The CLI asks its remote, and
  the remote asks the issuer's directory.
- Origin Auth provides that directory as a public lookup. That fits, because
  handles are already public (see `docs/dev/security/handles.md`).
- Someone hosting Origin themselves points it at their own directory, or lists
  names in the server's configuration.
- A deleted account stops resolving.
- Offline, the CLI shows the ID, or a name it last displayed. That cache is
  only cosmetic.

Tracked in origin #47.

An earlier idea was **dropped**: the server keeping its own table of ID to
last-seen name, refreshed from token claims. piquel wanted something better
than a cache, with the conversion owned by the identity side.

### Readable policy files

**Open.** With IDs as principals, `policy.toml` becomes unreadable:

```toml
[groups]
maintainers = ["user:0193a5c2-..."]
```

The starting idea is that the CLI and the web editor accept handles and write
IDs, and show names when they print the file. piquel wants this thought
through more before deciding.

Tracked in origin #48.

## Authorization

**Open.** Origin's defaults are too open for a public host:

- Paths no rule mentions are writable by any signed-in caller.
- Without `[grants]`, everyone may land on every target except `policy`.
- With open registration, "everyone" is every Origin Account.

piquel agrees and was already thinking about a proper authorization system
inside Origin. Its design is not part of this plan yet.

Tracked in origin #50 (the design), #51 (repositories start closed) and #34
(revocable and per-repository tokens).

What is settled is where it lives. See
[permissions](platform.md#permissions): the platform does not build a second
permission system.

## Authority keys

**Decided.**

- Reading the node key is an Origin feature, and Origin already does it: the
  key is a file.
- piqueld mounts the key as a secret, as it does for Origin Auth's keys.
- The key does not go in a SourceOrigin database. Stock Origin would then
  depend on the platform, and a database leak could forge acceptances.
- One node key covers every hosted repository. That is the trade-off.
- **Deferred:** a key per repository, which would shrink what one leaked key
  can do. Tracked in origin #72.

## Finding repositories

Repositories are created with `origin repo create` on the server's own
machine. The HTTP API has no way to create one, and the platform needs to.

**Decided.** piquel designed the registry, and agreed to the five points
after it:

- The server's configuration names a registry: where the list of repositories
  is. The value is a URL whose scheme says how to read it, such as
  `https://sourceorigin.dev/repositories` or
  `file:///var/origin/repositories.json`.
- The registry is a map of repositories, with what the server needs to know
  about each: where to find it, which is a path on the file system for now.

This settles how SourceOrigin manages repositories. The platform's own API
creates a repository by adding it to its database, and it serves the registry
from there. Origin needs no notion of who may create a repository, and what
exists is recorded in one place.

1. **The server asks about one repository and caches the answer.** Asking on
   every request would add a network call to each one, and make every clone
   fail when the platform is down. The server keeps a short-lived cache and
   goes on serving the repositories it knows when the registry can't be
   reached.
2. **It looks up by the name in the URL and stores by a stable ID.** The entry
   returns the repository's ID, which names it on disk. Renaming a repository
   then changes the registry only.
3. **No secret keys in the registry.** This plan keeps authority keys out of
   SourceOrigin's database. See [authority keys](#authority-keys).
4. **Paths are sanitized and stay under the server's own root** when the
   registry is remote, so a registry can't point a name at an arbitrary
   directory.
5. **An entry carries the first admin and a state.** The server creates a
   listed repository the first time it is used, with that admin. A state such
   as read-only lets the platform suspend a repository without touching the
   node.

Tracked in origin #53.

## The git mirror

**Decided.** A one-way mirror from Origin to git is built first, ahead of the
web UI.

- It is a small worker. On every `target.advanced` event it writes the
  acceptance as a git commit and pushes it.
- Its purposes are Nix flakes, Cargo git dependencies and backup. It is the
  way out while Origin's on-disk format is unstable.
- It is not there to keep GitHub Actions. piquel wants off GitHub Actions as
  fast as possible.
- It is not how piqueld deploys. piqueld will read Origin directly.
- A full two-way bridge can wait.
- By [the integrations rule](platform.md#integrations) it is an Origin plugin.

Tracked in origin #58. The two-way bridge stays origin #32.

## Colocated mode

**Decided.** A working copy that is both an Origin workspace and a git
worktree, so tools that expect git keep working during the move. piquel first
answered "we'll see", then decided for it once it was clear how it works.

- The design already reserves both `.origin` and `.git` as names that are
  never stored.
- This is how jj was adopted.

How it works:

1. The folder holds both `.git/` and `.origin/`. Each tool ignores the other's
   directory.
2. Origin is the source of truth. Nobody commits with git.
3. The [git mirror](#the-git-mirror) gives each acceptance a git commit.
4. Whenever Origin moves the working copy, it points git's `HEAD` at the
   mirrored commit of what the change is based on. It doesn't touch files.
5. `git status` and `git diff` then show exactly the current change's edits.
   Cargo, Nix and a tool's diff view see an ordinary git repository.

Its limits:

- It gives tools read access through git, not write access. A tool that
  commits, pushes a branch or opens a pull request still writes something
  Origin ignores. So T3 Code's diff views would work, and its pull request
  workflow would still need the [provider](platform.md#t3-code).
- A change stacked on another change is based on a revision, not an
  acceptance. The mirror would have to write local commits for revisions too.
- Nix flakes only see files git tracks, so Origin would have to mark new files
  as intended to be added.

Recent T3 Code changes seem to reduce its dependence on git, and some
adapting may still be needed. How deeply T3 Code depends on git was not
measured.

Tracked in origin #59.

## CI

**Decided.**

- There is no CI engine with runners. At first, `origin ci worker` runs on
  piquel's machine.
- The one thing that loses is the macOS run of `origin-platform`'s conformance
  tests. That is run by hand on a Mac at first. `origin ci run` there still
  issues a statement, so a manual run leaves evidence.
- Another CI system can become a statement issuer through the mirror: it runs
  on the mirrored commit and posts its result back with `origin annotate`.
  That is how Buildkite or Depot would be integrated later.

How this repository's CI maps onto `checks.toml` is in
[CI by area](repository.md#ci-by-area).

## Deploys

**Decided.**

- piqueld builds from an Origin acceptance. Tracked in origin #64.
- For now, a deploy is recorded as a statement on the acceptance of `main`
  that was deployed. That needs no new Origin feature, only a convention,
  tracked in origin #63.

**Deferred:** making `production` a target, so that promoting is
`origin land --from main --onto production`.

- piquel's worry was that people could land on production by accident.
- Landing is granted per target, so only piqueld's node would hold
  `land production`.
- What is missing is a policy rule that a target accepts landings only from
  another target. Until Origin has one, deploys stay statements. Tracked in
  origin #70.

## Releases and channels

**Decided** in outline, **deferred** in time. piquel called this very far away
and not a priority.

- A release needs no new model. It is an acceptance on a release target, plus
  statements that link artifact digests from registries.
- piquel wants users to choose between a less stable nightly version and a
  stable release, as T3 Code does.
- For the Origin CLI and the SDKs, channels map to targets: nightly builds
  from `main`, stable builds from a release target, published as pre-release
  versions.
- For the hosted service, per-account feature flags on one version, not
  several versions running at once. That avoids the database migration
  problem.

## Hidden paths

Origin's path rules can make part of a repository unreadable. That covers the
case from piquel's notes of a closed monorepo with public SDKs, in one
repository.

**Decided,** as piquel designed it:

- For a hidden folder, a reader gets its name and its hash and nothing under
  it. The children aren't needed to recompute the parent's hash, so they are
  not sent.
- Origin saves the hidden files and folders with their hashes. It ignores
  whatever is on disk at those paths and uses the saved hash.
- So a project can keep a private env file. An outside contributor creates
  their own at that path, and it never shows up in diffs.
- This matches the rule Origin already has: a revision can have no effect on a
  path its writer can't write.

**Proposed,** not answered yet:

- A hash of small or guessable content can be confirmed by guessing, and a
  reader can see when it changes. A random nonce file inside each hidden
  folder fixes that with no format change.
- Gaining read access later is a sharp edge. A local file then sits where the
  real one wants to go. Origin must refuse and ask. It must not overwrite the
  local file, and it must not record it as an edit.

Tracked in origin #71.

## Operations

**Decided.** Mostly for the server:

- **TLS for remotes.** The client is built without TLS, so the CLI can't reach
  a hosted node over HTTPS. This blocks hosting. The server can leave TLS to
  the proxy in front of it. Tracked in origin #33.
- A format version with migrations. This also applies to local repositories.
  Packs, operation log segments and the index each have a version already; the
  repository as a whole has none. Tracked in origin #56.
- A command that verifies a repository. This also applies to local
  repositories. Tracked in origin #57.
- Health endpoints and telemetry. Tracked in origin #54 and #55.

## More than one server

**Deferred.** None of this blocks milestone 1. It is kept because the list was
worked out and agreed. Tracked in origin #65, with #66, #67, #68 and #28.

1. **A storage boundary.** Today's traits are shaped like a file system
   (`Durability`, `FileLock`, `CloneFile`). Running without local state needs
   a higher one: put and get immutable objects, compare-and-swap a reference,
   append to a log. Local disk and object storage are two implementations.
   It was first thought urgent, to be drawn before the server pull requests
   hardened. Reading the stack showed the store's API is already close to it,
   so it waits with the rest.
2. **Coordination without `flock`.** Target heads, change heads, the queue and
   the compactor become compare-and-swap objects. "One authority node" becomes
   "one authority key, any number of processes".
3. **Events that survive a change of server.** See below.
4. **Authority keys outside the process.** See
   [authority keys](#authority-keys).
5. **A local cache in front of object storage,** for hot reads. This is the
   hot and cold storage from piquel's notes. It only matters once object
   storage exists.
6. **Identity and operations.** See above.

### Events and cursors

Origin's events are pulled, not pushed. A subscriber asks for everything after
a cursor, and the cursor is a position in that node's operation log.

- The cursor is what lets a CI worker that was down for five minutes come back
  and get what it missed.
- piquel's model was simpler: the replica that handles a request fires the
  event, with no syncing. What that loses: if the subscriber is down, or the
  replica crashes between writing and sending, the event is gone. A landing
  then waits for a check nobody heard was requested.
- A cursor into one replica's log means nothing to another replica.

The design agreed for when replicas come needs no syncing between them:

1. Each replica writes the event into the shared store together with the
   record, under a time-ordered key.
2. The cursor is the last key the subscriber has seen.
3. Readers read a few seconds of overlap again, to absorb clock differences.
   Consumers already deduplicate by record ID.

The replica that handled the write can still wake its own waiting subscribers
at once. That is piquel's model, used as a speed-up.

### Object storage

**Proposed,** and unverified:

- Write against the plain S3 API with conditional writes, so the provider
  stays swappable.
- Default to Cloudflare R2. It charges nothing for egress, and a code host's
  traffic is mostly clones and fetches.
- This came from memory. Support for conditional writes across providers was
  not checked, and it must be before choosing.

### Continuous backup

**Decided.** Copying each new object and acceptance to a backup as it is
written works because records are immutable. It is not a piqueld feature.
piqueld's job is volume snapshots for every application. For Origin,
continuous backup falls out of the storage boundary: once Origin can write to
object storage, a second store or bucket versioning is the backup.
