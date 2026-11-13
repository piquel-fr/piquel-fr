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
- Someone hosting Origin themselves can use any identity provider that issues
  access tokens Origin can check by itself.
- On SourceOrigin, every caller signs in through Origin Auth. Origin's own
  signed tokens, which its design gives to agents and CI runners, are not used
  there. Until Origin Auth can issue narrower grants (sourceorigin#90), an
  agent works with the sign-in of the person it works for.

The `origin` CLI signs in with the device authorization grant, which is
sourceorigin#68 in v0.2. Workers need the client credentials grant
(sourceorigin#69), and Origin's API is a resource with its own scopes
(sourceorigin#71).

The council found the seam in `auth.rs` narrower than this plan claimed: the
`Authenticator` trait returns only a principal, so a token would act with all
of its owner's rights and never expire. **Decided:**

- It returns the principal, the capabilities the token's scopes allow, and the
  expiry.
- A waiting landing records who submitted it, and the queue checks that
  principal's rights again when it lands. It can't depend on the token still
  being alive: Origin Auth's access tokens last five minutes, and a check can
  take longer.
- `origin login` keeps a refresh token and renews the access token as it goes.

`crates/auth-sdk` is under Apache-2.0, like Origin, so Origin could use it to
validate tokens.

Tracked in origin#45 (the authenticator) and origin#46 (`origin login`).

## Principals

**Decided.** A principal in a record is an opaque, stable ID, never a name.

The problem: Origin's principals are names today (`user:<name>`), and they are
written into immutable records. Origin Auth handles can change. Once real
history exists this can't be fixed, so it is settled before then.

- For OpenID Connect, the ID is the token's `sub` claim.
- **One issuer per repository.** `policy.toml` names the identity provider its
  principals come from. The issuer stays out of records, and travels with them
  because the policy does.
- **A total encoding of the subject.** Other providers' subjects contain `|`,
  `:` or `/`, which a principal name rejects. An encoding maps any subject to
  a valid name, one to one, with a length cap. A UUID, which is what Origin
  Auth issues, already fits, so the record format doesn't change for it.
- **Workers.** A client that signs in as itself becomes `node:<id>`, where a
  person is `user:<id>`.
- For solo local use, the ID is random, generated beside the node key. It is
  not `$USER`.
- **Signing in sets the identity.** `origin login` sets who authors revisions
  for that remote. A public repository can be cloned without an account, so
  work may start before anyone signs in.
- **History made before signing in** is authored by the local ID, and a
  revision's author must be the caller, so it can't be pushed as it is. It is
  re-authored once, before the first push, which is only allowed while nothing
  has been shared.
- Deleting an account becomes possible. Purging an Origin Account cuts the
  link between history and the person. A name written into immutable records
  could never be removed, since Origin has no way to erase history.
- Origin Auth must keep giving every app the same subject for an account. It
  does today, and a change would split one person into several principals.
- An Origin Account's ID is a UUID of version 7, whose first bits are the time
  it was made. Every record a person writes therefore shows when their account
  was created. That is accepted.

Tracked in origin#44.

### Display names

**Decided.** The identity provider is the only source of names, and Origin
asks it.

- The Origin server exposes a principal lookup. The CLI asks its remote, and
  the remote asks the issuer's directory.
- Origin Auth provides that directory.
- Someone hosting Origin themselves points it at their own directory, or lists
  names in the server's configuration. No standard identity provider offers
  such a lookup, so this is a contract Origin defines.
- A deleted account stops resolving.
- Offline, the CLI shows the ID, or a name it last displayed. That cache is
  only cosmetic.

**Decided:** the lookup returns what a person's public profile shows, so it
can be public. Profiles will be public pages, sourceorigin#101. An account
with no public profile doesn't resolve, and its ID is shown. The deletion
promise is narrower than first written: the provider stops resolving the
account, and anyone who looked it up before may have kept the answer.

An earlier idea was **dropped**: the server keeping its own table of ID to
last-seen name, refreshed from token claims. piquel wanted something better
than a cache, with the conversion owned by the identity side.

Tracked in origin#47.

### Readable policy files

**Open.** With IDs as principals, `policy.toml` becomes unreadable:

```toml
[groups]
maintainers = ["user:0193a5c2-..."]
```

The starting idea is that the CLI and the web editor accept handles and write
IDs, and show names when they print the file. piquel wants this thought
through more before deciding.

Tracked in origin#48.

## Authorization

**Open.** Origin's defaults are too open for a public host:

- Paths no rule mentions are writable by any signed-in caller.
- Without `[grants]`, everyone may land on every target except `policy`.
- With open registration, "everyone" is every Origin Account.

piquel agrees and was already thinking about a proper authorization system
inside Origin. Its design is not part of this plan yet.

Tracked in origin#50 (the design), origin#51 (repositories start closed) and origin#34
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
- Every environment has its own node and its own key: production, staging and
  each preview start from scratch.
- **Deferred:** a key per repository, which would shrink what one leaked key
  can do. Tracked in origin#72.

**Open:** rotating and recovering a key. A lost key freezes every repository
it orders for good, and a leaked one can land a policy that names an
attacker's key. piquel wants a rotation system, cheap enough to rotate
regularly once each repository has its own key. It needs more thought, and it
likely adds to `policy.toml`, so it is designed before real history exists.
piqueld's backups include secrets, so the backup repository holds this key.
Tracked in origin#79.

## Finding repositories

Repositories are created with `origin repo create` on the server's own
machine. The HTTP API has no way to create one, and the platform needs to.

**Decided.** piquel designed the registry:

- The server's configuration names a registry: where the list of repositories
  is. The value is a URL whose scheme says how to read it, such as
  `https://sourceorigin.dev/repositories` or
  `file:///var/origin/repositories.json`.
- The registry says which repositories exist, and what the server needs to
  know about each.

This settles how SourceOrigin manages repositories. The platform's own API
creates a repository: it adds it to its database, serves the registry from
there, and tells the node to create it. What exists is recorded in one place.

1. **The server asks about one repository and caches the answer** for about
   30 seconds. Asking on every request would add a network call to each one.
2. **Two limits on staleness.** The cache's lifetime decides how fast a
   suspension applies. A second, longer limit decides how long the server
   keeps serving a repository when the registry can't be reached. After it,
   the server stops taking writes. Without it, a suspended repository would
   stay writable for as long as the registry is down.
3. **It looks up by the name in the URL and stores by a stable ID.** The entry
   returns the repository's ID, which names it on disk. Renaming a repository
   then changes the registry only.
4. **A name is one or more segments separated by `/`,** each of letters,
   digits, `.`, `_` and `-`, so SourceOrigin can use `<owner>/<repository>`.
   Arbitrary text was considered and dropped: it brings look-alike characters,
   case folding and URL encoding, which Origin Auth's handles already had to
   solve.
5. **No secret keys in the registry.** See [authority keys](#authority-keys).
6. **No path for now.** The server derives where a repository is from its ID,
   so a registry can't point a name at an arbitrary directory. When other
   kinds of storage arrive, an entry gains a storage location in its place.
7. **An entry carries a state.** A state such as read-only lets the platform
   suspend a repository without touching the node.
8. **`file://` first.** Milestone 1 has no platform service to answer over
   HTTP, and reading a file is the same code as reading a static list. The
   HTTP registry arrives with the platform's API.
9. **No Valkey.** piquel suggested keeping the registry in Valkey so changes
   apply at once. A 30-second cache is nearly that, and Valkey would be a new
   service that stock Origin has to speak to.

Tracked in origin#53.

### Creating a repository

**Decided.** Nothing is created implicitly. Someone calls SourceOrigin's
"create" endpoint, and the platform then calls an explicit create on the
node, with the repository's ID and its first admin. A request that names a
repository the node hasn't created is refused, even if the registry lists it.

An earlier proposal was **dropped**: the node creating a listed repository the
first time a request names it.

The create call is on a private listener of the node. See
[between services](#between-services). Tracked in origin#84.

### Between services

**Decided.** Not everything goes over the public internet. Calls between the
node and SourceOrigin's own services use private listeners, linked through
piqueld, as the telemetry collector is linked today. That covers the
registry, creating a repository, the display-name directory and the webhooks
Origin sends.

## The git mirror

**Decided.** A one-way mirror from Origin to git is built first, ahead of the
web UI.

- It is a small worker. For every acceptance on a target it mirrors, it writes
  a git commit and pushes it.
- Its purposes are Nix flakes, Cargo git dependencies and a copy of what
  landed. It is the way out while Origin's on-disk format is unstable.
- It is not there to keep GitHub Actions. piquel wants off GitHub Actions as
  fast as possible.
- It is not how piqueld deploys. piqueld will read Origin directly.
- It is the fallback when the node or Origin Auth is broken: the fix is pushed
  to the mirror with git, and piqueld builds from there.
- A full two-way bridge can wait.
- By [the integrations rule](platform.md#integrations) it is an Origin plugin.

**Decided** after the council's review:

- **Only chosen targets.** It mirrors the targets it is told to, and never
  `policy`.
- **It continues the git history that exists.** A repository that moves to
  Origin starts from a snapshot of its git tip. If the mirror then pushed its
  own commits to the same branch, they would share nothing with the old ones:
  the push would have to be forced, and every commit pinned in a `Cargo.lock`
  or a `flake.lock` would fall off the branch. So the mirror's first commit
  takes the branch's current head as its parent, and the branch only moves
  forward.
- **The same acceptance always gives the same commit.** The commit is a pure
  function of the acceptance: its tree, its [time](#times-on-records) and
  fixed formatting. A mirror can then be rebuilt, and colocated mode can
  compute the same commit locally.
- **Authors are IDs.** A commit's author is derived from the principal's ID,
  never from a display name, so deleting an account still unlinks the person.
- **It reconciles.** On start, and when its cursor has expired, it compares
  each target's chain with the branch. Events only wake it.
- **It is not a backup of the repository.** It holds no changes in progress,
  reviews, check results or signatures.
- **Hidden paths come later.** Git can't hold an entry whose content is
  withheld, so [hidden paths](#hidden-paths) are built once a project no
  longer needs its mirror.

Tracked in origin#58. The two-way bridge stays origin#32, and bringing a git
repository's history into Origin is origin#82.

## Colocated mode

**Decided.** A working copy that is both an Origin workspace and a git
worktree, so tools that expect git keep working during the move. piquel first
answered "we'll see", then decided for it once it was clear how it works.

The design already reserves both `.origin` and `.git` as names that are never
stored.

How it works:

1. The folder holds both `.git/` and `.origin/`. Each tool ignores the other's
   directory.
2. Origin is the source of truth. Nobody commits with git.
3. The [git mirror](#the-git-mirror) gives each acceptance a git commit.
4. Whenever Origin moves the working copy, it points git's `HEAD` at the
   mirrored commit of what the change is based on. It doesn't touch files.
5. It also rewrites git's index to match. Git compares files with its index,
   its own list of what the last commit holds, so moving `HEAD` alone would
   make `git status` report changes that aren't there.
6. `git status` and `git diff` then show exactly the current change's edits.
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
- Origin keeps two stores and converts on every move. An earlier comparison
  with jj was dropped: jj colocates cheaply because its store is git.

Recent T3 Code changes seem to reduce its dependence on git, and some
adapting may still be needed. How deeply T3 Code depends on git was not
measured.

Tracked in origin#59, in Origin's v0.2 because milestone 1 needs it.

## CI

**Decided.**

- CI does not run by itself at first. An automatic worker is out of scope for
  the beginning, and there is no CI engine with runners.
- Checks are run by hand, with `origin ci run`, and only after a change has
  been reviewed. Nothing then runs code nobody has read.
- A repository on SourceOrigin starts with a policy that lets only its owner
  in, so nobody else can land or ask for a check.
- The macOS run of `origin-platform`'s conformance tests is by hand on a Mac.
  `origin ci run` still issues a statement, so a manual run leaves evidence.
- **Deferred:** `origin ci worker`. When it comes, it runs in a sandbox with
  no access to a person's files or credentials. A check runs the candidate's
  build scripts, so a worker on someone's own machine would hand that machine
  to whoever may land.
- **Deferred:** another CI system as a statement issuer through the mirror. It
  runs on the mirrored commit and posts its result back with
  `origin annotate`. That is how Buildkite or Depot would be integrated.

How this repository's CI maps onto `checks.toml` is in
[CI by area](repository.md#ci-by-area).

## Deploys

**Decided.**

- piqueld builds from an Origin acceptance. Tracked in origin#64.
- piqueld learns of a landing through a webhook. Webhooks are an Origin
  plugin, origin#24, moved to Origin's v0.3 for this.
- A deploy is recorded as a statement on the acceptance of `main` that was
  deployed. That needs no new Origin feature, only a convention, tracked in
  origin#63.
- Environments stay in piqueld, as with git today: `main` builds staging, and
  production is promoted from staging. `infra/piqueld.toml` already says
  `promote_from = "staging"`.

**Dropped:** making `production` a target, so that promoting would be
`origin land --from main --onto production`. It would duplicate what piqueld
does, and people could land on production by accident. The policy rule it
needed, a target that accepts landings only from another target, was
origin#70 and is closed.

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
repository. Access control stays inside a repository: piquel has no intention
of building something like submodules, so the public part is not a separate
repository.

**Decided:**

- **Only folders can be hidden.** A reader gets a hidden folder's name and its
  hash and nothing under it. The children aren't needed to recompute the
  parent's hash, so they are not sent.
- **Every hidden folder holds a random nonce file,** so its hash can't be
  guessed.
- Origin saves the hidden folders with their hashes. It ignores whatever is on
  disk at those paths and uses the saved hash.
- So a project can keep a private folder of env files. An outside contributor
  creates their own there, and it never shows up in diffs.
- This matches the rule Origin already has: a revision can have no effect on a
  path its writer can't write.
- **Built after the mirror.** Git can't hold a withheld entry, so this waits
  until a project no longer needs its [git mirror](#the-git-mirror).

Why not single files: BLAKE3 is secure, and nobody can turn a hash back into
content. But anyone can hash a guess and compare. That confirms content with
few possibilities, such as `DEBUG=1`, a short token or a file copied from an
open project. A reader can also see when a hidden file changes, and whether
two are equal. A nonce in a folder defeats all three.

The descriptions, reviews and check output of hidden code stay readable to
everyone who can see a change. Hiding them is a choice made for each change:
see [private changes](#private-changes).

**Proposed,** not answered yet:

- Gaining read access later is a sharp edge. A local folder then sits where
  the real one wants to go. Origin must refuse and ask. It must not overwrite
  the local files, and it must not record them as edits.

Tracked in origin#71.

## Private changes

**Decided.** A change can be made private, by choice. Its revisions,
description and statements are then visible only to the people it names, such
as its author and a group of maintainers. piquel wanted this already: it lets
a sensitive fix be written, reviewed and checked before the problem is public.

It is never automatic. A rule that hid every revision touching a hidden path
was proposed and **dropped**: a change in which someone touched a hidden file
by accident would vanish for everyone else.

To design: where the choice is recorded, who may be named, and what becomes
visible when the change lands. Tracked in origin#87.

## Ignore files

**Decided.** Origin snapshots every file except `.origin` and `.git`. The
first command in a real project would record `target/`, `node_modules/` and
local env files, permanently. Origin gains ignore files and reads `.gitignore`
too. This was always a priority of piquel's and had slipped; it blocks moving
any real repository. Tracked in origin#76, in Origin's v0.1.

## Times on records

**Decided.** No record says when it was made. Every revision, statement and
acceptance gets a time. An acceptance's time is the authority's and is covered
by its signature. A revision's or statement's time is what its author claims.
This changes the record encoding, so it goes in before real history exists.
Tracked in origin#77, in Origin's v0.1.

## A repository's identity

**Decided.** An acceptance names no repository, and a target's ID is the hash
of its name. Two repositories created for the same admin on one node start
with identical genesis acceptances, so a wrong mapping in the registry, or a
restore into the wrong place, serves another repository's valid chain. A
unique identity is bound into genesis, and a clone pins it. Tracked in
origin#78.

## Erasing content

**Decided.** A host must be able to remove a leaked secret, abusive content
and personal data. An admin redacts a record: its content is dropped and its
ID is kept, so everything that refers to it still verifies. Tracked in
origin#80.

piquel also asked for a policy setting that stops some users from issuing
some statements, such as check results from someone who is neither an admin
nor a CI worker. Origin has it: the `annotate` capability is granted by kind.
What is wrong is the default, which grants `annotate *` to everyone. Closing
the default is origin#51.

## Diffs

**Decided.** A review UI needs the diff of a change. The API serves trees and
files, not diffs, so Origin gains an endpoint that returns the diff between
two records, streamed file by file. Tracked in origin#81.

## Operations

**Decided.** Mostly for the server:

- **TLS for remotes.** The client is built without TLS, so the CLI can't reach
  a hosted node over HTTPS. This blocks hosting. The server can leave TLS to
  the proxy in front of it. Tracked in origin#33.
- A format version with migrations. This also applies to local repositories.
  Packs, operation log segments and the index each have a version already; the
  repository as a whole has none. Tracked in origin#56.
- A command that verifies a repository. This also applies to local
  repositories. Tracked in origin#57.
- Health endpoints and telemetry. Tracked in origin#54 and origin#55.

## More than one server

**Deferred.** None of this blocks milestone 1. It is kept because the list was
worked out and agreed. Tracked in origin#65, with origin#66, origin#67, origin#68 and origin#28.

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

**Open.** A design was agreed for when replicas come: each replica writes the
event into the shared store under a time-ordered key, the cursor is the last
key seen, and readers read a few seconds of overlap again. The council showed
it can lose events. A process that pauses longer than the overlap publishes
behind subscribers that have already passed. Deduplicating by record ID is
also wrong, since several check requests can concern one record. Whatever
replaces it needs publication that is atomic with the record, a mark of how
far it is safe to read, and consumers that reconcile. Replicas are deferred,
so nothing has to be chosen now.

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
