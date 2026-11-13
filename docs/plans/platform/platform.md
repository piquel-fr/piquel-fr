# The platform

This page describes SourceOrigin itself: what it stores, the services it runs,
how it hosts repositories, and the product ideas discussed so far.

See [the plan's overview](README.md) for what each status means.

## What the platform is

From piquel's [notes](notes.md), SourceOrigin has two parts:

- **Hosting.** Stock Origin servers, exposed on an API, that manage nodes and
  above all storage. The only difference from stock Origin is that sign-in
  goes through Origin Auth. People need an Origin Account to contribute. The
  biggest priorities are performance and data safety.
- **Integrations.** The more traditional service: a web UI, a notification
  system, and integrations with outside tools. They listen to Origin's events
  and process them.

## Data lives in Origin

**Decided.** This was the idea behind Origin from the start: all the metadata
development needs is stored beside the code, not in a remote database, so
outside services can query it.

- Reviews, CI results, deploys and releases are statements on Origin records.
- The platform builds no second data model.
- PostgreSQL holds only what can't live in a repository:
  - the registry of projects;
  - credentials for integrations;
  - notification rules;
  - the state of deliveries;
  - caches that can be rebuilt.

## Permissions

**Decided.** The platform builds no second permission system. Its permissions
page is an editor: it changes `policy.toml` and lands the change on the
`policy` target, where it is ordered, reviewed and audited like code.

What Origin's own authorization looks like is still open. See
[authorization](origin.md#authorization).

## Services

**Proposed.**

- One Rust service for the API, on axum, sqlx and utoipa. Origin uses axum and
  utoipa too; it has no database.
- It reads and writes Origin only through Origin's public API. That matches
  Origin's own rule that a plugin can do nothing the API can't.
- Every API is described with OpenAPI. That is from piquel's notes.
- The web UI is a client of that API. See [the frontend](frontend.md).
- **Decided:** the product's pages render on a server, for search engines. So
  a second process serves the frontend beside the Rust API.
- **Decided:** the platform writes to Origin as the user. A review only counts
  if its issuer is the caller, so the platform's own credential can't issue
  one. Origin Auth's token exchange, sourceorigin#70, was moved from its v1.0
  to its v0.3 for this.

## Hosting and backups

**Decided.**

- One Origin node with a local volume. See
  [one node first](origin.md#one-node-first).
- Backups use piqueld's backup features, which are in piqueld's v0.2
  milestone. See [the roadmap](roadmap.md#piqueld).
- A scheduled job restores the latest backup into a scratch node and verifies
  it. A backup that has never been restored is not known to work. piqueld's
  restore drills, piqueld#340, were moved to its v0.2 for this.
- Continuous backup is not piqueld's job. See
  [continuous backup](origin.md#continuous-backup).

The council found the first version of this unsafe. **Proposed,** not
answered yet:

- **Stop the node to copy it.** A copy of a live store can catch a target's
  head before the objects it names, and a restore drill passing once says
  nothing about the next backup. piqueld's `stop` method already avoids this:
  it stops the node, copies the volume and starts it again. A few seconds of
  downtime at night costs one person nothing.
- **Later, a consistent copy without stopping.** Origin gains a command that
  writes one, by reading the heads first and the objects after. Records are
  immutable, so everything those heads name is then in the copy.
- **A restored node takes back what it signed.** A restore puts the node
  behind acceptances that clients and the mirror already hold. If it signed
  new ones at the same positions, every chain would fork. So before it takes
  writes, it accepts back the acceptances that carry its own signature.
- **The drill does more than check chains.** It runs `origin verify`, which
  checks that every record a record names is present, then clones, fetches
  and lands.
- **What may be lost.** With a nightly backup, landed code is safe in clients
  and in the mirror. Up to a day of changes in progress, reviews and check
  results that nobody fetched can be lost.
- **The backup holds the authority key,** because piqueld's backups include
  secrets. The backup repository must be encrypted.

## Notifications

**Proposed,** not answered:

- Origin Auth owns how to reach a person: verified email addresses, linked
  accounts, channel preferences and the notification bell.
- The platform owns what is worth telling them: rules over Origin's events.
- The platform then never stores an email address.

From piquel's notes: the system should let people follow their projects and
broadcast to channels, with powerful settings for which changes to follow. It
is built on Origin's events. Email goes through Resend, probably by relying on
Origin Auth's email and notification system.

## Integrations

**Decided.** One rule says where an integration lives:

- If a worker needs only Origin's API, it is an Origin plugin, in the Origin
  repository. The git mirror, webhooks, Linear and Discord are examples.
- If it needs accounts, tenancy or billing, it lives in this repository.

piquel would rather keep bespoke, less common plugins in repositories of their
own. That works already, since `origin <name>` runs any `origin-<name>` on
`PATH`. The details are for a later discussion.

### Linking accounts

**Decided.** Letting people link a Linear or Discord account is realistic, and
it keeps the rule above.

- The plugin stays generic. It asks a small interface for a token, and for the
  outside identity that matches a principal.
- When someone hosts it themselves, a configuration file answers.
- On SourceOrigin, the platform answers.
- A person's own links live in Origin Auth.
- A project's installs, such as a Linear workspace and its bot token, live in
  the platform's database.

### Other CI systems

**Decided.** Any CI system built on git becomes a statement issuer through the
[git mirror](origin.md#the-git-mirror): it runs on the mirrored commit and
posts the result back. piquel's notes list Depot, Buildkite, Hydra and
Blacksmith as candidates.

### T3 Code

**Deferred** to milestone 4.

- All of piquel's development goes through T3 Code today. Its maintainers are
  not accepting feature requests, so piquel will keep a fork.
- The fork adds Origin only as a pull request provider, beside GitHub and
  Azure DevOps. The point is to keep the pull request linking and overview
  workflows.
- SourceOrigin is not integrated into T3 Code beyond that.
- The platform must therefore expose what any pull request provider exposes: a
  URL for a change, its state, its checks and its reviews.
- T3 Code's stack plays no part in choosing the frontend framework.

## Friendly to agents

**Decided** as a goal. piquel wants the main service to be very friendly to
agents, and getting agent tooling adapted is essential.

Nothing more specific was agreed. The API-first design above is the base for
it.

## Product ideas

### Marking files as reviewed

From piquel's notes, reviewing should be first class for bots and humans:

- Marking a file as reviewed marks it for the head revision.
- After a push, a file that changed since then is shown as changed since the
  last review, with its diff since the reviewed revision and a button to see
  the full diff.
- This makes incremental review far more powerful, above all for the author.

**Decided:** the marks live in the platform's PostgreSQL, as each person's
private state. They record which revision of a file a person saw, and
"changed since my review" is the diff between that revision and the head.

**Dropped:** the marks as `review.seen` statements carried over by promotion.
The council showed it doesn't work: marking a second file supersedes the
first, and a direct statement drops the ones carried over. As statements they
would also be permanent, copied to every clone and readable by everyone, and
anyone could flood a repository with them. A bot doesn't need to know which
files a person looked at.

### Releases

**Decided.** See [releases and channels](origin.md#releases-and-channels).

### A public part of a private repository

**Decided.** Path rules cover the closed monorepo with public SDKs in one
repository. See [hidden paths](origin.md#hidden-paths).

### Projects

From piquel's notes, not discussed in depth:

- A project is the main unit of organization. A user or an organization owns
  it.
- A project holds repositories, permissions and integration settings.

**Decided:**

- A repository is private when it is created: its policy lets only its owner
  in. The owner can make it public.
- An account may create up to three repositories. Administrators can change
  the limit.
- Organizations will sit beside users as owners. They are not needed yet.
  Their members are stored in policy, like everyone else.
- Every environment has its own Origin node and key: production, staging and
  each preview start from scratch.

Projects and organizations are in milestone 5.

### Smaller features from the notes

Not discussed:

- A project's main page renders a file, the first repository's README by
  default, and this can be changed.
- A viewer for the diff between any two records.

## Dropped

- **Issues as changes.** The idea was that an issue is a change with no code
  yet, and starting work adds revisions to it. piquel wants issue objects that
  can be created in advance, grouped into epics, and linked with metadata. The
  idea is dropped.
- **A project management system.** Not for now. Issues live in Linear, which
  piquel is moving all development to, and a Linear integration is planned.
  piquel's notes suggest discussions and bug reports might go through deep
  Discord integrations.
- **Production as a target.** See [deploys](origin.md#deploys).
- **Reviewed marks as statements.** See
  [marking files as reviewed](#marking-files-as-reviewed).

## Not discussed yet

These come from piquel's notes and have no decision:

- Content moderation and scanning of hosted repositories.
- Redundancy of storage, beyond backups.
- Integrations with registries (Docker Hub, npm, crates.io), to link builds to
  revisions.
- Notifications over Discord, Slack, SMS or SentDM, and announcements for a
  whole repository.
- Money. The notes suggest paying per repository, notably for private ones.
- Discussions, bug reports and other community features.
- Rendering Markdown. The notes name Enhanced.
