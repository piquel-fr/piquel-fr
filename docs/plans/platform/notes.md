# The original notes

These are piquel's notes that started the planning discussion, unchanged. They
are kept as the starting point: some of what they say was later changed, and
[the plan's overview](README.md) lists what was decided.

`[[origin]]` and `[[Origin Auth]]` are links in piquel's own notes, not in
this repository.

````markdown
# Source Origin
Source Origin is a platform to manage [[origin]] repositories.
This has essentially two main components.
## Adding SourceOrigin to the repo
- Keep same database crate but have different users depending on the service.
- Have observability be for the entire monorepo.
- Try to split CI per code area not per language.
- `web` service should be renamed to sourceorigin
- split the piqueld applications: `sourceorigin-auth`, `sourceorigin-observability`, `sourceorigin-origin`.
## Open Questions
The stack used for frontend is still under consideration.
- Topcoat is still experimental and lacks features.
- We need `diffs`, `trees`& `highlight`.
- `SvelteKit` is first choice if we move off Rust. Might need to go for more classical (react-based) web framework (also look into Effect?).
- End-to-end typesafety & UI consistency is extremely important.
- Other important stack requirements: performance, ease of development (testing, dev-build speed, ...)

Product Design
- How to handle releases?
- What about other community stuff like discussions, bug reports, ...
  Could be handled through deep discord integrations but TBD
## Hosting Platform
We host [[origin]] repositories. Essentially, we just run stock servers that manage the nodes and most importantly **storage**.

This will be essentially stock origin exposed on an API.
The only difference is that authentication will have to go through the sourceorigin authentication system. Users will need an account to contribute.
### Storage Layer
Since origin servers are stateless, we will be able to optimize on how data is managed with optional cold/hot storage systems.
This would need following systems:
- backups
- redundancy
- content moderation and scanning

**The biggest priority is performance and data safety**
## Integrations
This is the more traditional saas part but the biggest in terms of feature.

The main **design** will be to just have the service (or services) listen for origin webhooks and process data.
Most of the data that these services manage should be in the shape of statements on origin revisions.
**The main idea is that data should stay on the origin instance directly so it can easily be queried by external services**

The two main surface integrations are the **Web UI** and the **Notification System**.
These will be coupled with external integrations.
### Web UI
Simply a web UI to work on your origin repos.
You could see the code, active changes, history, modify settings, ...
### Notification System
A powerful system to get notified about projects. Would allow to follow your projects yourself, broadcast to comms channels.
Should have powerful settings to follow said changes. Should be build on the origin webhook system.
### External Integrations
These will come under different forms.
Most of them will probably be published as standalone workers or tools for origin. These would then be usable by people.
Most will probably go through Origin Auth to manage linking accounts and stuff.
#### Linear
This integration will have two parts:
- **auth**: just managing the Linear auth & tokens and stuff
- **webhooks**: will translate the generic Origin webhooks into Linear API calls. This will be handled through a configuration that users will have created for how to treat stuff and manage their projects.
#### CI
A way to integrate with CI existing CI systems.
This will probably be quite complex as most CI relies on Git.
Could be interesting to leverage the git bridge to do this.
Systems we could integrate with:
- Depot
- BuildKite
- Hydra (for Nix)
- Blacksmith (if they ever do more than runners)
#### Registries
Some way to integrate with registries.
IDK what kind or how but would be useful to link builds and stuff to revisions.
- Docker Hub
- npm
- crates.io
#### Social Media
Would be cool to link to social media accounts and setup integrations based on that.
For example, having notifications be sent to Discord, Slack, SMS, [SentDM](https://soydev.link/sent), …
This could also be used for repo-wide annoucements.
## Monetization?
This might need to be monetized.
For now: pay per repo (notably for private repos).
## Stack
[[origin]] for storage layer.
### Auth
- [[Origin Auth]]
- Authorization will be integrated.
### Backend
- Rust
- Resend for email (probably rely on the [[Origin Auth]] email & notification system)
- All the APIs should be OpenAPI compatible
### Frontend
- [diffs.com](https://diffs.com)
- [trees.software](https://trees.software)
- Topcoat (rust, [DoC](https://youtu.be/HfRQjix9tU4?is=Q-Ulb0K5x-H9Gx1a))
- Enhanced (markdown)
## Good to haves
#### Reviewing should be first class for bots & humans:
Essentially, marking a file as "Reviewed" (through UI or API for bots) should mark it as viewed for the head commit. After push, all files that have changed since then are still marked as reviewed by at the last HEAD.
Getting unreviewed stuff should then return the file diff since the last reviewed HEAD commit.
Make it obvious that its "changed since last commit", with a "see full diff button".
This will make incremental reviews much more powerfull. Especially **for the PR author**.
### Other Minor Features
- **Project main page**
The main page of a project should render a file (repo 1's README by default).
Should be configurable.
- **Arbitrary Diff Viewer**
Allow users to view the diff between any arbitrary records.
## Idea for Novel Domain Organization
**Projects** should be the primary unit of organization.
A project is owned by an entity (user or org).
Projects contain:
- Repositories
- User permissions
- Integration settings

One interesting use case would be for a large monorepo to have depending repos.
For example, a company could have their closed source service in a large monorepo, but other smaller public repositories with SDKs, examples, docs, ...
This should be thought about more but is very interesting.
````
