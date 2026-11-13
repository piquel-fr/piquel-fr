# The council review

On 13 November 2026 three reviewers each read this whole plan and checked it
against this repository, Origin's design, Origin's open stack and its issues.
This page records what they found and what was decided about each finding, so
that a finding isn't raised again, and so that what is still unanswered is in
one place.

See [the plan's overview](README.md) for what each status means.

## Scores

| Reviewer | Score |
| --- | --- |
| GPT 6.1 Sol | 6/10 |
| Claude Opus 5.5 | 5/10 |
| Claude Fable 5.2 | 5/10 |

They agreed that the direction is sound: stock Origin, one node, data as
statements, no second permission system. They also agreed that milestone 1
could not be reached as written, and that several decisions about formats and
security were missing.

## Findings and outcomes

| Finding | Outcome | Where |
| --- | --- | --- |
| Origin has no ignore files, so a real project's first snapshot records build outputs for good | Decided: ignore files, in Origin's v0.1 | [origin](origin.md#ignore-files) |
| Nothing brings git history in, and the mirror would push an unrelated history | Decided: start from the git tip, and the mirror continues the existing history. Importing history is later | [origin](origin.md#the-git-mirror) |
| Milestone 1 needed agent skills, colocated mode and a restore drill that were scheduled later | Decided: all three moved earlier. SourceOrigin is the priority, and features of Origin Auth and piqueld are placed where it needs them | [roadmap](roadmap.md#origins-milestones) |
| There was no CI between milestones 1 and 2 | Decided: checks by hand, after review. An automatic worker is deferred | [origin](origin.md#ci) |
| Hosting for one person waits on features for many | Decided: no split. Both projects are worked on together | [roadmap](roadmap.md#milestones) |
| History written before signing in can't be pushed | Decided: signing in sets the identity, cloning from SourceOrigin needs a sign-in, and earlier history is re-authored once | [origin](origin.md#principals) |
| "Principals need no format change" only held for Origin Auth | Decided: one issuer per repository, in `policy.toml`, and a total encoding of the subject | [origin](origin.md#principals) |
| No record carries a time | Decided: every revision, statement and acceptance carries one, in Origin's v0.1 | [origin](origin.md#times-on-records) |
| A repository's ID never reaches its signed history | Decided: bind an identity into genesis and pin it at clone | [origin](origin.md#a-repositorys-identity) |
| The single authority key has no rotation or recovery | Open: piquel wants a rotation system; it needs more thought | [origin](origin.md#authority-keys) |
| Nothing can be erased | Decided: redaction that keeps the ID and drops the content | [origin](origin.md#erasing-content) |
| The sign-in seam loses a token's scope and expiry, and five-minute tokens stall waiting landings | Decided: the authenticator returns capabilities and expiry, and the queue checks rights again when it lands | [origin](origin.md#sign-in-with-openid-connect) |
| The platform can't write to Origin as the user | Decided: token exchange is brought forward | [platform](platform.md#services) |
| CI on piquel's machine runs code nobody has read | Decided: no automatic CI at first, repositories start private, and a later worker runs in a sandbox | [origin](origin.md#ci) |
| No storage or request limits until milestone 5 | Deferred: it matters little while there are few users. origin#83 | [roadmap](roadmap.md#origins-milestones) |
| A nonce doesn't protect a single hidden file | Decided: only folders can be hidden | [origin](origin.md#hidden-paths) |
| Descriptions, reviews and check output of hidden code stay readable | Decided: private changes, by choice. Hiding them automatically was dropped | [origin](origin.md#private-changes) |
| Git can't represent hidden paths, and the mirror would publish `policy` | Decided: hidden paths wait until the mirror is gone, and `policy` is never mirrored | [origin](origin.md#the-git-mirror) |
| Mirrored commits must be reproducible, must not carry names, and the mirror must reconcile | Decided | [origin](origin.md#the-git-mirror) |
| The display-name lookup links all of a person's history | Decided: it returns what a public profile shows | [origin](origin.md#display-names) |
| The registry's `path` is redundant | Decided: no path for now, a storage location later | [origin](origin.md#finding-repositories) |
| Serving stale registry answers contradicts suspension | Decided: a short cache and a limit on staleness, without Valkey | [origin](origin.md#finding-repositories) |
| A repository name is one segment, with no room for an owner | Decided: segments separated by `/` | [origin](origin.md#finding-repositories) |
| Creating a repository the first time it is used must be atomic | Dropped: nothing is created implicitly. The platform calls an explicit create | [origin](origin.md#creating-a-repository) |
| Bootstrapping is circular: piqueld would build from a node it hosts | Decided: the git mirror on GitHub is the fallback | [origin](origin.md#the-git-mirror) |
| Backups of a live store aren't consistent, and a restore forks every chain | Decided: stop the node to copy it, and a restored node takes back what it signed | [platform](platform.md#hosting-and-backups) |
| Reviewed marks don't work as statements | Decided: they live in PostgreSQL | [platform](platform.md#marking-files-as-reviewed) |
| The event cursor planned for replicas can lose events | Open, and deferred with replicas | [origin](origin.md#events-and-cursors) |
| `cargo metadata` can't list every input of a check | Decided: generated Rust inputs, and the rest by hand | [repository](repository.md#ci-by-area) |
| Porting all of Origin Auth off Topcoat isn't earned | Decided: sign-in stays in Origin Auth, and the rest moves | [below](#the-auth-port-and-the-admin-dashboard) |
| Server rendering was undecided, though it changes the experiment | Decided: the product renders on a server | [frontend](frontend.md#moving-over) |
| Nothing serves diffs | Decided: Origin gains a diff endpoint | [origin](origin.md#diffs) |
| `production` as a target duplicates piqueld | Dropped | [origin](origin.md#deploys) |
| Issue numbers collide between repositories | Decided: every number is written with its repository, such as origin#54 | Every page |
| The comparison with jj doesn't hold | Dropped | [origin](origin.md#colocated-mode) |
| `git status` needs git's index rewritten, not only `HEAD` | Decided | [origin](origin.md#colocated-mode) |
| An account's ID shows when it was created | Accepted | [origin](origin.md#principals) |
| Events are one long-poll per repository, which won't scale to many subscribers | Not discussed. It matters at milestone 5 | |

## Questions the reviewers asked

| Question | Answer |
| --- | --- |
| Where do issues live once GitHub is a read-only mirror? | In Linear. piquel is moving all development there |
| Where do organization and team memberships live? | In policy. Organizations will sit beside users, later |
| Who may create a repository, and with what limits? | Any account, up to three. Administrators can change the limit |
| Are hosted repositories readable by anyone by default? | No. They start private, and the owner can make one public |
| Which token system do agents use? | Origin Auth's. On SourceOrigin, all of Origin's sign-in goes through Origin Auth |
| Do staging and previews get their own node and key? | Yes. Every environment starts from scratch |
| How does piqueld learn of a landing? | Through a webhook |
| What happens to a repository when its only admin deletes their account? | It is deleted with the account, after the waiting period, unless handed over first |

## The auth port and the admin dashboard

Two questions turned out to be one.

The first is whether to port Origin Auth's pages off Topcoat. All three
reviewers said that porting every page isn't earned: it rewrites working,
security-sensitive pages over a new JSON API. piquel's answer is that agents
make porting, reviewing and hardening cheap, the service is young and still
small, and consistency in development is worth a lot.

The second is where SourceOrigin's admin dashboard goes. piquel wants the two
admin surfaces close: clicking a user in the auth admin should lead to their
repositories, and back. piquel's options:

1. One dashboard holds both SourceOrigin's and Origin Auth's administration.
2. Today's `admin.sourceorigin.dev` becomes a private path on
   `auth.sourceorigin.dev`, which needs routing by path in piqueld, and the
   platform's admin takes `admin.sourceorigin.dev`.
3. `auth.sourceorigin.dev` serves only the public API, the admin API and the
   sign-in pages. The account settings and the admin dashboard move to the
   product's frontend and call those APIs.

**Decided:** the third option.

- Sign-in, consent and recovery stay in Origin Auth, rendered on its server as
  today. They are the pages where a mistake costs an account, and they are
  the part the reviewers warned about.
- The account settings, the developer console and the admin dashboard move to
  the product's frontend. That is most of the pages, and where one component
  library pays off. The admin dashboard is then one app for both services, so
  a user and their repositories are a link apart.
- This is not one page that loads everything. The frontend renders each page
  on its server.
- It is done after the product's frontend exists, so the component library is
  there first.

Its cost: Origin Auth needs a JSON API for every account and admin operation,
with its own protection against forged requests, and the browser tests and
the documentation's screenshots are rewritten. With agents that is moderate.

**Open:** whether the account settings get their own hostname, not a path on
`sourceorigin.dev`. A browser lets any script on a page act as the signed-in
person on every page of the same hostname. The product's pages show content
that other people wrote, such as READMEs and diffs. If a bug ever let such
content run a script, that script could open the settings and add its own
passkey. On another hostname the browser stops it. The cheaper alternative
keeps `/settings` and asks for a passkey again, at Origin Auth, before every
sensitive change.

## Still to answer

- Whether the account settings get their own hostname, above.
- How private changes work in detail. See
  [private changes](origin.md#private-changes).
- What happens when a reader gains access to a hidden folder they already
  have local files in. See [hidden paths](origin.md#hidden-paths).
