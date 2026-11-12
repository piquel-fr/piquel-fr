# The frontend

This page records why Topcoat goes, what the frontend must do, and the
experiment that picks its framework.

See [the plan's overview](README.md) for what each status means.

## What it must do

From piquel's [notes](notes.md) and the discussion:

- Diffs, file trees and syntax highlighting. The notes name
  [diffs.com](https://diffs.com) and [trees.software](https://trees.software),
  both from Pierre.
- Diffs must be ridiculously fast, as fast as Pierre's diffshub demo.
- Type safety from the database to the page.
- One consistent UI across every surface. piquel calls this extremely
  important.
- Performance, and ease of development: testing, build speed during
  development.

## Topcoat goes

**Decided.** Topcoat is dropped everywhere, Origin Auth included.

- Topcoat is early and experimental, and its own README says to expect
  breaking changes. piquel would rather have something with more established
  features.
- Its roadmap still lists islands as planned. Without them, a rich component
  inside a server-rendered page needs hand-written JavaScript to connect it.
- Origin Auth already has that glue: about 1,700 lines of hand-written
  scripts in `apps/auth-service/assets` (`passkey.js` 607 lines, `search.js`
  548, `dashboard.js` 281, `picture.js` 204).
- An earlier argument for keeping Topcoat in auth was that sign-in pages
  should carry little JavaScript. It was weak: passkeys need JavaScript
  anyway.
- Two frameworks would mean two component libraries, which works against one
  consistent UI.

## Moving over

**Proposed** order, not answered in detail:

1. Build the product app first, with a shared component library in
   `packages/ui`.
2. Port Origin Auth's surfaces onto it: the admin dashboard first, since it is
   private, then the developer console, the account settings, and sign-in
   last.
3. Build auth's pages as static files embedded in the auth executable. Origin
   Auth stays one Rust executable, and no Node process ever sees a session
   cookie.
4. Give auth a JSON API for what its pages do. Being friendly to agents needs
   one anyway.
5. Move the email templates in `crates/ui` to a small Rust templater such as
   maud. They must stay on the server.

The design tokens in `crates/ui/assets/style` are plain CSS, so they can stay
the single source of the look while the pages move.

**Open:** whether the product app renders on a server. Public repository
pages will want it for search engines and link previews. It was not
discussed.

## What Pierre provides

These are facts read from Pierre's repository, `pierrecomputer/pierre`, and
its documentation on 13 November 2026.

- `@pierre/diffs` was at version 1.6.4. Its entry points:

  | Entry point | What it holds |
  | --- | --- |
  | `@pierre/diffs` | Components in plain JavaScript, and utilities |
  | `@pierre/diffs/react` | React components |
  | `@pierre/diffs/edit` | The editor for edit mode |
  | `@pierre/diffs/ssr` | Rendering on a server, with highlighting |
  | `@pierre/diffs/worker` | A worker pool that highlights off the main thread |

- The plain JavaScript API has four core components. One is `CodeView`: a
  single scroll region for a list of files and diffs, with virtualization per
  line, sticky headers, selection across items, annotations, and scrolling to
  an item or a line.
- The React components are a thin layer over the plain JavaScript ones.
- `@pierre/highlights` is a highlighter written in WebAssembly text, with 152
  languages. It runs in Node, browsers and Cloudflare Workers. Pierre says it
  is about 300 times faster than Shiki.
- `@pierre/trees` exports a plain `FileTree` class with `render` and
  `hydrate`, and React hooks. Its documentation says other frameworks can wrap
  the plain class.
- Diffshub, in `apps/diffshub`, is Next.js and React, under Apache-2.0. Its
  speed does not come from React. It comes from `CodeView`, the worker pool,
  `@pierre/highlights`, and parsing the patch as a stream, file by file. Any
  framework can use all four.

Not verified: exactly how an annotation is rendered through the plain
JavaScript API. The experiment will show it.

## The experiment

**Decided.** Build the same single screen in two frameworks, with a time
limit, then delete the loser.

- **Candidates:** React with TanStack Start, and SvelteKit.
- **Out:** Leptos. The diff viewer and the file tree are JavaScript libraries,
  so in Leptos they would sit behind WebAssembly interop, and every UI change
  would cost a Rust compile.
- **Not a factor:** that T3 Code and diffshub use React. piquel has worked in
  neither codebase, and the choice is for this project alone.
- **Not needed:** Effect. With a Rust backend and a thin client it adds a
  paradigm for little gain. This was proposed and not answered.

The screen is change review: the file tree, a large diff in `CodeView`,
comment threads inline, files marked as reviewed, and live updates.

Measure, on one large real diff:

- the time to the first diff line;
- how smooth scrolling is;
- the bundle size;
- how many lines the wrapper around Pierre's components takes;
- how the generated API client feels to use;
- which accessible form and dialog components exist, for the auth port.

What is known before running it:

- Pierre maintains the React wrapper. With Svelte, we would maintain our own
  around the plain JavaScript API.
- Svelte is lighter, and it is piquel's preference. SvelteKit was the first
  choice in the notes.
- No lean either way remains. An early lean toward SvelteKit, then one toward
  React, both rested on arguments that were later set aside.

## Type safety

**Proposed.** Generate the TypeScript client from the platform's OpenAPI
document. The repository already generates TypeScript types from Rust with
`ts-rs`, for the TypeScript SDK.
