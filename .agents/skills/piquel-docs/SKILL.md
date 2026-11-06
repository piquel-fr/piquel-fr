---
name: piquel-docs
description: >
  Write or change piquel.fr's documentation: any page under `docs/`, the root
  README, SECURITY.md or CONTRIBUTING.md, or a README beside the code. Use
  before writing or reviewing documentation, when a change needs its docs
  updated, or when asked to document a feature.
---

# Write the documentation

Read `docs/dev/documentation.md` in full before you write anything. It is the
documentation's writing guide, and everything below only points into it:

- **Where pages go:** the user guide (`docs/user`) or the contributor guide
  (`docs/dev`), and `docs/SUMMARY.md`, which lists every published page.
- **Writing and Style:** how to write a page, with an example, and the outline
  every feature guide in the user guide follows.
- **Links:** how to link to pages, anchors and repository files.
- **Building and checking:** `just docs` builds the book and checks every link
  and anchor.

Check every claim against the code before you write it: the documentation
must say what auth does now. Before you finish, run `just docs`. The `preview`
skill runs the app, to check that the pages, labels and commands you document
are right.
