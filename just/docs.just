set working-directory := '..'

# The build fails on any mdBook warning. lychee then checks every link and
# heading anchor in the book and in the repository's other Markdown files,
# offline (see lychee.toml). Links to this repository on GitHub are checked
# against the checkout; the second remap fails those that don't point at main,
# which would otherwise go unchecked. CI runs this on every pull request; see
# docs/dev/documentation.md.
# Build the book into target/book and check every link and anchor.
check:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! log=$(mdbook build 2>&1) || grep -q WARN <<<"$log"; then
        echo "$log" >&2
        exit 1
    fi
    repository='https://(github\.com/sourceorigin-dev/sourceorigin/(blob|tree)|raw\.githubusercontent\.com/sourceorigin-dev/sourceorigin)'
    # mdBook checks SUMMARY.md's links itself; its section headings are empty
    # links, which lychee rejects.
    git ls-files -z --cached --others --exclude-standard '*.md' ':!docs/SUMMARY.md' \
        | xargs -0 lychee --root-dir "$PWD/target/book" \
            --remap "$repository/main/ file://$PWD/" \
            --remap "$repository/ file:///links-to-this-repository-must-point-at-main/" \
            target/book

# Serves the book on localhost:3000, rebuilding it on every change.
serve *args:
    @mdbook serve {{ args }}

# The configuration variables and the auth-service commands, from the code that
# defines them. `just test` fails while they are stale.
# Rewrite the generated reference pages.
reference:
    @UPDATE_DOCS_REFERENCE=1 cargo nextest run --locked -p auth-service -p sourceorigin-web -E 'test(reference_is_current)'

# Each run deploys this checkout to a fresh preview of its own, the `docs` slot,
# takes the screenshots there, and deletes it: a new database every run keeps the
# pages the same. Only images whose page changed are rewritten. ARGS go on to
# Playwright, such as a spec's name. See docs/dev/documentation.md.
# Retake the documentation's screenshots in docs/images.
screenshots *args:
    #!/usr/bin/env bash
    set -euo pipefail
    branch=$(git branch --show-current)
    just preview-delete --slot docs 2>/dev/null || true
    trap 'just preview-delete --slot docs' EXIT
    just preview --slot docs
    url() { piquelctl preview url sourceorigin "$branch" --slot docs --route "$1"; }
    E2E_AUTH_URL=$(url auth) E2E_ADMIN_URL=$(url admin) \
        E2E_GRANT_ADMIN="piquelctl preview exec sourceorigin $branch --slot docs auth -- auth-service --operator docs-screenshots admin grant" \
        pnpm exec playwright test --project docs --update-snapshots=changed {{ args }}
