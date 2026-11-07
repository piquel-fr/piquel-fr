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
    repository='https://(github\.com/piquel-fr/piquel-fr/(blob|tree)|raw\.githubusercontent\.com/piquel-fr/piquel-fr)'
    git ls-files -z --cached --others --exclude-standard '*.md' \
        | xargs -0 lychee --root-dir "$PWD/target/book" \
            --remap "$repository/main/ file://$PWD/" \
            --remap "$repository/ file:///links-to-this-repository-must-point-at-main/" \
            target/book

# Serves the book on localhost:3000, rebuilding it on every change.
serve *args:
    @mdbook serve {{ args }}

# Rewrite the generated reference pages: the configuration variables and the
# auth-service commands, from the code that defines them. `just test` fails while
# they are stale.
reference:
    @UPDATE_DOCS_REFERENCE=1 cargo nextest run --locked -p auth-service -p piquel-web -E 'test(reference_is_current)'
