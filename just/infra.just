set working-directory := '..'

# `--slot NAME` keeps several previews of one branch.
# Deploy this worktree, uncommitted changes included, to its preview; print its URLs.
preview *args:
    piquelctl --timeout 30m preview deploy piquel-fr --local {{ args }}
    piquelctl --timeout 10m preview wait piquel-fr "$(git branch --show-current)" {{ args }} --ready routes

# Delete this worktree's preview with its database.
preview-delete *args:
    piquelctl preview delete piquel-fr "$(git branch --show-current)" {{ args }} --yes
