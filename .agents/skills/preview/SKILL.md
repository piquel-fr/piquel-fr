---
name: preview
description: >
  Deploy this worktree to its piqueld preview: a disposable copy of piquel.fr
  (auth with its settings pages, the admin dashboard and PostgreSQL) on private
  tailnet URLs, built from the worktree's files without committing or pushing.
  Use whenever a change needs the running app: to try it, debug it against real
  services, or share it with the user. Also for reading a preview's logs or
  deleting it.
---

# Previews

A preview runs the whole application from `infra/piqueld.toml` on the piqueld
daemon. Each branch (and optional slot) gets its own: separate database,
generated secrets, and URLs.

| Route | URL |
| --- | --- |
| auth, with the settings at `/settings` | `https://auth-<slug>.dev.piquel.fr` |
| admin | `https://admin-<slug>.dev.piquel.fr` |
| web (redirects to auth, keeping the path) | `https://<slug>.dev.piquel.fr` |
| www (redirects to web) | `https://www-<slug>.dev.piquel.fr` |

URLs are private: they work from devices on the tailnet, including this machine
and the user's devices, and nowhere else. Each preview's database starts empty
and registration needs no invitation.

## Deploy

```sh
just preview
```

This snapshots the worktree (committed, uncommitted and untracked files, except
ignored ones) without touching Git, builds every image, runs migrations, rolls
out, and waits until the URLs serve. It then prints the deployment with its URLs.
A cold build compiles auth in release mode and can take 15 minutes or more: run
it as a background command, not in a polling loop.

Run it again after every change: each run replaces the same preview with a new
snapshot. Add `--slot NAME` only when another agent already uses this branch's
preview. A preview is addressed by its branch and slot, so then pass the same
`--slot NAME` to every `just preview*` and `piquelctl preview` command below.

On failure, the exit code says what happened:

| Exit | Meaning | Do |
| --- | --- | --- |
| 2 | Invalid command or manifest | Fix it; retrying won't help |
| 3 | Superseded by a newer deployment, or preview limit reached | Wait for the newer one; on the limit, ask the user which preview to delete |
| 4 | Timed out or daemon unreachable | The deployment continues: `piquelctl --timeout 15m preview wait piquel-fr "$(git branch --show-current)" --ready routes` |
| 5 | Deployment failed | Read the error, then the logs below; fix, deploy again |

Permission errors mean the credentials lack `previews:deploy` or
`previews:delete`. Report them to the user. Never work around them with other
credentials.

## Inspect

```sh
branch=$(git branch --show-current)
piquelctl preview show piquel-fr "$branch"                    # state, commit, URLs
piquelctl preview logs piquel-fr "$branch" --service auth --tail 100
piquelctl preview url piquel-fr "$branch" --route auth       # or --route admin
```

Build and `migrate` job output live in the build history:
`piquelctl --json preview show piquel-fr "$branch"` gives the preview's
`environment_id`, then `piquelctl builds list --environment ID` and
`piquelctl builds logs BUILD_ID`.

## Pushed branches

`piquelctl preview create piquel-fr --branch NAME` previews a pushed branch
instead. Previews redeploy when their branch moves, so a pushed branch's preview
follows its pushes, and a local snapshot is replaced once its branch is pushed
again.

## Clean up

Leave the preview running when you hand work to the user, and tell them it is
still up. Delete it once they are done, or when asked:

```sh
just preview-delete
```

Never deploy, promote or delete staging or production (`piquelctl env ...`,
`app deploy`): they are the user's.
