# Building with coding agents

A coding agent, such as Claude Code or Codex, can do most of the work of
adding sourceorigin.dev sign-in to your app. This page says what it can do, what
stays with you, and how to give it the four skills that teach it the steps.

## What an agent can do

- **Read this documentation**, to learn how sign-in works and what each
  setting means.
- **Write the sign-in code**, with the Rust SDK (`sourceorigin-auth`, with axum) or
  the TypeScript SDK (`@sourceorigin/auth`).
- **Run your app locally** against auth.sourceorigin.dev, and check each step of a
  sign-in it can reach without a browser.
- **Deploy your app** on piqueld, with its secrets and a redirect URI for each
  environment.
- **Debug a failed sign-in**, from the error your app got to the setting that
  causes it.

## What only you can do

Registering an app, changing its settings and rotating its secret all need a
[passkey confirmation](../introduction.md#words-this-guide-uses) in the
developer console. Only you can give one, so an agent can't do any of these
yet. The skills stop at those steps and ask you to do them, at
`auth.sourceorigin.dev/developers`, as [registering an app](../apps/register-an-app.md)
describes.

Signing in to try the app is yours too, since it takes your passkey.

The skills also ask you to put the client secret in your app's environment or
secret store yourself. It never goes in the repository, and you don't need to
paste it into the conversation.

## Install a skill

A skill is a directory holding a `SKILL.md` file. Copy each one you want into
your project's `.claude/skills/` for Claude Code, or `.agents/skills/` for
agents that read that directory, such as Codex:

```console
mkdir -p .claude/skills
cp -r sourceorigin/docs/user/agents/skills/sourceorigin-sign-in .claude/skills/
```

Here `sourceorigin` is a clone of the
[repository](https://github.com/sourceorigin-dev/sourceorigin). Each skill's page below
also shows its whole file, to copy into `<skills directory>/<name>/SKILL.md`.

The agent then uses a skill when your request matches its description, such
as "add sign-in with sourceorigin.dev".

| Skill | Use it to |
| --- | --- |
| [`sourceorigin-sign-in`](sourceorigin-sign-in.md) | Add sign-in to an app, with the Rust or the TypeScript SDK |
| [`sourceorigin-dev-setup`](sourceorigin-dev-setup.md) | Run the app on your machine and check a sign-in from end to end |
| [`sourceorigin-deploy`](sourceorigin-deploy.md) | Deploy the app on piqueld |
| [`sourceorigin-debug-sign-in`](sourceorigin-debug-sign-in.md) | Find out why a sign-in fails |

## Let the agent read the documentation

This documentation is plain Markdown, in the repository's
[`docs`](https://github.com/sourceorigin-dev/sourceorigin/tree/main/docs) directory, and
published at <https://docs.sourceorigin.dev>. Give an agent a page's address, or a
clone of the repository to read `docs/user/`. The skills link to the published
pages rather than repeating them, so they stay short and current.
