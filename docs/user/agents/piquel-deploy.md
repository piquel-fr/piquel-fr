# Deploying on piqueld

The `piquel-deploy` skill teaches an agent to deploy an app that signs in with
piquel.fr on [piqueld](https://docs.piqueld.dev). Use it when the app runs
locally and you want it on its own address, in one environment or several.

The agent asks you for a registration per environment, each with that
environment's redirect URI, and to store each client secret in piqueld
yourself. It writes the manifest's settings and secret mounts, deploys, and
checks the sign-in on the deployed app.

To install it, save this file as `.claude/skills/piquel-deploy/SKILL.md` in
your project, or under `.agents/skills/` for agents that read that directory:

````markdown
{{#include skills/piquel-deploy/SKILL.md}}
````
