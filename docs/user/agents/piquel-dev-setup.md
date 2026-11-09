# Running your app locally

The `piquel-dev-setup` skill teaches an agent to run an app that signs in with
piquel.fr on your machine, against auth.piquel.fr. Use it once the sign-in
code is written, to try it before you deploy.

The agent asks you for a separate development registration, with a loopback
redirect URI such as `http://127.0.0.1:3000/auth/callback`, so the production
secret stays off your machine. It sets the environment, then checks every step
of a sign-in it can reach without a browser, and asks you to finish it with
your passkey.

To install it, save this file as `.claude/skills/piquel-dev-setup/SKILL.md` in
your project, or under `.agents/skills/` for agents that read that directory:

````markdown
{{#include skills/piquel-dev-setup/SKILL.md}}
````
