# Adding sign-in

The `piquel-sign-in` skill teaches an agent to add sign-in with a piquel.fr
account to a web app with a backend. Use it when you start adding sign-in, in
Rust with axum or in TypeScript.

The agent asks you to register the app in the developer console, with the
settings the SDKs' login routes need, and to put its client secret in the
app's environment. It then reads the configuration from the environment,
mounts the login routes, and protects the pages that need a signed-in user.

To install it, save this file as `.claude/skills/piquel-sign-in/SKILL.md` in
your project, or under `.agents/skills/` for agents that read that directory:

````markdown
{{#include skills/piquel-sign-in/SKILL.md}}
````
