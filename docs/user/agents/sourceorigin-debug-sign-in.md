# Debugging a sign-in

The `sourceorigin-debug-sign-in` skill teaches an agent to find out why a sign-in
with Origin Auth fails. Use it when your app answers an error during sign-in,
when sign-in loops, or when sessions end too soon.

The agent reads the error your app answered, checks auth's discovery, asks
auth for its reason directly, and compares the app's configuration with what
you read it from the app's page in the developer console. When the fix is a
change to the registration, it asks you to make it.

To install it, save this file as
`.claude/skills/sourceorigin-debug-sign-in/SKILL.md` in your project, or under
`.agents/skills/` for agents that read that directory:

````markdown
{{#include skills/sourceorigin-debug-sign-in/SKILL.md}}
````
