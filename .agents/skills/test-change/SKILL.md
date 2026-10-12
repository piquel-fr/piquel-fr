---
name: test-change
description: >
  Test a change end to end on a piqueld preview, then hand the running preview
  to the user so they can try it too. Use after changing auth, the web
  frontends, the database, or infra/, before reporting the work as done, and
  whenever asked to test, verify, or QA a change.
---

# Test a change

Passing unit tests is not the same as working. Test the change where it will
run, against real PostgreSQL behind real HTTPS, then let the user try it.

## 1. Check locally first

Run only the checks for what changed: `cargo nextest run -p <crate>`,
`pnpm --filter <package> check`, `cargo clippy -p <crate>`. For changes to
`infra/piqueld.toml`, run `piquelctl app validate --file infra/piqueld.toml`.
Fix failures before deploying: a preview build costs minutes.

## 2. Deploy a preview

Follow the `preview` skill: `just preview` in the background, then note the
two URLs it prints. Below, `$web` is `https://<slug>.dev.piquel.fr` and `$auth`
is `https://auth-<slug>.dev.piquel.fr`.

## 3. Smoke-test the deployment

```sh
curl -fsS "$auth/health/ready"
curl -fsS "$web/config.json"     # {"auth_origin":"<$auth>"}
piquelctl preview logs piquel-fr "$(git branch --show-current)" --tail 200
```

Look for errors and panics in the logs even when everything answers.

## 4. Exercise the change like a user

Plan the checks from the change itself: the flow it adds or fixes, its error
paths (bad input, expired or replayed links, missing permissions), and the
flows next to it that it could break. Signing up, signing in and loading
settings are always worth one pass.

- **Pages and layout:** open `$web` or `$auth` in T3 Code's preview browser
  (`preview_open`), and take screenshots of what changed.
- **Passkeys:** the preview browser cannot create passkeys. Drive Chromium
  with Playwright and its virtual authenticator instead, as
  `tests/browser/account.spec.ts` does (`WebAuthn.enable`, then
  `WebAuthn.addVirtualAuthenticator`). For a one-off check, run a script from
  the repository root so it resolves `@playwright/test`, e.g.
  `node --input-type=module -e "import { chromium } from '@playwright/test'; ..."`.
  Set `CHROMIUM_EXECUTABLE` (or `executablePath`) to a Chromium binary; on
  NixOS, `$(nix build --no-link --print-out-paths nixpkgs#chromium)/bin/chromium`.
- **APIs:** `curl` the auth API directly. State-changing requests need
  `origin: $web` (or `$auth`), `content-type: application/json` and
  `x-piquel-csrf: 1`. Account endpoints also need a session cookie, so those
  checks are usually simpler from Playwright.
- **Lasting coverage:** if the change deserves a regression test, add a focused
  spec to `tests/browser`. The existing suite also needs the `browser-e2e` OIDC
  client, which previews don't configure. Run it locally as
  `tests/browser/README.md` describes when consent or OIDC changes.

After fixing anything, run `just preview` again and repeat the checks the fix
could affect.

## 5. Hand it to the user

Leave the preview running and tell the user, in chat:

- the web and auth URLs, as links;
- that they work from any device on their tailnet, so they can register a real
  passkey from their phone or laptop, and that registration needs no
  invitation;
- what to try: concrete steps for the changed behaviour;
- what you verified and how, and what you could not (real devices, Google or
  GitHub sign-in, production-only configuration);
- that `just preview-delete` removes the preview once they are done.

Report failures as failures, with the command and its output. Don't present a
partially working preview as done.
